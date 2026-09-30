// arena: tagwatch's own allocator for watched objects.
//
// Watched allocations are not left in the system heap. The system allocator
// only tags small blocks (on the test machine, up to about 4 KB), retags
// memory on its own schedule, and rounds sizes in ways that make neighbours
// share granules. Here every block starts on a granule boundary, occupies
// whole granules, can be any size, and nobody else changes its tags.
//
// The arena is one large MTE-enabled virtual reservation that the kernel
// populates lazily, so "does this pointer belong to tagwatch" is a range
// check. It is registered as a malloc zone: free(), realloc() and
// malloc_size() on an arena block find their way here even when called from
// code the interposers cannot see.
//
// Freed blocks that were watched stay armed in a FIFO quarantine, so a
// use-after-free of a watched object is reported instead of going unnoticed.
#include <malloc/malloc.h>
#include <mach/mach_vm.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

#ifndef VM_FLAGS_MTE
#define VM_FLAGS_MTE 0x00002000
#endif

#define HDR 32
#define MAGIC 0x54574131u      // "TWA1": live block
#define MAGIC_FREED 0x54574146u // "TWAF": freed, waiting in quarantine
#define SMALL_MAX 1040    // largest block size with an exact class
#define N_SMALL (SMALL_MAX / 16 + 1)
#define POW_MIN 11 // 2 KB
#define POW_MAX 26 // 64 MB
#define N_CLASSES (N_SMALL + POW_MAX - POW_MIN + 1)
#define REFILL (256u << 10)
#define QUEUE 65536

typedef struct {
    uint32_t magic;
    uint32_t back; // payload - block start
    uint64_t cap;  // block size (class size)
    uint64_t size; // bytes requested
    uint64_t pad;
} hdr_t;

static os_unfair_lock lock = OS_UNFAIR_LOCK_INIT;
static uint64_t base, next, end;
static uint64_t free_list[N_CLASSES]; // singly linked through the first word of each free block
static uint64_t bump[N_CLASSES], bump_end[N_CLASSES];
static uint64_t quarantine[QUEUE];
static uint32_t q_head, q_count;
static uint64_t q_bytes, q_limit = 1 << 20;
static malloc_zone_t zone;
static malloc_introspection_t introspect;

int tw_arena_owns(const void *p) {
    uint64_t a = (uint64_t)(uintptr_t)p & TW_ADDR_MASK;
    return a >= base && a < end;
}

static int class_of(uint64_t cap, uint64_t *class_cap) {
    if (cap <= SMALL_MAX) {
        *class_cap = cap;
        return (int)(cap / 16);
    }
    for (int p = POW_MIN; p <= POW_MAX; p++)
        if (cap <= (1ull << p)) {
            *class_cap = 1ull << p;
            return N_SMALL + p - POW_MIN;
        }
    *class_cap = (cap + TW_PAGE_SIZE - 1) & ~(TW_PAGE_SIZE - 1);
    return -1; // huge: carved directly, never recycled
}

static uint64_t carve(uint64_t bytes) {
    bytes = (bytes + TW_PAGE_SIZE - 1) & ~(TW_PAGE_SIZE - 1);
    if (end - next < bytes) return 0;
    uint64_t p = next;
    next += bytes;
    return p;
}

// Caller holds the lock. *recycled tells whether the block may hold old data
// (fresh pages from the kernel are already zero).
static uint64_t block_get(int cls, uint64_t cap, int *recycled) {
    *recycled = 0;
    if (cls < 0) return carve(cap);
    if (free_list[cls]) {
        uint64_t b = free_list[cls];
        free_list[cls] = *(uint64_t *)(uintptr_t)b;
        *recycled = 1;
        return b;
    }
    if (bump_end[cls] - bump[cls] < cap) {
        uint64_t chunk = cap > REFILL ? cap : REFILL;
        uint64_t c = carve(chunk);
        if (!c) return 0;
        bump[cls] = c;
        bump_end[cls] = c + chunk;
    }
    uint64_t b = bump[cls];
    bump[cls] += cap;
    return b;
}

void *tw_arena_alloc(size_t size, size_t align) {
    if (align < TW_GRANULE) align = TW_GRANULE;
    if (align & (align - 1)) return NULL;
    uint64_t payload_bytes = ((uint64_t)size + TW_GRANULE_MASK) & ~TW_GRANULE_MASK;
    if (payload_bytes == 0) payload_bytes = TW_GRANULE;
    if (payload_bytes < size || payload_bytes > (1ull << 40)) return NULL;
    uint64_t cap = HDR + payload_bytes + (align > TW_GRANULE ? align : 0), class_cap;
    int cls = class_of(cap, &class_cap);
    int recycled;
    os_unfair_lock_lock(&lock);
    uint64_t b = block_get(cls, class_cap, &recycled);
    os_unfair_lock_unlock(&lock);
    if (!b) return NULL;
    uint64_t payload = (b + HDR + align - 1) & ~((uint64_t)align - 1);
    hdr_t *h = (hdr_t *)(uintptr_t)(payload - HDR);
    h->magic = MAGIC;
    h->back = (uint32_t)(payload - b);
    h->cap = class_cap;
    h->size = size;
    // Blocks are always handed out zeroed, so calloc needs no extra pass.
    if (recycled) memset((void *)(uintptr_t)payload, 0, payload_bytes);
    return (void *)(uintptr_t)payload;
}

// Header of a live or quarantined block, or NULL.
static hdr_t *header_of(const void *p) {
    uint64_t a = (uint64_t)(uintptr_t)p & TW_ADDR_MASK;
    if (a < base + HDR || a >= end || (a & TW_GRANULE_MASK)) return NULL;
    hdr_t *h = (hdr_t *)(uintptr_t)(a - HDR);
    return h->magic == MAGIC || h->magic == MAGIC_FREED ? h : NULL;
}

size_t tw_arena_size(const void *p) {
    if (!tw_arena_owns(p)) return 0;
    hdr_t *h = header_of(p);
    if (!h) return 0;
    uint64_t rounded = (h->size + TW_GRANULE_MASK) & ~TW_GRANULE_MASK;
    return rounded ? rounded : TW_GRANULE;
}

// Returns the block to its free list. Caller holds the lock.
static void block_put(uint64_t payload) {
    hdr_t *h = (hdr_t *)(uintptr_t)(payload - HDR);
    uint64_t b = payload - h->back, cap = h->cap, class_cap;
    int cls = class_of(cap, &class_cap);
    h->magic = 0;
    if (cls < 0) {
        // Give the pages back but keep the address range reserved.
        mach_vm_address_t a = b;
        mach_vm_map(mach_task_self(), &a, cap, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_FLAGS_MTE, MACH_PORT_NULL, 0, FALSE,
                    VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_DEFAULT);
        return;
    }
    *(uint64_t *)(uintptr_t)b = free_list[cls];
    free_list[cls] = b;
}

void tw_arena_set_quarantine(uint64_t bytes) {
    os_unfair_lock_lock(&lock);
    q_limit = bytes;
    os_unfair_lock_unlock(&lock);
}

void tw_arena_free(void *p) {
    hdr_t *h = header_of(p);
    if (!h) return; // not a block of ours
    if (h->magic == MAGIC_FREED) {
        tw_emit_note("double-free", "double free of a watched object (it is still in quarantine); ignored");
        return;
    }
    uint64_t payload = (uint64_t)(uintptr_t)p & TW_ADDR_MASK;
    uint64_t evict[8];
    unsigned n_evict = 0;
    int quarantined = 0;

    // A watched block goes to quarantine still armed; anything that touches
    // it from now on is reported as a use-after-free.
    if (q_limit && tw_on() && tw_watch_mark_freed(payload)) {
        os_unfair_lock_lock(&lock);
        if (q_count < QUEUE) {
            quarantine[(q_head + q_count++) % QUEUE] = payload;
            q_bytes += h->cap;
            h->magic = MAGIC_FREED; // a second free() of this block is now ignored
            quarantined = 1;
        }
        while (q_count && (q_bytes > q_limit || q_count == QUEUE) && n_evict < 8) {
            uint64_t old = quarantine[q_head];
            q_head = (q_head + 1) % QUEUE;
            q_count--;
            q_bytes -= ((hdr_t *)(uintptr_t)(old - HDR))->cap;
            evict[n_evict++] = old;
        }
        os_unfair_lock_unlock(&lock);
    }
    if (!quarantined) evict[n_evict++] = payload;
    for (unsigned i = 0; i < n_evict; i++) {
        // Disarm outside the arena lock (the watch module has its own).
        if (tw_on()) tw_watch_remove_addr(evict[i], evict[i] == payload && !quarantined ? "free" : "quarantine-evict");
        os_unfair_lock_lock(&lock);
        block_put(evict[i]);
        os_unfair_lock_unlock(&lock);
    }
}

// ---- malloc zone ------------------------------------------------------------
static size_t z_size(malloc_zone_t *z, const void *p) {
    (void)z;
    return tw_arena_size(p);
}
static void *z_malloc(malloc_zone_t *z, size_t size) {
    (void)z;
    return tw_arena_alloc(size, TW_GRANULE);
}
static void *z_calloc(malloc_zone_t *z, size_t n, size_t size) {
    (void)z;
    size_t total;
    if (__builtin_mul_overflow(n, size, &total)) return NULL;
    return tw_arena_alloc(total, TW_GRANULE);
}
static void *z_valloc(malloc_zone_t *z, size_t size) {
    (void)z;
    return tw_arena_alloc(size, TW_PAGE_SIZE);
}
static void z_free(malloc_zone_t *z, void *p) {
    (void)z;
    tw_arena_free(p);
}
static void *z_realloc(malloc_zone_t *z, void *p, size_t size) {
    (void)z;
    // The grown object is an ordinary one: whether the *new* size deserves a
    // watch is decided by the realloc interposer, which sees the call first.
    size_t old = tw_arena_size(p);
    void *q = malloc(size);
    if (!q) return NULL;
    uint64_t saved = tw_tco_save_and_set();
    memcpy(q, p, old < size ? old : size);
    tw_tco_restore(saved);
    tw_arena_free(p);
    return q;
}
static void z_destroy(malloc_zone_t *z) { (void)z; }
static void *z_memalign(malloc_zone_t *z, size_t align, size_t size) {
    (void)z;
    return tw_arena_alloc(size, align);
}
static void z_free_definite(malloc_zone_t *z, void *p, size_t size) {
    (void)z;
    (void)size;
    tw_arena_free(p);
}
static size_t z_pressure(malloc_zone_t *z, size_t goal) {
    (void)z;
    (void)goal;
    return 0;
}
static boolean_t z_claimed(malloc_zone_t *z, void *p) {
    (void)z;
    return tw_arena_owns(p);
}

static kern_return_t i_enumerator(task_t task, void *ctx, unsigned type_mask, vm_address_t zone_address, memory_reader_t reader,
                                  vm_range_recorder_t recorder) {
    (void)task, (void)ctx, (void)type_mask, (void)zone_address, (void)reader, (void)recorder;
    return KERN_SUCCESS;
}
static size_t i_good_size(malloc_zone_t *z, size_t size) {
    (void)z;
    return (size + TW_GRANULE_MASK) & ~(size_t)TW_GRANULE_MASK;
}
static boolean_t i_check(malloc_zone_t *z) {
    (void)z;
    return 1;
}
static void i_print(malloc_zone_t *z, boolean_t verbose) { (void)z, (void)verbose; }
static void i_log(malloc_zone_t *z, void *address) { (void)z, (void)address; }
static void i_force_lock(malloc_zone_t *z) {
    (void)z;
    os_unfair_lock_lock(&lock);
}
static void i_force_unlock(malloc_zone_t *z) {
    (void)z;
    os_unfair_lock_unlock(&lock);
}
static void i_statistics(malloc_zone_t *z, malloc_statistics_t *stats) {
    (void)z;
    memset(stats, 0, sizeof *stats);
    stats->size_allocated = next - base;
}
static boolean_t i_locked(malloc_zone_t *z) {
    (void)z;
    return 0;
}
static void i_reinit_lock(malloc_zone_t *z) {
    (void)z;
    lock = OS_UNFAIR_LOCK_INIT;
}

int tw_arena_init(void) {
    static const uint64_t sizes[] = {64ull << 30, 8ull << 30, 1ull << 30};
    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0] && !base; i++) {
        mach_vm_address_t addr = 0;
        if (mach_vm_map(mach_task_self(), &addr, sizes[i], 0, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE, MACH_PORT_NULL, 0, FALSE,
                        VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_DEFAULT) == KERN_SUCCESS) {
            base = next = addr;
            end = addr + sizes[i];
        }
    }
    if (!base) return -1;

    introspect.enumerator = i_enumerator;
    introspect.good_size = i_good_size;
    introspect.check = i_check;
    introspect.print = i_print;
    introspect.log = i_log;
    introspect.force_lock = i_force_lock;
    introspect.force_unlock = i_force_unlock;
    introspect.statistics = i_statistics;
    introspect.zone_locked = i_locked;
    introspect.reinit_lock = i_reinit_lock;
    zone.size = z_size;
    zone.malloc = z_malloc;
    zone.calloc = z_calloc;
    zone.valloc = z_valloc;
    zone.free = z_free;
    zone.realloc = z_realloc;
    zone.destroy = z_destroy;
    zone.zone_name = "tagwatch";
    zone.introspect = &introspect;
    zone.version = 10;
    zone.memalign = z_memalign;
    zone.free_definite_size = z_free_definite;
    zone.pressure_relief = z_pressure;
    zone.claimed_address = z_claimed;
    malloc_zone_register(&zone);
    return 0;
}

// watch: the set of live watches, and the code that arms and disarms them.
//
// Arming a range means: remember each granule's current allocation tag in the
// watch table, then store a different tag with STG. From that instant every
// pointer the program holds mismatches, and every access traps. Disarming
// stores the remembered tags back.
//
// One lock protects the table and the records. It is never held while
// touching program memory through ordinary (tag-checked) accesses, so the
// thread holding it cannot take a watch fault and deadlock the handler.
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

#include "internal.h"

#define CHUNK 1024
#define MAX_CHUNKS 4096 // 4.2 million simultaneous watches
#define ID_SHIFT 27     // public id = serial << ID_SHIFT | slot

static os_unfair_lock lock = OS_UNFAIR_LOCK_INIT;
// The thread that is inside fork() and holds the lock for its duration (see
// tw_watch_before_fork). Its own calls in that window must not take the
// lock again: libSystem's fork handlers call free() (and so the free
// interposer) on that thread, in the child, before tagwatch's own handler
// has run. Such calls see an empty table.
static _Atomic(pthread_t) fork_thread;
static tw_wtab table;
static tw_watch *chunks[MAX_CHUNKS];
static uint32_t n_slots = 1; // slot 0 is "no watch"
static uint32_t free_head;   // free slots are chained through .serial
static uint64_t next_serial = 1;
static uint64_t live_watches, total_watches;
_Atomic uint64_t tw_armed_granules;
_Atomic uint64_t tw_watch_generation;
_Atomic uint64_t tw_inplace_watches; // live watches on memory outside the arena

static tw_watch *slot_ptr(uint32_t slot) { return &chunks[slot / CHUNK][slot % CHUNK]; }

static inline int in_own_fork(void) {
    pthread_t t = atomic_load_explicit(&fork_thread, memory_order_relaxed);
    return t != NULL && pthread_equal(t, pthread_self());
}

static uint32_t slot_alloc(void) {
    if (free_head) {
        uint32_t s = free_head;
        free_head = (uint32_t)slot_ptr(s)->serial;
        return s;
    }
    if (n_slots >= MAX_CHUNKS * CHUNK) return 0;
    if (!chunks[n_slots / CHUNK]) {
        chunks[n_slots / CHUNK] = tw_vm_alloc(CHUNK * sizeof(tw_watch));
        if (!chunks[n_slots / CHUNK]) return 0;
    }
    return n_slots++;
}

static void slot_free(uint32_t s) {
    tw_watch *w = slot_ptr(s);
    memset(w, 0, sizeof *w);
    w->serial = free_head;
    free_head = s;
}

// Public ids carry the slot in the low bits and the serial above, so a stale
// id can be told apart from the slot's next tenant.
static tagwatch_id make_id(uint32_t slot, uint64_t serial) { return (tagwatch_id)((serial << ID_SHIFT) | slot); }

int tw_watch_module_init(void) { return tw_wtab_init(&table, &tw_vm_mem); }

static void disarm_locked(uint32_t slot) {
    tw_watch *w = slot_ptr(slot);
    // Guarded stores: the program may have unmapped the memory meanwhile.
    for (uint64_t a = w->gbase; a != w->gbase + w->glen; a += TW_GRANULE) {
        unsigned orig;
        if (tw_wtab_get(&table, a, &orig) == slot) (void)tw_mte_try_set_tag(a, orig);
    }
    if (!tw_arena_owns((const void *)(uintptr_t)w->base)) atomic_fetch_sub(&tw_inplace_watches, 1);
    uint64_t n = tw_wtab_remove(&table, w->gbase, w->glen, slot);
    atomic_fetch_sub(&tw_armed_granules, n);
    atomic_fetch_add(&tw_watch_generation, 1);
    live_watches--;
}

tagwatch_id tw_watch_add(uint64_t addr, uint64_t len, const char *label, unsigned mode, unsigned origin,
                         const uint64_t *bt, unsigned nbt) {
    addr &= TW_ADDR_MASK;
    if (len == 0 || addr + len < addr || !(mode & TAGWATCH_RW)) return -TAGWATCH_EINVAL;
    uint64_t gbase = addr & ~TW_GRANULE_MASK;
    uint64_t glen = ((addr + len + TW_GRANULE_MASK) & ~TW_GRANULE_MASK) - gbase;
    if (in_own_fork()) return -TAGWATCH_EBUSY;

    os_unfair_lock_lock(&lock);
    uint32_t slot = slot_alloc();
    if (!slot) {
        os_unfair_lock_unlock(&lock);
        return -TAGWATCH_ENOMEM;
    }
    int rc = tw_wtab_insert(&table, gbase, glen, slot);
    if (rc != 0) {
        slot_free(slot);
        os_unfair_lock_unlock(&lock);
        return rc == -EEXIST ? -TAGWATCH_EEXIST : rc == -ENOMEM ? -TAGWATCH_ENOMEM : -TAGWATCH_EINVAL;
    }
    // Arm. The first load and store on each page are the guarded ones: they
    // report unmapped memory, and memory that is not in an MTE mapping,
    // instead of crashing.
    uint64_t a = gbase, probed_page = UINT64_MAX;
    for (; a != gbase + glen; a += TW_GRANULE) {
        int fresh_page = (a >> TW_PAGE_SHIFT) != probed_page;
        int got = fresh_page ? tw_mte_try_get_tag(a) : (int)tw_mte_get_tag(a);
        if (got < 0) break;
        unsigned orig = (unsigned)got, wt = tw_watch_tag(orig);
        tw_wtab_set_orig_tag(&table, a, orig);
        if (fresh_page) {
            if (tw_mte_try_set_tag(a, wt) != 0) break;
            probed_page = a >> TW_PAGE_SHIFT;
        } else {
            tw_mte_set_tag(a, wt);
        }
    }
    if (a != gbase + glen) { // untaggable page: undo what was armed
        for (uint64_t u = gbase; u != a; u += TW_GRANULE) {
            unsigned orig;
            tw_wtab_get(&table, u, &orig);
            tw_mte_set_tag(u, orig);
        }
        tw_wtab_remove(&table, gbase, glen, slot);
        slot_free(slot);
        os_unfair_lock_unlock(&lock);
        return -TAGWATCH_ENOTTAGGED;
    }
    tw_watch *w = slot_ptr(slot);
    memset(w, 0, sizeof *w);
    w->base = addr;
    w->len = len;
    w->gbase = gbase;
    w->glen = glen;
    w->serial = next_serial++;
    w->flags = TW_WF_ACTIVE;
    w->mode = (uint8_t)mode;
    w->origin = (uint8_t)origin;
    w->id = make_id(slot, w->serial);
    if (!tw_arena_owns((const void *)(uintptr_t)addr)) atomic_fetch_add(&tw_inplace_watches, 1);
    if (label) strlcpy(w->label, label, sizeof w->label);
    live_watches++;
    total_watches++;
    atomic_fetch_add(&tw_armed_granules, glen / TW_GRANULE);
    atomic_fetch_add(&tw_watch_generation, 1);
    tw_watch copy = *w;
    os_unfair_lock_unlock(&lock);

    tw_emit_watch(&copy, bt, nbt);
    return copy.id;
}

static int remove_slot(uint32_t slot, uint64_t serial_or_zero, const char *reason) {
    if (in_own_fork()) return -TAGWATCH_ENOENT;
    os_unfair_lock_lock(&lock);
    if (slot == 0 || slot >= n_slots) {
        os_unfair_lock_unlock(&lock);
        return -TAGWATCH_ENOENT;
    }
    tw_watch *w = slot_ptr(slot);
    if (!(w->flags & TW_WF_ACTIVE) || (serial_or_zero && w->serial != serial_or_zero)) {
        os_unfair_lock_unlock(&lock);
        return -TAGWATCH_ENOENT;
    }
    tw_watch copy = *w;
    disarm_locked(slot);
    slot_free(slot);
    os_unfair_lock_unlock(&lock);
    tw_emit_unwatch(copy.serial, reason, copy.reads, copy.writes);
    return 0;
}

int tw_watch_remove_id(tagwatch_id id, const char *reason) {
    if (id <= 0) return -TAGWATCH_ENOENT;
    return remove_slot((uint32_t)(id & TW_SLOT_MAX), (uint64_t)id >> ID_SHIFT, reason);
}

int tw_watch_remove_addr(uint64_t addr, const char *reason) {
    if (in_own_fork()) return -TAGWATCH_ENOENT;
    os_unfair_lock_lock(&lock);
    uint32_t slot = tw_wtab_get(&table, addr & TW_ADDR_MASK, NULL);
    os_unfair_lock_unlock(&lock);
    // A concurrent remove of the same watch makes the second one a no-op.
    return slot ? remove_slot(slot, 0, reason) : -TAGWATCH_ENOENT;
}

// Removes every watch that intersects [addr, addr+len). Returns how many.
int tw_watch_remove_range(uint64_t addr, uint64_t len, const char *reason) {
    int n = 0;
    addr &= TW_ADDR_MASK;
    if (in_own_fork()) return 0;
    for (;;) {
        os_unfair_lock_lock(&lock);
        uint32_t slot = tw_wtab_find(&table, addr, len, NULL);
        os_unfair_lock_unlock(&lock);
        if (!slot) return n;
        if (remove_slot(slot, 0, reason) == 0) n++;
    }
}

// Marks every watch intersecting [addr, addr+len) as freed (they stay
// armed). Returns how many.
int tw_watch_mark_freed(uint64_t addr, uint64_t len) {
    uint64_t serials[16];
    int n = 0;
    addr &= TW_ADDR_MASK;
    uint64_t end = addr + len;
    if (in_own_fork()) return 0;
    os_unfair_lock_lock(&lock);
    while (addr < end) {
        uint64_t hit = 0;
        uint32_t slot = tw_wtab_find(&table, addr, end - addr, &hit);
        if (!slot) break;
        tw_watch *w = slot_ptr(slot);
        if (!(w->flags & TW_WF_FREED)) {
            w->flags |= TW_WF_FREED;
            if (n < 16) serials[n] = w->serial;
            n++;
        }
        addr = w->gbase + w->glen; // continue after this watch
    }
    os_unfair_lock_unlock(&lock);
    for (int i = 0; i < n && i < 16; i++) tw_emit_freed(serials[i]);
    return n;
}

int tw_watch_hit(uint64_t ea, uint64_t size, uint64_t far, unsigned access, tw_watch *out, uint64_t *slack,
                 unsigned *tag_now) {
    ea &= TW_ADDR_MASK;
    far &= TW_ADDR_MASK;
    if (in_own_fork()) return 0;
    os_unfair_lock_lock(&lock);
    uint32_t slot = size ? tw_wtab_find(&table, ea, size, NULL) : 0;
    if (!slot) slot = tw_wtab_get(&table, far, NULL);
    if (!slot) {
        // Read the granule's tag while still holding the lock: arming and
        // disarming change the table and the tags under this same lock, so
        // "not in the table" and "this tag" describe one consistent moment.
        if (tag_now) *tag_now = tw_mte_get_tag(far);
        os_unfair_lock_unlock(&lock);
        return 0;
    }
    tw_watch *w = slot_ptr(slot);
    // The granule is armed, but did the access touch the bytes the user asked
    // for? A 16-byte granule can be shared with a neighbouring object.
    uint64_t lo = size ? ea : far, hi = size ? ea + size : far + 1;
    *slack = !(lo < w->base + w->len && hi > w->base);
    if (!*slack) {
        if (access & TAGWATCH_READ) w->reads++;
        if (access & TAGWATCH_WRITE) w->writes++;
    }
    *out = *w;
    os_unfair_lock_unlock(&lock);
    return 1;
}

int tw_watch_overlaps(uint64_t addr, uint64_t len) {
    if (atomic_load_explicit(&tw_armed_granules, memory_order_relaxed) == 0 || len == 0 || in_own_fork()) return 0;
    os_unfair_lock_lock(&lock);
    uint32_t slot = tw_wtab_find(&table, addr & TW_ADDR_MASK, len, NULL);
    os_unfair_lock_unlock(&lock);
    return slot != 0;
}

static void restore_tag(uint64_t addr, unsigned orig_tag, void *ctx) {
    (void)ctx;
    (void)tw_mte_try_set_tag(addr, orig_tag);
}

// fork() copies the address space one VM entry at a time while other threads
// keep running, so the child's copy of the table and its copy of the tags
// could come from different instants. The forking thread therefore holds
// the lock from before the fork until after it: no arming or disarming is
// in progress while the kernel copies, and the child's snapshot is
// consistent. (wtab.c additionally orders its stores so that a snapshot
// taken mid-operation is safe to walk, but that alone is not enough.)
void tw_watch_before_fork(void) {
    os_unfair_lock_lock(&lock);
    atomic_store(&fork_thread, pthread_self());
}
void tw_watch_after_fork_parent(void) {
    atomic_store(&fork_thread, NULL);
    os_unfair_lock_unlock(&lock);
}

void tw_watch_disarm_all(void) {
    // Runs in a fork child. The lock was held by the forking thread, which
    // is the only thread that exists here; the child's copy is re-initialised
    // rather than unlocked because os_unfair_lock records its owner. The
    // table says exactly which granules carry a watch tag and what to put
    // back; it is left as it is afterwards, as the child never arms anything
    // again.
    lock = OS_UNFAIR_LOCK_INIT;
    atomic_store(&fork_thread, NULL);
    tw_wtab_foreach_armed(&table, restore_tag, NULL);
    for (uint32_t s = 1; s < n_slots; s++) slot_ptr(s)->flags = 0;
    atomic_store(&tw_armed_granules, 0);
    atomic_store(&tw_inplace_watches, 0);
    live_watches = 0;
}

// Probes whether the page holding addr is an MTE mapping, under the watch
// lock so that the probe (which writes the tag it just read) cannot race
// with a watch being armed or disarmed on the same granule.
int tw_watch_page_taggable(uint64_t addr) {
    if (in_own_fork()) return 0;
    os_unfair_lock_lock(&lock);
    int tag = tw_mte_try_get_tag(addr);
    int ok = tag >= 0 && tw_mte_try_set_tag(addr, (unsigned)tag) == 0;
    os_unfair_lock_unlock(&lock);
    return ok;
}

void tw_watch_counts(uint64_t *live, uint64_t *total, uint64_t *granules) {
    if (in_own_fork()) {
        *live = *total = *granules = 0;
        return;
    }
    os_unfair_lock_lock(&lock);
    *live = live_watches;
    *total = total_watches;
    *granules = table.granules;
    os_unfair_lock_unlock(&lock);
}

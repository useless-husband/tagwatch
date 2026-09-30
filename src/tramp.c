// tramp: out-of-line execution slots.
//
// A watched granule has the "wrong" tag for every pointer the program holds,
// so the faulting instruction can never succeed where it stands. Instead of
// putting the right tag back for a moment (which would let other threads
// through unseen), tagwatch runs a copy of the instruction in a slot:
//
//     msr  TCO, #1        ; tag checks off, this thread only
//     <the instruction>
//     msr  TCO, #0
//     b    pc + 4         ; "near" slot: one exception per access
//
// B reaches +-128 MB and there is no way to jump further without clobbering
// a register, so slots are allocated near the code they serve. Where that is
// impossible (code deep inside the dyld shared cache) the slot ends in BRK
// and the exception thread finishes the return: two exceptions per access.
//
// The instruction is a load or store with a register base, so it behaves the
// same at any address. Slots are per pc and immutable once written, so any
// number of threads can run the same slot at once. Only the exception
// thread calls into this file.
#include <libkern/OSCacheControl.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "internal.h"

#define SLOT_BYTES 16
#define POOL_BYTES (4 * TW_PAGE_SIZE)
#define POOL_SLOTS (POOL_BYTES / SLOT_BYTES)
#define MAX_POOLS 256
#define REACH (120ull << 20) // stay clear of the +-128 MB limit

#define INSN_TCO_ON 0xd503419fu
#define INSN_TCO_OFF 0xd503409fu
#define INSN_BRK 0xd42e8ee0u // brk #0x7477

typedef struct {
    uint64_t base;
    uint32_t used;
    uint64_t *orig_pc; // per slot
} pool_t;

typedef struct {
    uint64_t pc; // 0 = empty
    uint64_t entry;
    uint32_t insn;
    uint32_t far;
} map_t;

static pool_t pools[MAX_POOLS];
static int n_pools;
static map_t *map;
static size_t map_cap, map_used;
static int force_far; // TAGWATCH_FORCE_FAR=1: always return through BRK (tests, benchmarks)
// Neighbourhoods (64 MB buckets) where the search for nearby free address
// space already failed; searching again for every new pc there would cost
// thousands of system calls each time.
#define HOPELESS_MAX 128
static uint64_t hopeless[HOPELESS_MAX];
static int n_hopeless;

static size_t map_bucket(uint64_t pc) { return (size_t)(((pc >> 2) * 0x9e3779b97f4a7c15ull) >> 32) & (map_cap - 1); }

static int map_grow(void) {
    size_t ncap = map_cap ? map_cap * 2 : 1024;
    map_t *nm = tw_vm_alloc(ncap * sizeof *nm), *om = map;
    if (!nm) return -1;
    size_t ocap = map_cap;
    map = nm;
    map_cap = ncap;
    for (size_t i = 0; i < ocap; i++) {
        if (!om[i].pc) continue;
        size_t j = map_bucket(om[i].pc);
        while (map[j].pc) j = (j + 1) & (map_cap - 1);
        map[j] = om[i];
    }
    tw_vm_free(om, ocap * sizeof *om);
    return 0;
}

static void *map_jit(uint64_t hint) {
    void *p = mmap((void *)(uintptr_t)hint, POOL_BYTES, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_JIT | MAP_ANON | MAP_PRIVATE, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

int tw_tramp_init(void) {
    const char *ff = getenv("TAGWATCH_FORCE_FAR");
    force_far = ff && ff[0] == '1';
    if (map_grow() != 0) return -1;
    // Fail early if this process may not create JIT memory (hardened runtime
    // without the allow-jit entitlement).
    void *p = map_jit(0);
    if (!p) return -1;
    munmap(p, POOL_BYTES);
    return 0;
}

static uint64_t distance(uint64_t a, uint64_t b) { return a > b ? a - b : b - a; }

static pool_t *add_pool(uint64_t base) {
    if (n_pools == MAX_POOLS) return NULL;
    uint64_t *orig = tw_vm_alloc(POOL_SLOTS * sizeof *orig);
    if (!orig) return NULL;
    pool_t *p = &pools[n_pools++];
    p->base = base;
    p->used = 0;
    p->orig_pc = orig;
    return p;
}

// Finds unmapped address space within branch range of pc and maps a pool
// there. The kernel treats the mmap address as a hint, so verify the result.
static pool_t *new_pool_near(uint64_t pc) {
    // Round the lower bound up: a pool starting one page below pc - REACH
    // would fail the distance check below and lose the whole first gap.
    uint64_t lo = pc > REACH ? ((pc - REACH) & ~(TW_PAGE_SIZE - 1)) + TW_PAGE_SIZE : TW_PAGE_SIZE;
    uint64_t hi = pc + REACH - POOL_BYTES;
    mach_vm_address_t addr = lo;
    for (int tries = 0; tries < 4096 && addr < hi; tries++) {
        mach_vm_address_t raddr = addr;
        mach_vm_size_t rsize = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        kern_return_t kr = mach_vm_region(mach_task_self(), &raddr, &rsize, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj);
        if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);
        uint64_t gap_end = kr == KERN_SUCCESS ? raddr : hi + POOL_BYTES;
        if (gap_end > addr && gap_end - addr >= POOL_BYTES) {
            // Prefer the end of the gap nearest to pc.
            uint64_t want = addr;
            if (gap_end <= pc) want = gap_end - POOL_BYTES;
            void *p = map_jit(want);
            if (p) {
                uint64_t got = (uint64_t)(uintptr_t)p;
                if (distance(got, pc) < REACH && distance(got + POOL_BYTES, pc) < REACH) return add_pool(got);
                munmap(p, POOL_BYTES);
            }
        }
        if (kr != KERN_SUCCESS) break;
        addr = raddr + rsize;
    }
    return NULL;
}

static pool_t *pool_near(uint64_t pc) {
    for (int i = 0; i < n_pools; i++)
        if (pools[i].used < POOL_SLOTS && distance(pools[i].base, pc) < REACH && distance(pools[i].base + POOL_BYTES, pc) < REACH)
            return &pools[i];
    uint64_t bucket = pc >> 26;
    for (int i = 0; i < n_hopeless; i++)
        if (hopeless[i] == bucket) return NULL;
    pool_t *p = new_pool_near(pc);
    if (!p && n_hopeless < HOPELESS_MAX) hopeless[n_hopeless++] = bucket;
    return p;
}

static pool_t *pool_any(void) {
    for (int i = 0; i < n_pools; i++)
        if (pools[i].used < POOL_SLOTS) return &pools[i];
    void *p = map_jit(0);
    if (!p) return NULL;
    pool_t *pl = add_pool((uint64_t)(uintptr_t)p);
    if (!pl) munmap(p, POOL_BYTES);
    return pl;
}

static void write_slot(uint64_t entry, uint64_t pc, uint32_t insn, int far) {
    uint32_t *w = (uint32_t *)(uintptr_t)entry;
    uint32_t tail = INSN_BRK;
    if (!far) {
        int64_t off = (int64_t)(pc + 4) - (int64_t)(entry + 12);
        tail = 0x14000000u | ((uint32_t)(off >> 2) & 0x03ffffffu);
    }
    pthread_jit_write_protect_np(0); // this thread: writable, not executable
    w[0] = INSN_TCO_ON;
    w[1] = insn;
    w[2] = INSN_TCO_OFF;
    w[3] = tail;
    pthread_jit_write_protect_np(1);
    sys_icache_invalidate(w, SLOT_BYTES);
}

uint64_t tw_tramp_get(uint64_t pc, uint32_t insn, int *far) {
    size_t i = map_bucket(pc);
    while (map[i].pc && map[i].pc != pc) i = (i + 1) & (map_cap - 1);
    if (map[i].pc == pc) {
        if (map[i].insn != insn) { // the code at pc changed (JIT, or an image reloaded at the same address)
            map[i].insn = insn;
            write_slot(map[i].entry, pc, insn, (int)map[i].far);
        }
        *far = (int)map[i].far;
        return map[i].entry;
    }
    if ((map_used + 1) * 10 > map_cap * 7) {
        if (map_grow() != 0) return 0;
        i = map_bucket(pc);
        while (map[i].pc) i = (i + 1) & (map_cap - 1);
    }
    int is_far = 0;
    pool_t *p = force_far ? NULL : pool_near(pc);
    if (!p) {
        p = pool_any();
        is_far = 1;
    }
    if (!p) return 0;
    uint64_t entry = p->base + (uint64_t)p->used * SLOT_BYTES;
    p->orig_pc[p->used++] = pc;
    write_slot(entry, pc, insn, is_far);
    map[i].pc = pc;
    map[i].entry = entry;
    map[i].insn = insn;
    map[i].far = (uint32_t)is_far;
    map_used++;
    *far = is_far;
    return entry;
}

int tw_tramp_owner(uint64_t addr, uint64_t *entry, uint64_t *orig_pc, unsigned *word) {
    for (int i = 0; i < n_pools; i++) {
        if (addr < pools[i].base || addr >= pools[i].base + POOL_BYTES) continue;
        uint64_t slot = (addr - pools[i].base) / SLOT_BYTES;
        if (slot >= pools[i].used) return 0;
        *entry = pools[i].base + slot * SLOT_BYTES;
        *orig_pc = pools[i].orig_pc[slot];
        *word = (unsigned)((addr - *entry) / 4);
        return 1;
    }
    return 0;
}

uint64_t tw_tramp_count(void) { return map_used; }

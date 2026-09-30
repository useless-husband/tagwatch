// pagewatch: the classic alternative to hardware watchpoints — protect the
// page that holds the watched object, take a fault on every access to the
// page, single-step the instruction with the page unprotected, protect it
// again. Runs the kv workload and watches one node in K, to measure how many
// of its traps are for memory nobody asked about.
//   usage: pagewatch [nodes] [operations] [K]
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#include "excport.h"
#include "kv.h"

#define PAGE 16384ull

static struct kv table;
static uint64_t every;
static uint8_t *page_armed;        // one flag per page of the address range that holds nodes
static uint64_t range_lo, range_hi;
static uint64_t traps, hits, stepping_page;

static int is_watched_node(uint64_t addr) {
    // Watched nodes are those at indices 0, K, 2K, ... in allocation order.
    for (uint64_t i = 0; i < table.n; i += every) {
        uint64_t p = (uint64_t)(uintptr_t)table.all[i];
        if (addr >= p && addr < p + sizeof(struct kv_node)) return 1;
    }
    return 0;
}

static kern_return_t on_exception(thread_t th, exception_type_t exc, int64_t code0, int64_t code1) {
    (void)code0;
    if (exc == EXC_BAD_ACCESS) {
        uint64_t addr = (uint64_t)code1, page = addr & ~(PAGE - 1);
        if (addr < range_lo || addr >= range_hi || !page_armed[(page - range_lo) / PAGE]) return KERN_FAILURE;
        traps++;
        hits += (uint64_t)is_watched_node(addr);
        mprotect((void *)(uintptr_t)page, PAGE, PROT_READ | PROT_WRITE);
        stepping_page = page;
        bx_single_step(th, 1);
        return KERN_SUCCESS;
    }
    if (exc == EXC_BREAKPOINT && stepping_page) {
        bx_single_step(th, 0);
        mprotect((void *)(uintptr_t)stepping_page, PAGE, PROT_NONE);
        stepping_page = 0;
        return KERN_SUCCESS;
    }
    return KERN_FAILURE;
}

int main(int argc, char **argv) {
    uint64_t n = argc > 1 ? strtoull(argv[1], NULL, 0) : 100000;
    uint64_t m = argc > 2 ? strtoull(argv[2], NULL, 0) : 1000000;
    every = argc > 3 ? strtoull(argv[3], NULL, 0) : 1000;
    alarm(600);
    kv_build(&table, n);
    range_lo = UINT64_MAX;
    for (uint64_t i = 0; i < n; i++) {
        uint64_t p = (uint64_t)(uintptr_t)table.all[i];
        if (p < range_lo) range_lo = p;
        if (p + sizeof(struct kv_node) > range_hi) range_hi = p + sizeof(struct kv_node);
    }
    range_lo &= ~(PAGE - 1);
    range_hi = (range_hi + PAGE - 1) & ~(PAGE - 1);
    page_armed = calloc((range_hi - range_lo) / PAGE, 1);
    if (bx_start(on_exception, EXC_MASK_BAD_ACCESS | EXC_MASK_BREAKPOINT) != 0) return 1;
    uint64_t watched = 0, pages = 0;
    for (uint64_t i = 0; i < n; i += every, watched++) {
        uint64_t p = (uint64_t)(uintptr_t)table.all[i];
        for (uint64_t page = p & ~(PAGE - 1); page < p + sizeof(struct kv_node); page += PAGE)
            if (!page_armed[(page - range_lo) / PAGE]) {
                page_armed[(page - range_lo) / PAGE] = 1;
                pages++;
            }
    }
    for (uint64_t page = range_lo; page < range_hi; page += PAGE)
        if (page_armed[(page - range_lo) / PAGE]) mprotect((void *)(uintptr_t)page, PAGE, PROT_NONE);

    uint64_t t0 = kv_now_ns();
    uint64_t sum = kv_run(&table, m);
    uint64_t t1 = kv_now_ns();

    for (uint64_t page = range_lo; page < range_hi; page += PAGE)
        if (page_armed[(page - range_lo) / PAGE]) mprotect((void *)(uintptr_t)page, PAGE, PROT_READ | PROT_WRITE);
    printf("pagewatch nodes=%llu ops=%llu every=%llu watched=%llu pages=%llu checksum=%llu ops_ms=%.2f traps=%llu hits=%llu "
           "false_traps=%llu false_pct=%.2f us_per_trap=%.2f\n",
           (unsigned long long)n, (unsigned long long)m, (unsigned long long)every, (unsigned long long)watched,
           (unsigned long long)pages, (unsigned long long)sum, (double)(t1 - t0) / 1e6, (unsigned long long)traps,
           (unsigned long long)hits, (unsigned long long)(traps - hits), traps ? 100.0 * (double)(traps - hits) / (double)traps : 0.0,
           traps ? (double)(t1 - t0) / 1e3 / (double)traps : 0.0);
    return 0;
}

// hwwatch: hardware data watchpoints, driven the way a debugger drives them
// (the debug registers of a thread, via thread_set_state) but from inside
// the process, so the measurement contains no debugger round trips. This is
// a lower bound for what LLDB costs per hit, and it shows the register limit.
//   usage: hwwatch [hits]
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

#include "excport.h"

static volatile uint64_t slots[8];
static uint64_t traps;
static thread_t main_thread;
static uint64_t saved_wcr0;

// WCR: byte address select 0xff (8 bytes), load+store, EL0 only, enabled.
#define WCR_RW8 ((0xffull << 5) | (3ull << 3) | (2ull << 1) | 1ull)

static kern_return_t set_watch(thread_t th, int reg, const volatile void *addr, int enable) {
    arm_debug_state64_t ds;
    mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
    kern_return_t kr = thread_get_state(th, ARM_DEBUG_STATE64, (thread_state_t)&ds, &cnt);
    if (kr) return kr;
    ds.__wvr[reg] = (uint64_t)(uintptr_t)addr;
    ds.__wcr[reg] = enable ? WCR_RW8 : 0;
    return thread_set_state(th, ARM_DEBUG_STATE64, (thread_state_t)&ds, ARM_DEBUG_STATE64_COUNT);
}

static kern_return_t on_exception(thread_t th, exception_type_t exc, int64_t code0, int64_t code1) {
    (void)code1;
    if (exc != EXC_BREAKPOINT) return KERN_FAILURE;

    arm_debug_state64_t ds;
    mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
    if (thread_get_state(th, ARM_DEBUG_STATE64, (thread_state_t)&ds, &cnt) != KERN_SUCCESS) return KERN_FAILURE;
    if (code0 == 0x102) { // EXC_ARM_DA_DEBUG: the watchpoint fired before the access; step over it with the watchpoint off
        traps++;
        saved_wcr0 = ds.__wcr[0];
        ds.__wcr[0] = 0;
        ds.__mdscr_el1 |= 1;
    } else { // single-step done: watchpoint back on
        ds.__wcr[0] = saved_wcr0;
        ds.__mdscr_el1 &= ~1ull;
    }
    return thread_set_state(th, ARM_DEBUG_STATE64, (thread_state_t)&ds, ARM_DEBUG_STATE64_COUNT);
}

int main(int argc, char **argv) {
    int hits = argc > 1 ? atoi(argv[1]) : 20000;
    alarm(120);
    int nreg = 0;
    size_t len = sizeof nreg;
    sysctlbyname("hw.optional.watchpoint", &nreg, &len, NULL, 0);
    printf("hwwatch hw.optional.watchpoint=%d\n", nreg);
    main_thread = mach_thread_self();
    if (bx_start(on_exception, EXC_MASK_BREAKPOINT) != 0) return 1;

    if (set_watch(main_thread, 0, &slots[0], 1) != KERN_SUCCESS) return 1;

    // Cost per hit with one watchpoint (on slots[0]).
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    int yield = getenv("HW_YIELD") != NULL;
    for (int i = 0; i < hits; i++) {
        slots[0] = (uint64_t)i;
        if (yield) sched_yield();
    }
    clock_gettime(CLOCK_MONOTONIC, &b);
    set_watch(main_thread, 0, &slots[0], 0);
    double us = ((double)(b.tv_sec - a.tv_sec) * 1e9 + (double)(b.tv_nsec - a.tv_nsec)) / 1e3;
    printf("hwwatch hits=%d traps=%llu us_per_hit=%.2f value=%llu\n", hits, (unsigned long long)traps, traps ? us / (double)traps : 0.0,
           (unsigned long long)slots[0]);
    return 0;
}

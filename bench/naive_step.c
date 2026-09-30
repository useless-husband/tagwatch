// naive_step: the design tagwatch rejected, kept as a measured baseline.
// On a tag-check fault: put the original tag back on the granule, single-step
// the instruction, put the watch tag back. It needs two exceptions and two
// debug-state system calls per access, and while the original tag is in
// place every other thread can touch the granule without being seen.
//   usage: naive_step [accesses]      (must be signed with the MTE entitlements)
#include <arm_acle.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "excport.h"

#ifndef VM_FLAGS_MTE
#define VM_FLAGS_MTE 0x00002000
#endif

static uint64_t granule;
static uint64_t traps;

static void set_tag(unsigned tag) { __arm_mte_set_tag((void *)(uintptr_t)(granule | ((uint64_t)tag << 56))); }

static kern_return_t on_exception(thread_t th, exception_type_t exc, int64_t code0, int64_t code1) {
    (void)code1;
    if (exc == EXC_BAD_ACCESS && code0 == 0x106) { // tag-check fault
        traps++;
        set_tag(0);
        bx_single_step(th, 1);
        return KERN_SUCCESS;
    }
    if (exc == EXC_BREAKPOINT) {
        bx_single_step(th, 0);
        set_tag(9);
        return KERN_SUCCESS;
    }
    return KERN_FAILURE;
}

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 20000;
    alarm(300);
    mach_vm_address_t addr = 0;
    if (mach_vm_map(mach_task_self(), &addr, 1 << 14, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE, MACH_PORT_NULL, 0, FALSE,
                    VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_DEFAULT) != KERN_SUCCESS) {
        printf("naive_step: skipped (MTE is not enabled for this process)\n");
        return 77;
    }
    // Same recovery precondition as tagwatch: a traced process, with a parent that reaps it.
    pid_t child = fork();
    if (child != 0) {
        int st = 0;
        while (waitpid(child, &st, 0) > 0 && WIFSTOPPED(st)) ptrace(PT_CONTINUE, child, (caddr_t)1, WSTOPSIG(st));
        return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
    }
    ptrace(PT_TRACE_ME, 0, 0, 0);
    if (bx_start(on_exception, EXC_MASK_BAD_ACCESS | EXC_MASK_BREAKPOINT) != 0) return 1;
    granule = addr;
    volatile uint64_t *p = (volatile uint64_t *)(uintptr_t)addr;
    p[0] = p[1] = 0;
    set_tag(9);
    struct timespec a, b;
    uint64_t sum = 0;
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (int i = 0; i < n; i++) {
        p[0] = (uint64_t)i;
        sum += p[1];
    }
    clock_gettime(CLOCK_MONOTONIC, &b);
    set_tag(0);
    double us = ((double)(b.tv_sec - a.tv_sec) * 1e9 + (double)(b.tv_nsec - a.tv_nsec)) / 1e3;
    printf("naive_step traps=%llu us_per_trap=%.2f (retag + single-step + retag: 2 exceptions per access)\n", (unsigned long long)traps,
           us / (double)traps);
    return sum == 0 && traps == (uint64_t)(2 * n) ? 0 : 1;
}

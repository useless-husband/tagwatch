// Experiment: can the fault handler live in another process?
//
// The parent gives the child an exception port at spawn time
// (posix_spawnattr_setexceptionports_np), so the child's tag-check faults are
// delivered to the parent together with the faulting thread's registers. The
// child arms one granule and stores to it n times; the parent "handles" each
// fault by skipping the instruction (pc += 4), which is enough to measure the
// round trip and to see whether recovery works from outside.
//
//   cc -O2 -march=armv8.5-a+memtag -o external_handler external_handler.c && ./external_handler
//
// Result on the development machine is recorded in docs/DESIGN.md.
#include <arm_acle.h>
#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef VM_FLAGS_MTE
#define VM_FLAGS_MTE 0x00002000
#endif
extern char **environ;
extern int posix_spawnattr_set_use_sec_transition_shims_np(posix_spawnattr_t *attr, uint32_t flags) __attribute__((weak_import));

#pragma pack(push, 4)
typedef struct {
    mach_msg_header_t head;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t thread, task;
    NDR_record_t ndr;
    exception_type_t exception;
    mach_msg_type_number_t code_count;
    int64_t code[2];
    int flavor;
    mach_msg_type_number_t state_count;
    natural_t state[1296];
    char trailer[128];
} request_t;
typedef struct {
    mach_msg_header_t head;
    NDR_record_t ndr;
    kern_return_t ret;
    int flavor;
    mach_msg_type_number_t state_count;
    natural_t state[1296];
} reply_t;
#pragma pack(pop)

static mach_port_t port;
static volatile unsigned long handled, other;

static void *serve(void *arg) {
    (void)arg;
    static request_t rq;
    static reply_t rp;
    for (;;) {
        if (mach_msg(&rq.head, MACH_RCV_MSG, 0, sizeof rq, port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) != KERN_SUCCESS) return NULL;
        memset(&rp, 0, sizeof(mach_msg_header_t) + sizeof(NDR_record_t) + 12);
        rp.head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(rq.head.msgh_bits), 0);
        rp.head.msgh_remote_port = rq.head.msgh_remote_port;
        rp.head.msgh_id = rq.head.msgh_id + 100;
        rp.ndr = NDR_record;
        rp.flavor = rq.flavor;
        if (rq.exception == EXC_BAD_ACCESS && rq.code[0] == 0x106 && rq.flavor == ARM_THREAD_STATE64) {
            memcpy(rp.state, rq.state, rq.state_count * 4);
            ((arm_thread_state64_t *)(void *)rp.state)->__pc += 4;
            rp.state_count = rq.state_count;
            rp.ret = KERN_SUCCESS;
            handled++;
        } else {
            rp.ret = KERN_FAILURE;
            other++;
        }
        rp.head.msgh_size = (mach_msg_size_t)(sizeof(mach_msg_header_t) + sizeof(NDR_record_t) + 12 + rp.state_count * 4);
        mach_msg(&rp.head, MACH_SEND_MSG, rp.head.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        mach_port_deallocate(mach_task_self(), rq.thread.name);
        mach_port_deallocate(mach_task_self(), rq.task.name);
    }
}

static int child(int n, int traced) {
    alarm(30);
    if (traced) ptrace(PT_TRACE_ME, 0, 0, 0);
    mach_vm_address_t addr = 0;
    kern_return_t kr = mach_vm_map(mach_task_self(), &addr, 1 << 14, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE, MACH_PORT_NULL, 0, FALSE,
                                   VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_DEFAULT);
    if (kr != KERN_SUCCESS) {
        printf("child: MTE is not enabled (kr=%d)\n", kr);
        return 3;
    }
    volatile uint64_t *p = (volatile uint64_t *)(uintptr_t)addr;
    __arm_mte_set_tag((void *)(uintptr_t)(addr | (9ull << 56)));
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (int i = 0; i < n; i++) p[0] = 1; // faults; the parent skips the store
    clock_gettime(CLOCK_MONOTONIC, &b);
    printf("child: survived %d faulting stores, %.2f us each (handled in the parent process)\n", n,
           ((double)(b.tv_sec - a.tv_sec) * 1e9 + (double)(b.tv_nsec - a.tv_nsec)) / 1e3 / n);
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc > 1 && !strcmp(argv[1], "child")) return child(atoi(argv[2]), atoi(argv[3]));
    if (!posix_spawnattr_set_use_sec_transition_shims_np) {
        printf("no spawn SPI on this system\n");
        return 1;
    }
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    pthread_t t;
    pthread_create(&t, NULL, serve, NULL);
    for (int traced = 0; traced <= 1; traced++) {
        posix_spawnattr_t attr;
        posix_spawnattr_init(&attr);
        posix_spawnattr_set_use_sec_transition_shims_np(&attr, 1);
        int rc = posix_spawnattr_setexceptionports_np(&attr, EXC_MASK_BAD_ACCESS, port,
                                                      (exception_behavior_t)(EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES),
                                                      ARM_THREAD_STATE64);
        char *args[] = {argv[0], "child", "5000", traced ? "1" : "0", NULL};
        pid_t pid;
        handled = other = 0;
        if (rc != 0 || posix_spawn(&pid, argv[0], NULL, &attr, args, environ) != 0) {
            printf("spawn failed\n");
            return 1;
        }
        int st = 0;
        while (waitpid(pid, &st, 0) > 0 && WIFSTOPPED(st)) ptrace(PT_CONTINUE, pid, (caddr_t)1, WSTOPSIG(st) == SIGKILL ? SIGKILL : 0);
        printf("parent: child %s ptrace(PT_TRACE_ME): %lu tag faults handled here, %lu other exceptions; child %s %d\n",
               traced ? "with" : "without", handled, other, WIFEXITED(st) ? "exited with" : "was killed by signal",
               WIFEXITED(st) ? WEXITSTATUS(st) : WTERMSIG(st));
    }
    return 0;
}

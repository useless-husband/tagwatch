// Experiment: three ways to let a trapped access proceed.
//
//   retag-step  put the original tag back, single-step, put the watch tag back
//   tco-state   set PSTATE.TCO through the thread state and single-step
//   tramp       run a copy of the instruction out of line, bracketed by MSR TCO
//
// usage: let_access_proceed <mode> [n]      (see experiments/README.md for how
// to build and sign it, and for the results on the development machine)
#include <arm_acle.h>
#include <errno.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_statistics.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#pragma pack(push, 4)
typedef struct {
    mach_msg_header_t Head;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t NDR;
    exception_type_t exception;
    mach_msg_type_number_t codeCnt;
    int64_t code[2];
    int flavor;
    mach_msg_type_number_t old_stateCnt;
    natural_t old_state[1296];
    char trailer[64];
} req_t;
typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
    int flavor;
    mach_msg_type_number_t new_stateCnt;
    natural_t new_state[1296];
} rep_t;
#pragma pack(pop)

static mach_port_t exc_port;
static const char *mode;
static volatile int n_tag, n_step, n_other;
static uint32_t *jit;
static uintptr_t watch_addr;
static unsigned watch_tag = 9, orig_tag = 0;

static kern_return_t set_ss(thread_t th, int on) {
    arm_debug_state64_t ds;
    mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
    kern_return_t kr = thread_get_state(th, ARM_DEBUG_STATE64, (thread_state_t)&ds, &cnt);
    if (kr) return kr;
    if (on) ds.__mdscr_el1 |= 1; else ds.__mdscr_el1 &= ~1ULL;
    return thread_set_state(th, ARM_DEBUG_STATE64, (thread_state_t)&ds, ARM_DEBUG_STATE64_COUNT);
}

static void set_tag(unsigned tag) {
    void *p = (void *)((watch_addr & 0x00ffffffffffffffULL) | ((uintptr_t)tag << 56));
    __arm_mte_set_tag(p);
}

static void *exc_thread(void *arg) {
    (void)arg;
    __asm__ volatile("msr TCO, #1");
    static req_t req;
    static rep_t rep;
    for (;;) {
        kern_return_t kr = mach_msg(&req.Head, MACH_RCV_MSG, 0, sizeof req, exc_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (kr) { fprintf(stderr, "rcv kr=%x\n", kr); break; }
        arm_thread_state64_t *ts = (arm_thread_state64_t *)req.old_state;
        kern_return_t ret = KERN_FAILURE;
        memset(&rep, 0, sizeof rep);
        memcpy(rep.new_state, req.old_state, req.old_stateCnt * 4);
        arm_thread_state64_t *ns = (arm_thread_state64_t *)rep.new_state;
        uint64_t pc = arm_thread_state64_get_pc(*ts);
        if (req.exception == EXC_BAD_ACCESS && req.code[0] == 0x106) {
            n_tag++;
            if (n_tag <= 2) fprintf(stderr, "  fault addr=%llx pc=%llx cpsr=%x flavor=%d cnt=%d id=%d\n", req.code[1], pc, ts->__cpsr, req.flavor, req.old_stateCnt, req.Head.msgh_id);
            if (!strcmp(mode, "tco-state")) {
                ns->__cpsr |= (1u << 25);
                set_ss(req.thread.name, 1);
            } else if (!strcmp(mode, "tramp")) {
                uint32_t insn = *(uint32_t *)pc;
                pthread_jit_write_protect_np(0);
                jit[0] = 0xd503419f;            // msr TCO, #1
                jit[1] = insn;
                jit[2] = 0xd503409f;            // msr TCO, #0
                int64_t off = (int64_t)(pc + 4) - (int64_t)(uintptr_t)&jit[3];
                jit[3] = 0x14000000 | ((uint32_t)(off >> 2) & 0x03ffffff);
                pthread_jit_write_protect_np(1);
                sys_icache_invalidate(jit, 16);
                if (n_tag <= 2) fprintf(stderr, "  tramp at %p off=%lld insn=%08x\n", (void *)jit, off, insn);
                arm_thread_state64_set_pc_fptr(*ns, (void *)jit);
            } else {
                set_tag(orig_tag);
                set_ss(req.thread.name, 1);
            }
            ret = KERN_SUCCESS;
        } else if (req.exception == EXC_BREAKPOINT) {
            n_step++;
            if (n_step <= 2) fprintf(stderr, "  step pc=%llx cpsr=%x\n", pc, ts->__cpsr);
            set_ss(req.thread.name, 0);
            if (!strcmp(mode, "tco-state")) ns->__cpsr &= ~(1u << 25);
            else set_tag(watch_tag);
            ret = KERN_SUCCESS;
        } else {
            n_other++;
            fprintf(stderr, "  other exc %d code %llx %llx pc=%llx\n", req.exception, req.code[0], req.code[1], pc);
        }
        rep.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req.Head.msgh_bits), 0);
        rep.Head.msgh_remote_port = req.Head.msgh_remote_port;
        rep.Head.msgh_id = req.Head.msgh_id + 100;
        rep.NDR = NDR_record;
        rep.RetCode = ret;
        rep.flavor = req.flavor;
        rep.new_stateCnt = req.old_stateCnt;
        rep.Head.msgh_size = (mach_msg_size_t)(sizeof(mach_msg_header_t) + sizeof(NDR_record_t) + 12 + rep.new_stateCnt * 4);
        if (ret != KERN_SUCCESS) rep.Head.msgh_size = sizeof(mach_msg_header_t) + sizeof(NDR_record_t) + 4, rep.Head.msgh_size = (mach_msg_size_t)(sizeof(mach_msg_header_t) + sizeof(NDR_record_t) + 12);
        kr = mach_msg(&rep.Head, MACH_SEND_MSG, rep.Head.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (kr) fprintf(stderr, "send kr=%x\n", kr);
        mach_port_deallocate(mach_task_self(), req.thread.name);
        mach_port_deallocate(mach_task_self(), req.task.name);
    }
    return 0;
}

static int child(int n) {
    int r = ptrace(PT_TRACE_ME, 0, 0, 0);
    printf("  PT_TRACE_ME=%d\n", r);
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exc_port);
    mach_port_insert_right(mach_task_self(), exc_port, exc_port, MACH_MSG_TYPE_MAKE_SEND);
    kern_return_t k2 = task_set_exception_ports(mach_task_self(), EXC_MASK_BAD_ACCESS | EXC_MASK_BREAKPOINT, exc_port,
                                                EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
    printf("  set_exception_ports kr=%d\n", k2);
    jit = mmap(0, 16384, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_JIT | MAP_ANON | MAP_PRIVATE, -1, 0);
    printf("  MAP_JIT mmap = %p errno=%d\n", (void *)jit, jit == MAP_FAILED ? errno : 0);
    pthread_t t;
    pthread_create(&t, 0, exc_thread, 0);
    mach_vm_address_t addr = 0;
    kern_return_t kr = mach_vm_map(mach_task_self(), &addr, 1 << 14, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE, MACH_PORT_NULL, 0, FALSE,
                                   VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_DEFAULT);
    if (kr) { printf("  vm_map kr=%d\n", kr); return 3; }
    volatile uint64_t *data = (volatile uint64_t *)addr;
    data[0] = 0;
    watch_addr = addr;
    set_tag(watch_tag);
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (int i = 0; i < n; i++) data[0] = data[0] + 1;
    clock_gettime(CLOCK_MONOTONIC, &b);
    double us = ((b.tv_sec - a.tv_sec) * 1e9 + (b.tv_nsec - a.tv_nsec)) / 1e3;
    uint64_t tco = 0;
    __asm__ volatile("mrs %0, TCO" : "=r"(tco));
    set_tag(orig_tag);
    printf("  RESULT mode=%s value=%llu (expect %d) tagfaults=%d steps=%d other=%d  %.2f us/trap  final TCO=%llx\n", mode,
           (unsigned long long)data[0], n, n_tag, n_step, n_other, n_tag ? us / n_tag : 0.0, (unsigned long long)tco);
    return 0;
}

int main(int argc, char **argv) {
    mode = argc > 1 ? argv[1] : "tco-state";
    int n = argc > 2 ? atoi(argv[2]) : 1000;
    setvbuf(stdout, 0, _IOLBF, 0);
    pid_t pid = fork();
    if (pid == 0) _exit(child(n));
    time_t deadline = time(0) + 20;
    for (;;) {
        int st = 0;
        pid_t r = waitpid(pid, &st, WNOHANG | WUNTRACED);
        if (r == pid) {
            if (WIFSIGNALED(st)) { printf("child KILLED sig %d\n", WTERMSIG(st)); break; }
            if (WIFEXITED(st)) { printf("child exit %d\n", WEXITSTATUS(st)); break; }
            if (WIFSTOPPED(st)) { printf("child STOPPED sig %d -> kill\n", WSTOPSIG(st)); kill(pid, SIGKILL); continue; }
        }
        if (time(0) > deadline) { printf("timeout\n"); kill(pid, SIGKILL); deadline += 1000; }
        usleep(5000);
    }
    return 0;
}

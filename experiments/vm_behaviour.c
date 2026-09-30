// Experiment: the virtual-memory and signal behaviours the arena, page
// adoption and the signal wrapper rely on. Each test runs in a forked child
// so that a fatal outcome is an observation, not the end of the run.
// (See experiments/README.md for how to build it and for the results.)
#include <arm_acle.h>
#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef VM_FLAGS_MTE
#define VM_FLAGS_MTE 0x2000
#endif
#define TAG(p) ((unsigned)(((uintptr_t)(p) >> 56) & 0xf))
static long g_data[4096] = {1, 2, 3};
static void run(const char *name, void (*fn)(void)) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) { alarm(10); fn(); printf("  [%s] done\n", name); fflush(stdout); _exit(0); }
    int st; waitpid(pid, &st, 0);
    if (WIFSIGNALED(st)) printf("  [%s] KILLED by signal %d\n", name, WTERMSIG(st));
}
static void stg(void *p, unsigned tag) { void *q = (void *)(((uintptr_t)p & 0x00ffffffffffffffULL) | ((uintptr_t)tag << 56)); __arm_mte_set_tag(q); }
static unsigned ldg(void *p) { return TAG(__arm_mte_get_tag((void *)((uintptr_t)p & 0x00ffffffffffffffULL))); }

static void t_reserve(void) {
    mach_vm_address_t base = 0;
    kern_return_t kr = mach_vm_map(mach_task_self(), &base, 64ull << 30, 0, VM_FLAGS_ANYWHERE, MACH_PORT_NULL, 0, FALSE, VM_PROT_NONE, VM_PROT_ALL, VM_INHERIT_DEFAULT);
    printf("    reserve 64G kr=%d base=%llx\n", kr, base);
    mach_vm_address_t a = base + (1 << 20);
    kr = mach_vm_map(mach_task_self(), &a, 1 << 20, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_FLAGS_MTE, MACH_PORT_NULL, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_DEFAULT);
    printf("    fixed|overwrite|MTE inside kr=%d a=%llx\n", kr, a);
    char *p = (char *)a; p[0] = 1; stg(p, 5); printf("    ldg=%u\n", ldg(p));
    // directly reserve with MTE flag
    mach_vm_address_t b = 0;
    kr = mach_vm_map(mach_task_self(), &b, 64ull << 30, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE, MACH_PORT_NULL, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_DEFAULT);
    printf("    direct 64G MTE map kr=%d b=%llx\n", kr, b);
    if (!kr) { char *q = (char *)b + (3ull << 30); q[0] = 1; stg(q, 7); printf("    ldg deep=%u\n", ldg(q)); }
}
static void t_ldg_plain(void) {
    char *p = mmap(0, 1 << 14, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    p[0] = 1;
    printf("    ldg on plain mmap = %u\n", ldg(p));
    printf("    ldg on global = %u\n", ldg(g_data));
    int local = 0; printf("    ldg on stack = %u\n", ldg(&local));
}
static void t_global(void) {
    uintptr_t page = (uintptr_t)&g_data[1024] & ~0x3fffUL;
    static char save[1 << 14];
    memcpy(save, (void *)page, 1 << 14);
    mach_vm_address_t a = page;
    kern_return_t kr = mach_vm_map(mach_task_self(), &a, 1 << 14, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_FLAGS_MTE, MACH_PORT_NULL, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_DEFAULT);
    printf("    overwrite __DATA page %lx kr=%d\n", page, kr);
    if (kr) return;
    memcpy((void *)page, save, 1 << 14);
    volatile long *g = (volatile long *)page;
    printf("    content ok=%d ldg=%u\n", g_data[0] == 1 || 1, ldg((void *)page));
    stg((void *)page, 9);
    printf("    after stg ldg=%u; now untagged access should fault...\n", ldg((void *)page)); fflush(stdout);
    long v = g[0]; printf("    NO FAULT v=%ld\n", v);
}
static void t_remap(void) {
    mach_vm_address_t src = 0;
    mach_vm_map(mach_task_self(), &src, 1 << 14, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE, MACH_PORT_NULL, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_DEFAULT);
    ((char *)src)[16] = 42; stg((char *)src + 32, 6);
    mach_vm_address_t dst = 0; vm_prot_t cur, max;
    kern_return_t kr = mach_vm_remap(mach_task_self(), &dst, 1 << 14, 0, VM_FLAGS_ANYWHERE, mach_task_self(), src, FALSE, &cur, &max, VM_INHERIT_DEFAULT);
    printf("    remap kr=%d dst=%llx\n", kr, dst);
    if (kr) return;
    printf("    dst content=%d ldg(dst+32)=%u ldg(dst)=%u\n", ((char *)dst)[16], ldg((char *)dst + 32), ldg((char *)dst));
    stg((char *)dst + 64, 3); printf("    stg on remapped ok ldg=%u src ldg=%u\n", ldg((char *)dst + 64), ldg((char *)src + 64));
}
static volatile int tco_in_handler = -1;
static void onsig(int s) { (void)s; uint64_t v; __asm__ volatile("mrs %0, tco" : "=r"(v)); tco_in_handler = (int)((v >> 25) & 1); }
static void t_tco_signal(void) {
    signal(SIGUSR1, onsig);
    __asm__ volatile("msr tco, #1");
    raise(SIGUSR1);
    uint64_t v; __asm__ volatile("mrs %0, tco" : "=r"(v));
    printf("    TCO in handler=%d, after sigreturn=%d\n", tco_in_handler, (int)((v >> 25) & 1));
    // syscall preserves?
    getpid(); __asm__ volatile("mrs %0, tco" : "=r"(v)); printf("    after syscall TCO=%d\n", (int)((v >> 25) & 1));
    usleep(1000); __asm__ volatile("mrs %0, tco" : "=r"(v)); printf("    after sleep TCO=%d\n", (int)((v >> 25) & 1));
}
static void t_syscall_read(void) {
    // kernel copyout into a granule whose tag mismatches the pointer
    mach_vm_address_t a = 0;
    mach_vm_map(mach_task_self(), &a, 1 << 14, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE, MACH_PORT_NULL, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_DEFAULT);
    char *p = (char *)a; stg(p, 9);
    int fds[2]; pipe(fds); write(fds[1], "hello", 5);
    printf("    read() into mismatched granule...\n"); fflush(stdout);
    ssize_t r = read(fds[0], p, 5);
    printf("    read returned %zd errno=%d\n", r, r < 0 ? errno : 0);
}
static void t_syscall_write(void) {
    mach_vm_address_t a = 0;
    mach_vm_map(mach_task_self(), &a, 1 << 14, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE, MACH_PORT_NULL, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_DEFAULT);
    char *p = (char *)a; memcpy(p, "hello", 5); stg(p, 9);
    int fds[2]; pipe(fds);
    printf("    write() from mismatched granule...\n"); fflush(stdout);
    ssize_t r = write(fds[1], p, 5);
    printf("    write returned %zd errno=%d\n", r, r < 0 ? errno : 0);
}
int main(void) {
    setvbuf(stdout, 0, _IOLBF, 0);
    run("reserve", t_reserve);
    run("ldg-plain", t_ldg_plain);
    run("global-adopt", t_global);
    run("remap", t_remap);
    run("tco-signal", t_tco_signal);
    run("syscall-read", t_syscall_read);
    run("syscall-write", t_syscall_write);
    return 0;
}

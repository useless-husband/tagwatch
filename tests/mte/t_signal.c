// Signals. The process is ptrace-traced, so every signal goes through the
// supervisor; handlers must still run, may touch watched memory, and must
// not cause accesses to be missed even when they interrupt an execution slot.
#include "mt.h"

#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/wait.h>

static uint64_t *obj; // [0]: bumped by the main loop, [1]: bumped by the handler
static _Atomic int handler_runs;
static _Atomic uint64_t handler_tid;

static void bump(uint64_t *p) {
    uint64_t one = 1, old;
    __asm__ volatile("ldaddal %1, %0, [%2]" : "=&r"(old) : "r"(one), "r"(p) : "memory");
}

static void on_usr1(int sig) {
    (void)sig;
    bump(obj + 1);
    atomic_fetch_add(&handler_runs, 1);
    handler_tid = mt_tid();
}

static void on_alarm(int sig, siginfo_t *si, void *uc) {
    (void)sig, (void)si, (void)uc;
    bump(obj + 1);
    atomic_fetch_add(&handler_runs, 1);
}

int main(void) {
    mt_start("signal");
    obj = tagwatch_alloc_watched(16, "counters");

    // A handler that touches watched memory.
    sig_t prev = signal(SIGUSR1, on_usr1);
    CHECK(prev == SIG_DFL);
    raise(SIGUSR1);
    CHECK_EQ(atomic_load(&handler_runs), 1);
    CHECK_EQ(mt_count(), 1);
    CHECK(mt_last()->offset == 8 && mt_last()->access == TAGWATCH_RW);
    CHECK(handler_tid == mt_tid());
    kill(getpid(), SIGUSR1);
    while (atomic_load(&handler_runs) < 2) usleep(100);
    CHECK_EQ(mt_count(), 2);

    // The program sees its own handler when it asks, not tagwatch's wrapper.
    struct sigaction cur;
    CHECK(sigaction(SIGUSR1, NULL, &cur) == 0);
    CHECK(cur.sa_handler == on_usr1 && !(cur.sa_flags & SA_SIGINFO));
    CHECK(signal(SIGUSR1, SIG_IGN) == on_usr1);
    raise(SIGUSR1);
    CHECK_EQ(atomic_load(&handler_runs), 2);
    CHECK(signal(SIGUSR1, SIG_DFL) == SIG_IGN);

    // A timer firing every 200 us while the main loop traps continuously:
    // signals keep landing on a thread that is in the middle of handling a
    // watchpoint. Every access, in the loop and in the handler, is reported.
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_alarm;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    CHECK(sigaction(SIGALRM, &sa, NULL) == 0);
    CHECK(sigaction(SIGALRM, NULL, &cur) == 0 && cur.sa_sigaction == on_alarm && (cur.sa_flags & SA_SIGINFO));
    mt_reset();
    atomic_store(&handler_runs, 0);
    struct itimerval it = {{0, 200}, {0, 200}};
    setitimer(ITIMER_REAL, &it, NULL);
    enum { LOOPS = 20000 };
    for (int i = 0; i < LOOPS; i++) bump(obj);
    memset(&it, 0, sizeof it);
    setitimer(ITIMER_REAL, &it, NULL);
    int runs = atomic_load(&handler_runs);
    uint64_t vals[2];
    tagwatch_peek(vals, obj, 16);
    CHECK_EQ(vals[0], LOOPS);
    CHECK_EQ(vals[1], 2 + runs);
    CHECK(runs > 10);
    CHECK_EQ(mt_count(), LOOPS + runs);
    printf("     (%d timer signals delivered during %d traps; all %d accesses reported)\n", runs, LOOPS, mt_count());

    // Being traced makes blocking calls return EINTR whenever any signal
    // stops the process, even an ignored one. The shims hide exactly that
    // case: a child's exit (SIGCHLD, ignored by default) must not disturb a
    // blocked read(), while a real handler without SA_RESTART still must.
    int fds[2];
    CHECK(pipe(fds) == 0);
    pid_t pid = fork();
    if (pid == 0) {
        usleep(30000);
        _exit(0); // SIGCHLD arrives in the parent while it is blocked in read()
    }
    pid_t writer = fork();
    if (writer == 0) {
        usleep(120000);
        (void)!write(fds[1], "x", 1);
        _exit(0);
    }
    char ch = 0;
    errno = 0;
    CHECK(read(fds[0], &ch, 1) == 1 && ch == 'x');
    int status;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(waitpid(writer, &status, 0) == writer);

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1; // no SA_RESTART: read() is supposed to fail with EINTR
    CHECK(sigaction(SIGUSR1, &sa, NULL) == 0);
    pid = fork();
    if (pid == 0) {
        usleep(30000);
        kill(getppid(), SIGUSR1);
        _exit(0);
    }
    errno = 0;
    CHECK(read(fds[0], &ch, 1) == -1 && errno == EINTR);
    CHECK(waitpid(pid, &status, 0) == pid);

    tagwatch_stats st;
    tagwatch_get_stats(&st);
    CHECK_EQ(st.violations, 0);
    return mt_done();
}

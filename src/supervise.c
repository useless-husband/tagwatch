#include "supervise.h"

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <sys/event.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile pid_t forward_to;

// Signals aimed at the supervisor (kill <pid>) are passed on. Signals the
// terminal sends to the whole foreground group have si_pid == 0 and reach
// the child on their own.
static void forward(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    pid_t child = forward_to;
    if (child > 0 && si && si->si_pid != 0 && si->si_pid != child) kill(child, sig);
}

static int is_stop_signal(int sig) { return sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU; }

int tw_supervise(pid_t child, int *termsig) {
    static const int passed[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2};
    struct sigaction sa, old[sizeof passed / sizeof passed[0]];
    sa.sa_sigaction = forward;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    forward_to = child;
    for (size_t i = 0; i < sizeof passed / sizeof passed[0]; i++) sigaction(passed[i], &sa, &old[i]);

    // A traced process gets a SIGTRAP when it execs. That one is an artefact
    // of tracing and must not be delivered; a kqueue tells it apart from a
    // SIGTRAP the program raised itself.
    int kq = kqueue();
    if (kq >= 0) {
        struct kevent ke;
        EV_SET(&ke, child, EVFILT_PROC, EV_ADD | EV_CLEAR, NOTE_EXEC, 0, NULL);
        kevent(kq, &ke, 1, NULL, 0, NULL);
    }

    int status = 0, result = 255;
    if (termsig) *termsig = 0;
    for (;;) {
        pid_t r = waitpid(child, &status, WUNTRACED);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (WIFEXITED(status)) {
            result = WEXITSTATUS(status);
            break;
        }
        if (WIFSIGNALED(status)) {
            result = 128 + WTERMSIG(status);
            if (termsig) *termsig = WTERMSIG(status);
            break;
        }
        if (!WIFSTOPPED(status)) continue;
        int sig = WSTOPSIG(status);
        if (sig == SIGTRAP && kq >= 0) {
            struct kevent ev;
            struct timespec zero = {0, 0};
            if (kevent(kq, NULL, 0, &ev, 1, &zero) == 1 && (ev.fflags & NOTE_EXEC)) sig = 0;
        }
        if (is_stop_signal(sig)) {
            // Job control: stop alongside the child so the shell sees the job
            // stop, and let both continue when the shell resumes us.
            kill(getpid(), SIGSTOP);
            sig = 0;
        }
        if (ptrace(PT_CONTINUE, child, (caddr_t)1, sig) != 0 && errno == ESRCH) continue; // already gone; reap it
    }
    forward_to = 0;
    for (size_t i = 0; i < sizeof passed / sizeof passed[0]; i++) sigaction(passed[i], &old[i], NULL);
    if (kq >= 0) close(kq);
    return result;
}

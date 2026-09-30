// Target for the CLI tests of process-level behaviour: exit codes, fatal
// signals, exec, fork, signal forwarding, and the two fatal cases (a system
// call tagwatch does not shim, and a genuine MTE violation).
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t got;
static void on_signal(int sig) { got = sig; }

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    alarm(60);
    setvbuf(stdout, NULL, _IONBF, 0);
    volatile char *watched = malloc(4000); // the tests watch size=4000
    watched[0] = 1;

    if (!strcmp(mode, "exit3")) return 3;
    if (!strcmp(mode, "abort")) abort();
    if (!strcmp(mode, "hello")) {
        printf("hello from the exec'ed image (DYLD_INSERT_LIBRARIES=%s)\n", getenv("DYLD_INSERT_LIBRARIES") ? "set" : "unset");
        return 0;
    }
    if (!strcmp(mode, "exec")) {
        char *args[] = {argv[0], "hello", NULL};
        execv(argv[0], args);
        perror("execv");
        return 1;
    }
    if (!strcmp(mode, "fork")) {
        pid_t pid = fork();
        if (pid == 0) {
            watched[1] = 2; // the child must survive touching the parent's watched object
            _exit(watched[1] == 2 ? 7 : 1);
        }
        int st = 0;
        pid_t r = waitpid(pid, &st, 0);
        watched[2] = 3;
        printf("child %s with status %d\n", r == pid && WIFEXITED(st) ? "exited" : "did not exit cleanly", WEXITSTATUS(st));
        return 0;
    }
    if (!strcmp(mode, "system")) {
        int rc = system("echo from a shell started by the target");
        printf("system() returned %d\n", rc);
        return 0;
    }
    if (!strcmp(mode, "sigwait")) {
        signal(SIGINT, on_signal);
        signal(SIGTERM, on_signal);
        printf("ready\n");
        while (!got) usleep(1000);
        watched[3] = 4;
        printf("got signal %d\n", (int)got);
        return 0;
    }
    if (!strcmp(mode, "readv")) {
        // readv() is not one of the calls tagwatch redirects: the kernel
        // writes straight into the watched buffer.
        int fds[2];
        if (pipe(fds) != 0 || write(fds[1], "data", 4) != 4) return 1;
        struct iovec iov = {(void *)watched, 4};
        printf("calling readv() on a watched buffer\n");
        ssize_t n = readv(fds[0], &iov, 1);
        printf("readv returned %zd\n", n);
        return 0;
    }
    if (!strcmp(mode, "uaf")) {
        volatile char *p = malloc(64); // not watched
        p[0] = 1;
        free((void *)p);
        printf("reading freed memory\n");
        return p[0]; // a genuine use-after-free: MTE catches it, tagwatch reports it
    }
    return 0;
}

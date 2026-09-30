// trapcost: the cost of one tagwatch trap, measured from the accessing
// thread's point of view (time per trapped access in a tight loop).
//   usage: trapcost <mode> [accesses]
//   modes: count   callback only, nothing formatted or written
//          trace   full JSON-lines record with a 16-frame backtrace to a file
//          log     human-readable record to a file as well
// Run with TAGWATCH_FORCE_FAR=1 to measure the two-exception return path.
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "tagwatch.h"

static uint64_t seen;
static int count_only(const tagwatch_event *ev, void *ctx) {
    (void)ev, (void)ctx;
    seen++;
    return 1;
}

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

__attribute__((noinline)) static uint64_t loop(volatile uint64_t *p, int n) {
    uint64_t sum = 0;
    for (int i = 0; i < n; i++) {
        p[0] = (uint64_t)i; // one trapped store
        sum += p[1];        // one trapped load
    }
    return sum;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "count";
    int n = argc > 2 ? atoi(argv[2]) : 20000;
    alarm(300);
    int rc = tagwatch_init();
    if (rc != 0) {
        printf("trapcost: skipped (%s)\n", tagwatch_strerror(rc));
        return 77;
    }
    char trace[] = "/tmp/tagwatch-trapcost.XXXXXX";
    int fd = mkstemp(trace);
    int log_fd = -1;
    if (!strcmp(mode, "count")) {
        tagwatch_set_callback(count_only, NULL);
        tagwatch_set_output(-1, NULL);
    } else if (!strcmp(mode, "trace")) {
        tagwatch_set_output(-1, trace);
    } else {
        log_fd = open("/dev/null", O_WRONLY);
        tagwatch_set_output(log_fd, trace);
    }
    volatile uint64_t *plain = malloc(64);
    double t0 = now_us();
    loop(plain, n);
    double t_plain = now_us() - t0;

    volatile uint64_t *p = tagwatch_alloc_watched(64, "bench");
    loop(p, 200); // create the execution slots, warm the caches
    tagwatch_stats s0, s1;
    tagwatch_get_stats(&s0);
    t0 = now_us();
    loop(p, n);
    double t_watch = now_us() - t0;
    tagwatch_get_stats(&s1);
    uint64_t traps = s1.traps - s0.traps;
    printf("trapcost mode=%s path=%s traps=%llu us_per_trap=%.2f unwatched_ns_per_access=%.2f\n", mode,
           s1.far_traps ? "far(2 exceptions)" : "near(1 exception)", (unsigned long long)traps, t_watch / (double)traps,
           t_plain * 1000.0 / (2.0 * n));
    close(fd);
    unlink(trace);
    return traps == (uint64_t)(2 * n) ? 0 : 1;
}

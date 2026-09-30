// fork(): watches do not follow the child. It has no handler thread and no
// tracer, so a trap there would kill it; every granule gets its original tag
// back before the child runs.
#include "mt.h"

#include <sys/wait.h>
#include <time.h>

static uint8_t *churn_obj;
static _Atomic int churn_stop;
static void *churn(void *arg) {
    (void)arg;
    while (!atomic_load(&churn_stop)) {
        tagwatch_id id = tagwatch_watch(churn_obj, 4096, "churn");
        if (id > 0) tagwatch_unwatch(id);
    }
    return NULL;
}

int main(void) {
    mt_start("fork");
    uint64_t *obj = tagwatch_alloc_watched(64, "shared");
    char *heap = malloc(48);
    CHECK(tagwatch_watch(heap, 48, "heap") > 0);
    store64(obj, 1);
    CHECK_EQ(mt_count(), 1);

    pid_t pid = fork();
    if (pid == 0) {
        // The child can use both objects freely and allocate/free normally.
        int ok = !tagwatch_available();
        store64(obj, 2);
        ok &= load64(obj) == 2;
        store8(heap, 9);
        ok &= load8(heap) == 9;
        ok &= tagwatch_watch(obj, 8, "again") == -TAGWATCH_ENOTSUP;
        char *x = malloc(100);
        store8(x, 1);
        free(x);
        free(heap);
        free(obj);
        _exit(ok ? 42 : 1);
    }
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status));
    CHECK_EQ(WEXITSTATUS(status), 42);

    // The parent is unaffected: same memory contents, watches still armed.
    CHECK_EQ(mt_count(), 1);
    CHECK(load64(obj) == 1);
    CHECK_EQ(mt_count(), 2);
    store8(heap, 3);
    CHECK_EQ(mt_count(), 3);

    // Several children in a row, while another thread keeps trapping.
    for (int i = 0; i < 5; i++) {
        pid = fork();
        if (pid == 0) {
            store64(obj + 1, (uint64_t)i);
            _exit(load64(obj + 1) == (uint64_t)i ? 0 : 1);
        }
        CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    // fork() while another thread is arming and disarming watches: whatever
    // instant the fork lands on, the child must find no granule still tagged.
    // (The parent holds the watch lock across the fork for that; libSystem's
    // own fork handlers call free() in the child before tagwatch's handler
    // runs, which the interposers must survive.)
    churn_obj = tagwatch_alloc(4096);
    pthread_t th;
    pthread_create(&th, NULL, churn, NULL);
    int bad = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < 300; i++) {
        pid = fork();
        if (pid == 0) {
            uint64_t sum = 0;
            for (int k = 0; k < 4096; k += 16) sum += load8(churn_obj + k); // dies here if a tag was left behind
            _exit(sum == 0 ? 0 : 1);
        }
        if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) bad++;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    atomic_store(&churn_stop, 1);
    pthread_join(th, NULL);
    CHECK_EQ(bad, 0);
    // fork() copies the tag storage of every MTE mapping, touched or not, at
    // about 8 ms per GB; the arena is mapped in 256 MB steps so that a fork
    // costs a few milliseconds, not the half second a 64 GB reservation did.
    double per_fork_ms = ((double)(t1.tv_sec - t0.tv_sec) * 1e3 + (double)(t1.tv_nsec - t0.tv_nsec) / 1e6) / 300;
    printf("     (300 forks under churn: %.1f ms each)\n", per_fork_ms);
    CHECK(per_fork_ms < 100);

    tagwatch_stats st;
    tagwatch_get_stats(&st);
    CHECK_EQ(st.violations, 0);
    CHECK_EQ(st.watches_live, 2);
    return mt_done();
}

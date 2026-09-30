// fork(): watches do not follow the child. It has no handler thread and no
// tracer, so a trap there would kill it; every granule gets its original tag
// back before the child runs.
#include "mt.h"

#include <sys/wait.h>

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
    tagwatch_stats st;
    tagwatch_get_stats(&st);
    CHECK_EQ(st.violations, 0);
    CHECK_EQ(st.watches_live, 2);
    return mt_done();
}

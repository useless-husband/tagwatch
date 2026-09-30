// The slow return path. When no execution slot can be placed within branch
// range of the faulting code, the slot ends in a breakpoint and the handler
// finishes the return (two exceptions per access instead of one).
// TAGWATCH_FORCE_FAR=1 makes every slot take that path so it is tested
// regardless of where the system libraries happen to be mapped.
#include "mt.h"

static void *hammer(void *arg) {
    uint64_t *p = arg;
    for (int i = 0; i < 2000; i++) {
        uint64_t one = 1, old;
        __asm__ volatile("ldaddal %1, %0, [%2]" : "=&r"(old) : "r"(one), "r"(p) : "memory");
    }
    return NULL;
}

int main(void) {
    setenv("TAGWATCH_FORCE_FAR", "1", 1);
    mt_start("far");
    uint64_t *p = tagwatch_alloc_watched(64, "far");
    store64(p + 1, 5);
    CHECK(load64(p + 1) == 5);
    uint64_t base = (uint64_t)(uintptr_t)p, v = 0;
    __asm__ volatile("ldr %0, [%1, #8]!" : "=&r"(v), "+r"(base) : : "memory");
    CHECK(v == 5 && base == (uint64_t)(uintptr_t)p + 8);
    char copy[64];
    memcpy(copy, p, 64);
    memset(p, 0, 64);
    CHECK(mt_count() >= 5);
    tagwatch_stats st;
    tagwatch_get_stats(&st);
    CHECK(st.far_traps == st.traps && st.traps > 0);

    // Concurrency on the slow path: exact counts again.
    mt_reset();
    pthread_t th[4];
    for (int i = 0; i < 4; i++) pthread_create(&th[i], NULL, hammer, p);
    for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
    CHECK_EQ(mt_count(), 8000);
    tagwatch_peek(&v, p, 8);
    CHECK_EQ(v, 8000);
    tagwatch_get_stats(&st);
    CHECK(st.far_traps == st.traps);
    CHECK_EQ(st.violations, 0);
    return mt_done();
}

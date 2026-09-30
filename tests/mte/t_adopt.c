// Memory that is not in an MTE mapping: globals, another thread's stack, and
// what cannot be adopted (code, this thread's own stack).
#include "mt.h"

#include <dispatch/dispatch.h>

static long g_table[8] = {10, 11, 12, 13, 14, 15, 16, 17};
static long g_neighbour = 99;
static char g_bss[40000]; // spans several pages
static const char g_text_const[] = "read-only data in __TEXT";

static dispatch_semaphore_t ready, go_on;
static volatile char *worker_buf;
static _Atomic int worker_done;

__attribute__((noinline)) static void through_pointer(volatile char *p) { p[3] = 1; }

// Stores to [sp, #off]: the one addressing form MTE never checks.
__attribute__((noinline)) static int store_sp_relative(const volatile char *buf) {
    uintptr_t sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    uintptr_t off = (uintptr_t)buf - sp;
    uint32_t one = 1;
    switch (off) {
#define CASE(n)                                                                   \
    case n:                                                                       \
        __asm__ volatile("strb %w0, [sp, #" #n "]" : : "r"(one) : "memory");     \
        return 1;
        CASE(0) CASE(16) CASE(32) CASE(48) CASE(64) CASE(80) CASE(96) CASE(112) CASE(128) CASE(144) CASE(160) CASE(176)
        CASE(192) CASE(208) CASE(224) CASE(240) CASE(256) CASE(272) CASE(288) CASE(304) CASE(320) CASE(336) CASE(352)
        CASE(368) CASE(384) CASE(400) CASE(416) CASE(432) CASE(448) CASE(464) CASE(480) CASE(496)
#undef CASE
    default: return 0;
    }
}

static void *worker(void *arg) {
    (void)arg;
    volatile char buf[64] __attribute__((aligned(16)));
    buf[0] = 0;
    worker_buf = buf;
    dispatch_semaphore_signal(ready);
    dispatch_semaphore_wait(go_on, DISPATCH_TIME_FOREVER); // main adopts and watches buf meanwhile
    through_pointer(buf);
    int n1 = mt_count();
    int did = store_sp_relative(buf);
    int n2 = mt_count();
    // A pointer access is reported; the sp-relative store is not.
    atomic_store(&worker_done, 1 + (n1 == 1) + 2 * (did && n2 == n1) + 4 * (buf[3] == 1 && (!did || buf[0] == 1)));
    return NULL;
}

int main(void) {
    mt_start("adopt");

    // --- a global ---------------------------------------------------------------
    CHECK(tagwatch_watch(&g_table[2], 8, "g_table[2]") == -TAGWATCH_ENOTTAGGED);
    CHECK(tagwatch_adopt(g_table, sizeof g_table) == 0);
    for (int i = 0; i < 8; i++) CHECK(g_table[i] == 10 + i); // contents survived the page swap
    CHECK(g_neighbour == 99);
    CHECK(tagwatch_adopt(g_table, sizeof g_table) == 0); // already taggable: nothing to do
    CHECK(tagwatch_watch(&g_table[2], 8, "g_table[2]") > 0);
    store64(&g_table[2], 1000);
    CHECK_EQ(mt_count(), 1);
    CHECK(mt_last()->offset == 0 && mt_last()->access == TAGWATCH_WRITE);
    store64(&g_table[3], 1); // other half of the same granule: trapped, filtered
    store64(&g_table[4], 1); // next granule: not even trapped
    CHECK_EQ(mt_count(), 1);
    CHECK(load64(&g_table[2]) == 1000);
    CHECK_EQ(mt_count(), 2);

    // A range spanning several pages, one of which is already adopted.
    memset(g_bss, 7, sizeof g_bss);
    CHECK(tagwatch_adopt(g_bss, sizeof g_bss) == 0);
    int intact = 1;
    for (size_t i = 0; i < sizeof g_bss; i++) intact &= g_bss[i] == 7;
    CHECK(intact);
    mt_reset();
    CHECK(tagwatch_watch(g_bss + 20000, 16384, "bss page") > 0);
    store8(g_bss + 20000 + 16383, 1);
    store8(g_bss + 19999, 1);
    CHECK_EQ(mt_count(), 1);

    // --- what cannot be adopted -----------------------------------------------------
    CHECK(tagwatch_adopt((void *)(uintptr_t)g_text_const, sizeof g_text_const) == -TAGWATCH_ENOTTAGGED); // code pages
    long local = 5;
    CHECK(tagwatch_adopt(&local, sizeof local) == -TAGWATCH_ENOTTAGGED); // the calling thread's own stack
    CHECK(local == 5);
    CHECK(tagwatch_adopt((void *)0x10, 8) == -TAGWATCH_EINVAL); // unmapped
    CHECK(tagwatch_adopt(NULL, 8) == -TAGWATCH_EINVAL);

    // --- another thread's stack ----------------------------------------------------------
    mt_reset();
    ready = dispatch_semaphore_create(0);
    go_on = dispatch_semaphore_create(0);
    pthread_t th;
    pthread_create(&th, NULL, worker, NULL);
    dispatch_semaphore_wait(ready, DISPATCH_TIME_FOREVER);
    CHECK(tagwatch_adopt((void *)worker_buf, 64) == 0);
    CHECK(tagwatch_watch((void *)worker_buf, 64, "stack buffer") > 0);
    dispatch_semaphore_signal(go_on);
    pthread_join(th, NULL);
    int r = atomic_load(&worker_done) - 1;
    CHECK(r & 1); // access through a pointer: reported
    CHECK(r & 4); // both stores took effect
    printf("     (sp-relative store to a watched stack slot: %s)\n",
           (r & 2) ? "not reported, as MTE never checks [sp, #imm] accesses" : "could not be placed at an sp offset; not exercised");
    CHECK(r & 2);

    tagwatch_stats st;
    tagwatch_get_stats(&st);
    CHECK_EQ(st.violations, 0);
    return mt_done();
}

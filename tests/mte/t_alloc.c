// The arena, allocation matching through the malloc interposers, the
// use-after-free quarantine, and free/realloc of watched objects.
// (Accesses go through store8/load8: the optimiser deletes plain stores to
// memory that is freed without being read, and whole malloc/free pairs.)
#include "mt.h"

#include <malloc/malloc.h>

__attribute__((noinline)) static void *make_thing(size_t n) {
    void *p = malloc(n);
    __asm__ volatile(""); // keep this a real call frame
    return p;
}
__attribute__((noinline)) static void *make_other(size_t n) {
    void *p = malloc(n);
    __asm__ volatile("");
    return p;
}

int main(void) {
    // Library-mode configuration comes from the environment, read by tagwatch_init().
    setenv("TAGWATCH_WATCH",
           "alloc:size=777;alloc:size=600..700,caller=make_thing,label=thing;alloc:size=5000,every=3,skip=1,limit=2;"
           "alloc:size=333,off=24,len=8,label=field",
           1);
    setenv("TAGWATCH_QUARANTINE", "4096", 1);
    mt_start("alloc");
    tagwatch_stats st;

    // --- arena blocks of any size are taggable -------------------------------------
    static const size_t sizes[] = {1, 15, 16, 17, 48, 1000, 4096, 100000, 5u << 20, 70u << 20};
    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        mt_reset();
        uint8_t *p = tagwatch_alloc_watched(sizes[i], "sized");
        CHECK(p != NULL && ((uintptr_t)p & 15) == 0);
        CHECK(malloc_size(p) >= sizes[i]);
        CHECK(load8(p) == 0); // handed out zeroed
        store8(p + sizes[i] - 1, 0x5a); // last byte
        CHECK_EQ(mt_count(), 2);
        CHECK(mt_last()->offset == (int64_t)sizes[i] - 1 && mt_last()->watch_len == sizes[i]);
        free(p);
    }

    // --- allocations matched by size ---------------------------------------------------
    mt_reset();
    char *a = malloc(777);
    CHECK(a != NULL);
    store8(a, 1);
    CHECK_EQ(mt_count(), 1);
    char *b = malloc(776); // not matched
    store8(b, 1);
    CHECK_EQ(mt_count(), 1);
    char *c = calloc(7, 111); // 777 bytes through calloc
    store8(c + 776, 1);
    CHECK_EQ(mt_count(), 2);
    free(b);
    free(c);

    // realloc into a watched size keeps the contents and starts reporting...
    char *r = malloc(100);
    memset(r, 0x33, 100);
    r = realloc(r, 777);
    mt_reset();
    CHECK(load8(r + 99) == 0x33);
    CHECK_EQ(mt_count(), 1);
    // ...and realloc out of it stops, again keeping the contents.
    store8(r + 700, 0x44);
    r = realloc(r, 2000);
    mt_reset();
    CHECK(load8(r + 99) == 0x33 && load8(r + 700) == 0x44);
    CHECK_EQ(mt_count(), 0);
    free(r);

    // --- allocations matched by call site --------------------------------------------------
    mt_reset();
    char *t1 = make_thing(650), *t2 = make_other(650), *t3 = make_thing(800);
    store8(t1 + 1, 1);
    CHECK_EQ(mt_count(), 1);
    CHECK(!strcmp(mt_last()->label, "thing"));
    store8(t2 + 1, 1);
    store8(t3 + 1, 1);
    CHECK_EQ(mt_count(), 1);
    free(t2);
    free(t3);

    // --- sampling: skip=1, every=3, limit=2 watches the 2nd and 5th of eight ----------------
    mt_reset();
    char *s[8];
    int watched_idx[8], n_watched = 0;
    for (int i = 0; i < 8; i++) {
        s[i] = malloc(5000);
        int before = mt_count();
        store8(s[i], 1);
        if (mt_count() > before) watched_idx[n_watched++] = i;
    }
    CHECK_EQ(n_watched, 2);
    CHECK(watched_idx[0] == 1 && watched_idx[1] == 4);
    for (int i = 0; i < 8; i++) free(s[i]);

    // --- one field of every matching object (off=24,len=8) ---------------------------------
    mt_reset();
    char *obj = malloc(333);
    store8(obj + 23, 1); // the byte before the field: different granule half, not reported
    store8(obj + 32, 1); // the byte after
    CHECK_EQ(mt_count(), 0);
    store8(obj + 24, 1);
    store8(obj + 31, 1);
    CHECK_EQ(mt_count(), 2);
    CHECK(mt_last()->offset == 7 && mt_last()->watch_len == 8 && !strcmp(mt_last()->label, "field"));
    free(obj); // freed while only an interior range is watched
    (void)load8(obj + 24);
    CHECK_EQ(mt_count(), 3);
    CHECK(mt_last()->flags & TAGWATCH_EV_FREED);
    // The same for a system-heap block with an interior watch set through the API.
    char *sysblk = malloc(64);
    CHECK(tagwatch_watch(sysblk + 40, 4, "interior") > 0);
    free(sysblk);
    tagwatch_get_stats(&st);
    uint64_t live_before = st.watches_live;
    sysblk = malloc(64); // may well be the same block again: it must not still be armed
    mt_reset();
    store8(sysblk + 40, 1);
    CHECK_EQ(mt_count(), 0);
    free(sysblk);
    tagwatch_get_stats(&st);
    CHECK(st.watches_live == live_before);

    // --- use after free -----------------------------------------------------------------------
    mt_reset();
    free(a);
    (void)load8(a); // the object is freed, but still armed in quarantine
    CHECK_EQ(mt_count(), 1);
    CHECK(mt_last()->flags & TAGWATCH_EV_FREED);
    free(a); // double free: reported as a note, not a crash
    free(t1);
    // Push enough freed objects through the 4 KB quarantine to evict `a`.
    for (int i = 0; i < 40; i++) {
        char *x = malloc(777);
        store8(x, 1);
        free(x);
    }
    mt_reset();
    (void)load8(a);
    CHECK_EQ(mt_count(), 0);

    tagwatch_get_stats(&st);
    CHECK_EQ(st.violations, 0);
    printf("     (%llu watches armed in total, %llu still live in quarantine)\n", (unsigned long long)st.watches_total,
           (unsigned long long)st.watches_live);
    return mt_done();
}

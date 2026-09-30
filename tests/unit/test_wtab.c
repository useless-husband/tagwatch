#include "../../src/wtab.h"
#include "t.h"

#include <errno.h>

// Counting allocator: lets the test assert that nothing leaks and inject
// allocation failures.
static long live_bytes, fail_after = -1;
static void *t_alloc(size_t n) {
    if (fail_after == 0) return NULL;
    if (fail_after > 0) fail_after--;
    live_bytes += (long)n;
    return calloc(1, n);
}
static void t_release(void *p, size_t n) {
    live_bytes -= (long)n;
    free(p);
}
static const tw_mem mem = {t_alloc, t_release};

// Reference model: one slot per granule over a small address window that
// straddles many page boundaries.
#define WINDOW_GRANULES 8192
static uint32_t model[WINDOW_GRANULES];
#define BASE 0x100ffc000ull

static void basic(void) {
    tw_wtab t;
    CHECK(tw_wtab_init(&t, &mem) == 0);
    CHECK(tw_wtab_get(&t, 0x1000, NULL) == 0);
    CHECK(tw_wtab_insert(&t, 0x1000, 48, 7) == 0);
    unsigned tag = 99;
    CHECK(tw_wtab_get(&t, 0x1000, &tag) == 7 && tag == 0);
    CHECK(tw_wtab_get(&t, 0x102f, NULL) == 7);
    CHECK(tw_wtab_get(&t, 0x1030, NULL) == 0);
    CHECK(tw_wtab_get(&t, 0xfff, NULL) == 0);
    tw_wtab_set_orig_tag(&t, 0x1010, 0xa);
    CHECK(tw_wtab_get(&t, 0x1018, &tag) == 7 && tag == 0xa);
    tw_wtab_set_orig_tag(&t, 0x2000, 0x5); // not armed: ignored
    CHECK(tw_wtab_get(&t, 0x2000, &tag) == 0);

    // Overlap is rejected and leaves the table untouched.
    CHECK(tw_wtab_insert(&t, 0x1020, 32, 8) == -EEXIST);
    CHECK(tw_wtab_get(&t, 0x1030, NULL) == 0);
    CHECK(t.granules == 3);
    // Argument validation.
    CHECK(tw_wtab_insert(&t, 0x1001, 16, 8) == -EINVAL);
    CHECK(tw_wtab_insert(&t, 0x2000, 8, 8) == -EINVAL);
    CHECK(tw_wtab_insert(&t, 0x2000, 0, 8) == -EINVAL);
    CHECK(tw_wtab_insert(&t, 0x2000, 16, 0) == -EINVAL);
    CHECK(tw_wtab_insert(&t, 0xfffffffffffffff0ull, 16, 8) == -EINVAL);
    CHECK(tw_wtab_insert(&t, 0x2000, 16, TW_SLOT_MAX + 1) == -EINVAL);

    uint64_t hit = 0;
    CHECK(tw_wtab_find(&t, 0xff8, 16, &hit) == 7 && hit == 0x1000); // access straddling into the watch
    CHECK(tw_wtab_find(&t, 0x102f, 1, &hit) == 7 && hit == 0x1020);
    CHECK(tw_wtab_find(&t, 0x1030, 64, &hit) == 0);
    CHECK(tw_wtab_find(&t, 0xff0, 16, &hit) == 0);
    CHECK(tw_wtab_find(&t, 0x1000, 0, &hit) == 0);
    CHECK(tw_wtab_find(&t, 0xfffffffffffffff8ull, 64, &hit) == 0); // wrapping range

    // Removing with the wrong slot releases nothing.
    CHECK(tw_wtab_remove(&t, 0x1000, 48, 9) == 0);
    CHECK(tw_wtab_remove(&t, 0x1000, 48, 7) == 3);
    CHECK(t.granules == 0 && t.used == 0);
    CHECK(tw_wtab_get(&t, 0x1000, NULL) == 0);

    // A watch spanning several pages.
    CHECK(tw_wtab_insert(&t, 0x7ff0, 0x8020, 3) == 0);
    CHECK(t.used == 4); // 0x4000, 0x8000, 0xc000 and 0x10000
    CHECK(tw_wtab_get(&t, 0x7ff0, NULL) == 3 && tw_wtab_get(&t, 0x1000f, NULL) == 3 && tw_wtab_get(&t, 0x10010, NULL) == 0);
    CHECK(tw_wtab_remove(&t, 0x7ff0, 0x8020, 3) == 0x802);
    CHECK(t.used == 0);
    tw_wtab_destroy(&t);
    CHECK_EQ(live_bytes, 0);
}

static void oom(void) {
    // Every allocation point must fail cleanly: no partial watch, no leak.
    for (long budget = 0; budget < 12; budget++) {
        tw_wtab t;
        fail_after = budget;
        int rc = tw_wtab_init(&t, &mem);
        if (rc == 0) {
            rc = tw_wtab_insert(&t, 0x3ff0, 0x4020, 5);
            if (rc != 0) {
                CHECK_EQ(rc, -ENOMEM);
                CHECK(t.granules == 0);
                CHECK(tw_wtab_find(&t, 0, 0x100000, NULL) == 0);
            }
            fail_after = -1;
            tw_wtab_destroy(&t);
        }
        fail_after = -1;
        CHECK_EQ(live_bytes, 0);
    }
}

static void randomized(void) {
    uint64_t st = t_seed(0x7774616221212121ull);
    tw_wtab t;
    CHECK(tw_wtab_init(&t, &mem) == 0);
    struct {
        uint32_t first, count;
        int live;
    } watches[600];
    memset(watches, 0, sizeof watches);
    uint64_t total = 0;
    for (int step = 0; step < 60000; step++) {
        uint32_t w = (uint32_t)(t_rand(&st) % 600);
        if (!watches[w].live) {
            uint32_t first = (uint32_t)(t_rand(&st) % WINDOW_GRANULES);
            // Mostly small objects, sometimes multi-page ranges.
            uint32_t count = (t_rand(&st) % 16 == 0) ? 1 + (uint32_t)(t_rand(&st) % 2500) : 1 + (uint32_t)(t_rand(&st) % 8);
            if (first + count > WINDOW_GRANULES) count = WINDOW_GRANULES - first;
            int overlap = 0;
            for (uint32_t g = first; g < first + count; g++) overlap |= model[g] != 0;
            int rc = tw_wtab_insert(&t, BASE + first * 16ull, count * 16ull, w + 1);
            CHECK_EQ(rc, overlap ? -EEXIST : 0);
            if (rc == 0) {
                for (uint32_t g = first; g < first + count; g++) model[g] = w + 1;
                watches[w].first = first;
                watches[w].count = count;
                watches[w].live = 1;
                total += count;
            }
        } else {
            uint64_t n = tw_wtab_remove(&t, BASE + watches[w].first * 16ull, watches[w].count * 16ull, w + 1);
            CHECK_EQ(n, watches[w].count);
            for (uint32_t g = watches[w].first; g < watches[w].first + watches[w].count; g++) model[g] = 0;
            watches[w].live = 0;
            total -= watches[w].count;
        }
        CHECK(t.granules == total);
        // Point queries.
        for (int q = 0; q < 8; q++) {
            uint32_t g = (uint32_t)(t_rand(&st) % WINDOW_GRANULES);
            CHECK(tw_wtab_get(&t, BASE + g * 16ull + (t_rand(&st) & 15), NULL) == model[g]);
        }
        // Range query against a linear scan of the model.
        uint64_t a = t_rand(&st) % (WINDOW_GRANULES * 16ull), len = 1 + t_rand(&st) % 200;
        if (a + len > WINDOW_GRANULES * 16ull) len = WINDOW_GRANULES * 16ull - a;
        uint32_t expect = 0;
        uint64_t expect_hit = 0;
        for (uint64_t g = a / 16; g <= (a + len - 1) / 16; g++)
            if (model[g]) {
                expect = model[g];
                expect_hit = BASE + g * 16;
                break;
            }
        uint64_t hit = 0;
        uint32_t got = tw_wtab_find(&t, BASE + a, len, &hit);
        CHECK(got == expect);
        if (got) CHECK(hit == expect_hit);
    }
    // Full sweep at the end, then drain and check the table empties itself.
    for (uint32_t g = 0; g < WINDOW_GRANULES; g++) CHECK(tw_wtab_get(&t, BASE + g * 16ull, NULL) == model[g]);
    for (int w = 0; w < 600; w++)
        if (watches[w].live) tw_wtab_remove(&t, BASE + watches[w].first * 16ull, watches[w].count * 16ull, (uint32_t)w + 1);
    CHECK(t.granules == 0 && t.used == 0);
    tw_wtab_destroy(&t);
    CHECK_EQ(live_bytes, 0);
}

static void watch_tag_properties(void) {
    for (unsigned tag = 0; tag < 16; tag++) {
        unsigned w = tw_watch_tag(tag);
        CHECK(w != tag); // every legitimate pointer must fault
        CHECK(w != 0);   // untagged pointers must fault as well
        CHECK(w < 16);
    }
}

int main(void) {
    basic();
    oom();
    randomized();
    watch_tag_properties();
    return t_done("wtab");
}

// Arm, fault, log, continue, disarm: the core loop and its error paths.
#include "mt.h"

static long on_stack_probe;

int main(void) {
    mt_start("basic");
    tagwatch_stats st0, st;
    CHECK(tagwatch_available());
    CHECK(tagwatch_init() == 0); // idempotent

    // --- an object from the arena ------------------------------------------
    uint64_t *p = tagwatch_alloc_watched(64, "obj");
    CHECK(p != NULL);
    store64(p + 1, 0x1122334455667788ull);
    CHECK_EQ(mt_count(), 1);
    const mt_event *e = mt_last();
    CHECK(e->access == TAGWATCH_WRITE);
    CHECK_EQ(e->size, 8);
    CHECK(e->addr == (uint64_t)(uintptr_t)(p + 1));
    CHECK_EQ(e->offset, 8);
    CHECK_EQ(e->watch_len, 64);
    CHECK(e->watch_base == (uint64_t)(uintptr_t)p);
    CHECK(!strcmp(e->label, "obj"));
    CHECK(e->tid == mt_tid());
    CHECK(e->flags == 0);
    CHECK(e->nframes >= 2 && e->frames[0] == e->pc);

    // The access really happened, and a read reports as a read.
    CHECK(load64(p + 1) == 0x1122334455667788ull);
    CHECK_EQ(mt_count(), 2);
    CHECK(mt_last()->access == TAGWATCH_READ && mt_last()->offset == 8);

    // peek/poke and pause/resume do not report.
    uint64_t q = 0, five = 5;
    tagwatch_peek(&q, p + 1, 8);
    CHECK(q == 0x1122334455667788ull);
    tagwatch_poke(p + 2, &five, 8);
    tagwatch_pause();
    tagwatch_pause();
    store64(p, 6);
    tagwatch_resume();
    store64(p, 7); // still paused: pauses nest
    tagwatch_resume();
    CHECK_EQ(mt_count(), 2);
    CHECK(load64(p + 2) == 5 && load64(p) == 7);
    CHECK_EQ(mt_count(), 4);

    // Disarming: accesses are silent again, and the id is gone.
    CHECK(tagwatch_unwatch_addr(p) == 0);
    store64(p, 8);
    CHECK_EQ(mt_count(), 4);
    CHECK(tagwatch_unwatch_addr(p) == -TAGWATCH_ENOENT);

    // --- a system-heap block watched in place ---------------------------------
    mt_reset();
    char *h = malloc(48);
    memset(h, 0, 48);
    tagwatch_id id = tagwatch_watch(h, 48, "heap");
    CHECK(id > 0);
    store8(h + 5, 1);
    CHECK_EQ(mt_count(), 1);
    CHECK(mt_last()->access == TAGWATCH_WRITE && mt_last()->size == 1 && mt_last()->offset == 5);
    CHECK(mt_last()->watch == id); // the callback sees the id the caller was given
    CHECK(tagwatch_watch(h + 16, 16, "overlap") == -TAGWATCH_EEXIST);
    CHECK(tagwatch_unwatch(id) == 0);
    CHECK(tagwatch_unwatch(id) == -TAGWATCH_ENOENT);
    store8(h + 5, 2);
    CHECK_EQ(mt_count(), 1);
    CHECK(load8(h + 5) == 2);
    // A stale id must not remove a later watch that reuses the slot.
    tagwatch_id id2 = tagwatch_watch(h, 48, "heap2");
    CHECK(id2 > 0 && id2 != id);
    CHECK(tagwatch_unwatch(id) == -TAGWATCH_ENOENT);
    store8(h, 3);
    CHECK_EQ(mt_count(), 2);
    free(h); // freeing a watched system block removes the watch first
    tagwatch_get_stats(&st);
    CHECK_EQ(st.watches_live, 0);

    // --- argument and memory errors ---------------------------------------------
    CHECK(tagwatch_watch(NULL, 8, "x") == -TAGWATCH_EINVAL);
    CHECK(tagwatch_watch(p, 0, "x") == -TAGWATCH_EINVAL);
    CHECK(tagwatch_watch_mode(p, 8, "x", 0) == -TAGWATCH_EINVAL);
    CHECK(tagwatch_watch_mode(p, 8, "x", 8) == -TAGWATCH_EINVAL);
    CHECK(tagwatch_unwatch(0) == -TAGWATCH_ENOENT && tagwatch_unwatch(-5) == -TAGWATCH_ENOENT);
    long local = 1;
    CHECK(tagwatch_watch(&local, sizeof local, "stack") == -TAGWATCH_ENOTTAGGED);
    CHECK(tagwatch_watch(&on_stack_probe, 8, "global") == -TAGWATCH_ENOTTAGGED);
    CHECK(tagwatch_watch((void *)0x10, 8, "unmapped") == -TAGWATCH_ENOTTAGGED);
    char *big = malloc(1 << 20); // large system allocations are not tagged
    CHECK(tagwatch_watch(big, 64, "big") == -TAGWATCH_ENOTTAGGED);
    big[0] = 1;
    free(big);
    tagwatch_get_stats(&st);
    CHECK_EQ(st.watches_live, 0);
    CHECK_EQ(st.granules_live, 0);
    CHECK(local == 1);

    // --- byte-precise reporting on 16-byte granules -------------------------------
    mt_reset();
    char *g = tagwatch_alloc(64);
    CHECK(tagwatch_watch(g + 4, 4, "field") > 0);
    tagwatch_get_stats(&st0);
    store8(g + 4, 1); // inside the field
    CHECK_EQ(mt_count(), 1);
    CHECK(mt_last()->offset == 0);
    store8(g + 12, 1); // same granule, outside the field: traps, not reported
    CHECK_EQ(mt_count(), 1);
    store8(g + 16, 1); // next granule: does not trap at all
    tagwatch_get_stats(&st);
    CHECK_EQ(st.traps - st0.traps, 2);
    CHECK_EQ(st.filtered - st0.filtered, 1);
    store64(g, 0x0101010101010101ull); // an 8-byte store covering the field from outside
    CHECK_EQ(mt_count(), 2);
    CHECK(mt_last()->offset == -4 && mt_last()->size == 8);

    // --- write-only watches -----------------------------------------------------------
    mt_reset();
    CHECK(tagwatch_watch_mode(g + 32, 16, "wo", TAGWATCH_WRITE) > 0);
    (void)load64(g + 32);
    CHECK_EQ(mt_count(), 0);
    store64(g + 32, 1);
    CHECK_EQ(mt_count(), 1);
    free(g);

    CHECK(!strcmp(tagwatch_strerror(-TAGWATCH_EEXIST), tagwatch_strerror(TAGWATCH_EEXIST)));
    tagwatch_get_stats(&st);
    CHECK(st.violations == 0);
    CHECK(st.trampolines > 0);
    return mt_done();
}

// Multi-threaded guarantee: a watched granule never loses its watch tag while
// an access is being let through, so concurrent accesses by other threads are
// all seen. The counts below are exact, not lower bounds.
#include "mt.h"

#define THREADS 8
#define ITERS 1500

static uint64_t *shared; // watched: [0] shared atomic counter, [1..THREADS] private slots
static _Atomic int go;
static uint64_t tids[THREADS];

static void *hammer(void *arg) {
    long me = (long)arg;
    tids[me] = mt_tid();
    while (!atomic_load(&go)) {}
    for (int i = 0; i < ITERS; i++) {
        uint64_t one = 1, old;
        __asm__ volatile("ldaddal %1, %0, [%2]" : "=&r"(old) : "r"(one), "r"(shared) : "memory"); // 1 event
        uint64_t v = load64(shared + 1 + me);                                                      // 1 event
        store64(shared + 1 + me, v + 1);                                                           // 1 event
    }
    return NULL;
}

// Arm/disarm churn while other threads keep accessing the object.
static uint64_t *churn_obj;
static _Atomic int churn_stop;
static void *churn_reader(void *arg) {
    (void)arg;
    uint64_t sum = 0;
    while (!atomic_load(&churn_stop)) {
        sum += load64(churn_obj);
        store64(churn_obj + 1, sum);
    }
    return NULL;
}

int main(void) {
    mt_start("threads");
    shared = tagwatch_alloc_watched((1 + THREADS) * 8, "shared");
    pthread_t th[THREADS];
    for (long i = 0; i < THREADS; i++) pthread_create(&th[i], NULL, hammer, (void *)i);
    atomic_store(&go, 1);
    for (int i = 0; i < THREADS; i++) pthread_join(th[i], NULL);

    // Every access was reported exactly once...
    CHECK_EQ(mt_count(), THREADS * ITERS * 3);
    // ...and every access took effect exactly once.
    uint64_t vals[1 + THREADS];
    tagwatch_peek(vals, shared, sizeof vals);
    CHECK_EQ(vals[0], THREADS * ITERS);
    for (int i = 0; i < THREADS; i++) CHECK_EQ(vals[1 + i], ITERS);
    // Per thread: ITERS of each kind, attributed to the right thread and offset.
    int per_thread[THREADS][3];
    memset(per_thread, 0, sizeof per_thread);
    int unknown = 0;
    for (int k = 0; k < mt_count() && k < MT_MAX; k++) {
        const mt_event *e = &mt_events[k];
        int t = -1;
        for (int i = 0; i < THREADS; i++)
            if (tids[i] == e->tid) t = i;
        if (t < 0) {
            unknown++;
            continue;
        }
        if (e->access == TAGWATCH_RW && e->offset == 0) per_thread[t][0]++;
        else if (e->access == TAGWATCH_READ && e->offset == 8 * (1 + t)) per_thread[t][1]++;
        else if (e->access == TAGWATCH_WRITE && e->offset == 8 * (1 + t)) per_thread[t][2]++;
        else unknown++;
    }
    CHECK_EQ(unknown, 0);
    for (int i = 0; i < THREADS; i++) {
        CHECK_EQ(per_thread[i][0], ITERS);
        CHECK_EQ(per_thread[i][1], ITERS);
        CHECK_EQ(per_thread[i][2], ITERS);
    }
    tagwatch_stats st;
    tagwatch_get_stats(&st);
    CHECK_EQ(st.violations, 0);
    CHECK(tagwatch_unwatch_addr(shared) == 0);
    free(shared);

    // Arming and disarming under fire: faults that were already in flight
    // when the watch went away must be retried, not treated as violations.
    mt_reset();
    churn_obj = tagwatch_alloc(64);
    pthread_t readers[4];
    for (int i = 0; i < 4; i++) pthread_create(&readers[i], NULL, churn_reader, NULL);
    int armed = 0;
    for (int i = 0; i < 3000; i++) {
        tagwatch_id id = tagwatch_watch(churn_obj, 64, "churn");
        if (id > 0) {
            armed++;
            if (i % 7 == 0) usleep(50);
            CHECK(tagwatch_unwatch(id) == 0);
        }
    }
    atomic_store(&churn_stop, 1);
    for (int i = 0; i < 4; i++) pthread_join(readers[i], NULL);
    CHECK_EQ(armed, 3000);
    CHECK(mt_count() > 0);
    tagwatch_get_stats(&st);
    CHECK_EQ(st.violations, 0);
    CHECK_EQ(st.watches_live, 0);
    printf("     (%d accesses caught during 3000 arm/disarm cycles with 4 threads running)\n", mt_count());
    free(churn_obj);
    return mt_done();
}

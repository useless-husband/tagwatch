// Harness for the MTE tests. Each test is an executable that links
// libtagwatch, carries the hardened-process entitlements (so it runs with MTE
// enabled) and records the events it triggers through the callback.
#ifndef TW_MT_H
#define TW_MT_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tagwatch.h"

typedef struct {
    uint64_t addr, watch_base, watch_len, tid, pc, frames[8];
    int64_t offset, watch;
    uint32_t size, access, flags, nframes;
    char label[32], syscall[16];
} mt_event;

#define MT_MAX 200000
static mt_event *mt_events;
static _Atomic int mt_n;
static int mt_checks, mt_failures;
static const char *mt_name;

static int mt_record(const tagwatch_event *ev, void *ctx) {
    (void)ctx;
    int i = atomic_fetch_add(&mt_n, 1);
    if (i < MT_MAX) {
        mt_event *e = &mt_events[i];
        e->addr = ev->addr, e->watch_base = ev->watch_base, e->watch_len = ev->watch_len, e->tid = ev->thread_id, e->pc = ev->pc;
        e->offset = ev->offset, e->watch = ev->watch, e->size = ev->size, e->access = ev->access, e->flags = ev->flags;
        e->nframes = ev->nframes;
        for (unsigned k = 0; k < 8 && k < ev->nframes; k++) e->frames[k] = ev->frames[k];
        // No libc string calls here: the accessing thread is frozen and may hold locks.
        unsigned k = 0;
        for (; ev->label && ev->label[k] && k < sizeof e->label - 1; k++) e->label[k] = ev->label[k];
        e->label[k] = 0;
        for (k = 0; ev->syscall && ev->syscall[k] && k < sizeof e->syscall - 1; k++) e->syscall[k] = ev->syscall[k];
        e->syscall[k] = 0;
    }
    return 1; // keep the test output free of log lines
}

#define CHECK(cond)                                                                 \
    do {                                                                            \
        mt_checks++;                                                                \
        if (!(cond)) {                                                              \
            mt_failures++;                                                          \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);         \
        }                                                                           \
    } while (0)

#define CHECK_EQ(a, b)                                                              \
    do {                                                                            \
        long long mt_a = (long long)(a), mt_b = (long long)(b);                     \
        mt_checks++;                                                                \
        if (mt_a != mt_b) {                                                         \
            mt_failures++;                                                          \
            fprintf(stderr, "FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a, #b, mt_a, mt_b); \
        }                                                                           \
    } while (0)

static inline void mt_start(const char *name) {
    mt_name = name;
    setvbuf(stdout, NULL, _IOLBF, 0);
    int rc = tagwatch_init();
    if (rc != 0) {
        printf("SKIP %-10s tagwatch_init: %s\n", name, tagwatch_strerror(rc));
        exit(77);
    }
    alarm(120); // a hung test must not hang the suite
    // Allocated up front: the recorder runs on the handler thread and must not call malloc.
    mt_events = calloc(MT_MAX, sizeof *mt_events);
    tagwatch_set_callback(mt_record, NULL);
    if (!getenv("MT_LOG")) tagwatch_set_output(-1, NULL); // MT_LOG=1 keeps the live log for debugging
}

static inline int mt_count(void) { return atomic_load(&mt_n); }
static inline void mt_reset(void) { atomic_store(&mt_n, 0); }
static inline const mt_event *mt_last(void) {
    static const mt_event none;
    int n = mt_count();
    return n > 0 && n <= MT_MAX ? &mt_events[n - 1] : &none;
}

static inline int mt_done(void) {
    if (mt_failures) {
        fprintf(stderr, "%s: %d of %d checks FAILED\n", mt_name, mt_failures, mt_checks);
        return 1;
    }
    printf("ok   %-10s %d checks\n", mt_name, mt_checks);
    return 0;
}

static inline uint64_t mt_tid(void) {
    uint64_t t = 0;
    pthread_threadid_np(NULL, &t);
    return t;
}

// Exact instructions, so the tests know what access they performed.
static inline void store64(void *p, uint64_t v) { __asm__ volatile("str %1, [%0]" : : "r"(p), "r"(v) : "memory"); }
static inline uint64_t load64(const void *p) {
    uint64_t v;
    __asm__ volatile("ldr %0, [%1]" : "=r"(v) : "r"(p) : "memory");
    return v;
}
static inline void store8(void *p, uint8_t v) { __asm__ volatile("strb %w1, [%0]" : : "r"(p), "r"(v) : "memory"); }
static inline uint8_t load8(const void *p) {
    uint32_t v;
    __asm__ volatile("ldrb %w0, [%1]" : "=r"(v) : "r"(p) : "memory");
    return (uint8_t)v;
}

#endif

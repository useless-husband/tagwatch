// Minimal test harness: CHECK records a failure and keeps going, so one run
// reports everything that is wrong.
#ifndef TW_T_H
#define TW_T_H

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int t_checks, t_failures;
static uint64_t t_seed_value;

#define CHECK(cond)                                                                        \
    do {                                                                                   \
        t_checks++;                                                                        \
        if (!(cond)) {                                                                     \
            t_failures++;                                                                  \
            fprintf(stderr, "FAIL %s:%d: %s (seed %" PRIu64 ")\n", __FILE__, __LINE__, #cond, t_seed_value); \
        }                                                                                  \
    } while (0)

#define CHECK_EQ(a, b)                                                                     \
    do {                                                                                   \
        long long t_a = (long long)(a), t_b = (long long)(b);                              \
        t_checks++;                                                                        \
        if (t_a != t_b) {                                                                  \
            t_failures++;                                                                  \
            fprintf(stderr, "FAIL %s:%d: %s == %s (%lld vs %lld, seed %" PRIu64 ")\n", __FILE__, __LINE__, #a, #b, t_a, t_b, \
                    t_seed_value);                                                         \
        }                                                                                  \
    } while (0)

#define CHECK_STR(a, b)                                                                    \
    do {                                                                                   \
        const char *t_a = (a), *t_b = (b);                                                 \
        t_checks++;                                                                        \
        if (strcmp(t_a, t_b) != 0) {                                                       \
            t_failures++;                                                                  \
            fprintf(stderr, "FAIL %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, t_a, t_b); \
        }                                                                                  \
    } while (0)

// Deterministic PRNG (splitmix64). The seed is fixed unless TW_TEST_SEED is
// set, and is printed with every failure.
static inline uint64_t t_seed(uint64_t dflt) {
    const char *e = getenv("TW_TEST_SEED");
    t_seed_value = e ? strtoull(e, NULL, 0) : dflt;
    return t_seed_value;
}

static inline uint64_t t_rand(uint64_t *state) {
    uint64_t z = (*state += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

static inline int t_done(const char *name) {
    if (t_failures) {
        fprintf(stderr, "%s: %d of %d checks FAILED\n", name, t_failures, t_checks);
        return 1;
    }
    printf("ok   %-14s %d checks\n", name, t_checks);
    return 0;
}

#endif

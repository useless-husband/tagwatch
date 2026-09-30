// The workload used by the overhead and comparison benchmarks: a chained
// hash table of 48-byte heap nodes and a deterministic mix of lookups and
// updates. It is ordinary code with no knowledge of any watch mechanism.
#ifndef BENCH_KV_H
#define BENCH_KV_H

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

struct kv_node {
    struct kv_node *next;
    uint64_t key, value, hits;
    uint64_t pad[2];
}; // 48 bytes: three MTE granules

struct kv {
    struct kv_node **buckets;
    struct kv_node **all; // nodes in allocation order
    uint64_t n, mask;
};

static inline uint64_t kv_hash(uint64_t k) {
    k ^= k >> 33, k *= 0xff51afd7ed558ccdull, k ^= k >> 33;
    return k;
}

static inline uint64_t kv_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

__attribute__((noinline)) static struct kv_node *kv_node_new(uint64_t key) {
    struct kv_node *n = malloc(sizeof *n);
    if (!n) abort();
    n->next = NULL;
    n->key = key;
    n->value = key * 3;
    n->hits = 0;
    return n;
}

static void kv_build(struct kv *t, uint64_t n) {
    uint64_t buckets = 1;
    while (buckets < n) buckets <<= 1;
    t->n = n;
    t->mask = buckets - 1;
    t->buckets = calloc(buckets, sizeof *t->buckets);
    t->all = calloc(n, sizeof *t->all);
    if (!t->buckets || !t->all) abort();
    for (uint64_t k = 0; k < n; k++) {
        struct kv_node *node = kv_node_new(k);
        t->all[k] = node;
        struct kv_node **b = &t->buckets[kv_hash(k) & t->mask];
        node->next = *b;
        *b = node;
    }
}

// m operations on uniformly random keys: half read the value, half update it.
__attribute__((noinline)) static uint64_t kv_run(struct kv *t, uint64_t m) {
    uint64_t rng = 0x9e3779b97f4a7c15ull, sum = 0;
    for (uint64_t i = 0; i < m; i++) {
        rng ^= rng << 13, rng ^= rng >> 7, rng ^= rng << 17;
        uint64_t key = rng % t->n;
        struct kv_node *node = t->buckets[kv_hash(key) & t->mask];
        while (node && node->key != key) node = node->next;
        if (!node) abort();
        if (rng & (1ull << 40)) {
            node->value += key;
            node->hits++;
        } else {
            sum += node->value;
        }
    }
    return sum;
}

#endif

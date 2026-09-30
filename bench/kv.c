// kv: the benchmark workload as a standalone program (run it under
// `tagwatch run -a size=48,every=K` to watch one node in K).
//   usage: kv [nodes] [operations]
#include <stdio.h>

#include "kv.h"

int main(int argc, char **argv) {
    uint64_t n = argc > 1 ? strtoull(argv[1], NULL, 0) : 100000;
    uint64_t m = argc > 2 ? strtoull(argv[2], NULL, 0) : 1000000;
    struct kv t;
    kv_build(&t, n);
    uint64_t t0 = kv_now_ns();
    uint64_t sum = kv_run(&t, m);
    uint64_t t1 = kv_now_ns();
    printf("kv nodes=%llu ops=%llu checksum=%llu ops_ms=%.2f ns_per_op=%.1f\n", (unsigned long long)n, (unsigned long long)m,
           (unsigned long long)sum, (double)(t1 - t0) / 1e6, (double)(t1 - t0) / (double)m);
    return 0;
}

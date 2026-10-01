// Every addressing form and instruction class that can touch watched memory:
// the access must be reported with the right address, width and direction,
// and the instruction must have its normal effect (including base-register
// writeback and atomicity results).
#include "mt.h"

#include <sys/sysctl.h>
#include <zlib.h>

static uint8_t *blk; // 256-byte arena block; the watch covers [w, w + 64)
static uint8_t *w;

static void expect(const char *what, unsigned access, unsigned size, long off, int n_events) {
    int n = mt_count();
    if (n != n_events) fprintf(stderr, "  %s: %d events, expected %d\n", what, n, n_events);
    CHECK_EQ(n, n_events);
    if (n > 0) {
        const mt_event *e = mt_last();
        if (e->access != access || e->size != size || e->offset != off)
            fprintf(stderr, "  %s: got access=%u size=%u off=%lld, expected %u %u %ld\n", what, e->access, e->size,
                    (long long)e->offset, access, size, off);
        CHECK(e->access == access);
        CHECK_EQ(e->size, size);
        CHECK_EQ(e->offset, off);
    }
    mt_reset();
}

static void fill(void) {
    uint8_t pattern[256];
    for (int i = 0; i < 256; i++) pattern[i] = (uint8_t)i;
    tagwatch_poke(blk, pattern, 256);
}

static uint64_t peek64(const void *p) {
    uint64_t v;
    tagwatch_peek(&v, p, 8);
    return v;
}

#define R TAGWATCH_READ
#define W TAGWATCH_WRITE
#define RW TAGWATCH_RW

int main(void) {
    mt_start("insn");
    blk = tagwatch_alloc(320);
    // A 64-byte aligned window (DC ZVA needs it) with unwatched memory around it.
    w = (uint8_t *)(((uintptr_t)blk + 64 + 63) & ~(uintptr_t)63);
    CHECK(tagwatch_watch(w, 64, "window") > 0);
    fill();
    uint64_t v = 0, v2 = 0, base;
    const uint64_t at0 = peek64(w), at8 = peek64(w + 8), at16 = peek64(w + 16), at24 = peek64(w + 24);

    // --- integer loads and stores, immediate offsets ---------------------------
    __asm__ volatile("ldr %0, [%1, #8]" : "=r"(v) : "r"(w) : "memory");
    CHECK(v == at8);
    expect("ldr x", R, 8, 8, 1);
    __asm__ volatile("ldr %w0, [%1, #4]" : "=r"(v) : "r"(w) : "memory");
    CHECK(v == (uint32_t)(at0 >> 32));
    expect("ldr w", R, 4, 4, 1);
    __asm__ volatile("ldrh %w0, [%1, #2]" : "=r"(v) : "r"(w) : "memory");
    expect("ldrh", R, 2, 2, 1);
    __asm__ volatile("ldrsw %0, [%1, #12]" : "=r"(v) : "r"(w) : "memory");
    expect("ldrsw", R, 4, 12, 1);
    __asm__ volatile("ldursb %w0, [%1, #63]" : "=r"(v) : "r"(w) : "memory");
    expect("ldursb", R, 1, 63, 1);
    v = 0xa1a2a3a4a5a6a7a8ull;
    __asm__ volatile("str %0, [%1, #32]" : : "r"(v), "r"(w) : "memory");
    CHECK(peek64(w + 32) == v);
    expect("str x", W, 8, 32, 1);
    __asm__ volatile("strh %w0, [%1, #40]" : : "r"(v), "r"(w) : "memory");
    expect("strh", W, 2, 40, 1);
    __asm__ volatile("stur %0, [%1, #-8]" : : "r"(v), "r"(w + 16) : "memory");
    CHECK(peek64(w + 8) == v);
    expect("stur", W, 8, 8, 1);
    fill();

    // --- pairs -----------------------------------------------------------------------
    __asm__ volatile("ldp %0, %1, [%2, #16]" : "=&r"(v), "=&r"(v2) : "r"(w) : "memory");
    CHECK(v == at16 && v2 == at24);
    expect("ldp", R, 16, 16, 1);
    v = 1, v2 = 2;
    __asm__ volatile("stp %0, %1, [%2, #48]" : : "r"(v), "r"(v2), "r"(w) : "memory");
    CHECK(peek64(w + 48) == 1 && peek64(w + 56) == 2);
    expect("stp", W, 16, 48, 1);
    __asm__ volatile("ldp %w0, %w1, [%2, #8]" : "=&r"(v), "=&r"(v2) : "r"(w) : "memory");
    expect("ldp w", R, 8, 8, 1);
    fill();

    // --- writeback: the base register must end up updated ---------------------------
    base = (uint64_t)(uintptr_t)w;
    __asm__ volatile("ldr %0, [%1, #16]!" : "=&r"(v), "+r"(base) : : "memory");
    CHECK(v == at16 && base == (uint64_t)(uintptr_t)w + 16);
    expect("ldr pre-index", R, 8, 16, 1);
    base = (uint64_t)(uintptr_t)w;
    __asm__ volatile("ldr %0, [%1], #8" : "=&r"(v), "+r"(base) : : "memory");
    CHECK(v == at0 && base == (uint64_t)(uintptr_t)w + 8);
    expect("ldr post-index", R, 8, 0, 1);
    base = (uint64_t)(uintptr_t)w + 32;
    v = 7, v2 = 9;
    __asm__ volatile("stp %1, %2, [%0, #-16]!" : "+r"(base) : "r"(v), "r"(v2) : "memory");
    CHECK(base == (uint64_t)(uintptr_t)w + 16 && peek64(w + 16) == 7 && peek64(w + 24) == 9);
    expect("stp pre-index", W, 16, 16, 1);
    base = (uint64_t)(uintptr_t)w + 3;
    v = 0xee;
    __asm__ volatile("strb %w1, [%0], #1" : "+r"(base) : "r"(v) : "memory");
    CHECK(base == (uint64_t)(uintptr_t)w + 4);
    expect("strb post-index", W, 1, 3, 1);
    fill();

    // --- pair writeback, and a pair load that overwrites its own base ----------------------
    base = (uint64_t)(uintptr_t)w;
    __asm__ volatile("ldp %0, %1, [%2], #16" : "=&r"(v), "=&r"(v2), "+r"(base) : : "memory");
    CHECK(v == at0 && v2 == at8 && base == (uint64_t)(uintptr_t)w + 16);
    expect("ldp post-index", R, 16, 0, 1);
    base = (uint64_t)(uintptr_t)w;
    __asm__ volatile("ldp %0, %1, [%0, #16]" : "+&r"(base), "=&r"(v2) : : "memory"); // x = [x + 16], x2 = [x + 24]
    CHECK(base == at16 && v2 == at24);
    expect("ldp into its base", R, 16, 16, 1);
    base = (uint64_t)(uintptr_t)w;
    __asm__ volatile("ldr %0, [%0, #24]" : "+r"(base) : : "memory");
    CHECK(base == at24);
    expect("ldr into its base", R, 8, 24, 1);
    v = 3, v2 = 4;
    __asm__ volatile("stnp %0, %1, [%2, #32]" : : "r"(v), "r"(v2), "r"(w) : "memory");
    CHECK(peek64(w + 32) == 3 && peek64(w + 40) == 4);
    expect("stnp", W, 16, 32, 1);
    fill();

    // --- register offsets ---------------------------------------------------------------
    uint64_t idx = 3;
    __asm__ volatile("ldr %0, [%1, %2, lsl #3]" : "=&r"(v) : "r"(w), "r"(idx) : "memory");
    CHECK(v == at24);
    expect("ldr [x, x, lsl 3]", R, 8, 24, 1);
    int32_t neg = -8;
    __asm__ volatile("ldr %0, [%1, %w2, sxtw]" : "=&r"(v) : "r"(w + 32), "r"(neg) : "memory");
    CHECK(v == at24);
    expect("ldr [x, w, sxtw]", R, 8, 24, 1);
    idx = 5;
    __asm__ volatile("strb %w0, [%1, %2]" : : "r"(v), "r"(w), "r"(idx) : "memory");
    expect("strb [x, x]", W, 1, 5, 1);
    fill();

    // --- SIMD and FP -------------------------------------------------------------------
    __asm__ volatile("ldr q0, [%0, #16]" : : "r"(w) : "v0", "memory");
    expect("ldr q", R, 16, 16, 1);
    __asm__ volatile("str q0, [%0, #32]" : : "r"(w) : "memory");
    CHECK(peek64(w + 32) == at16 && peek64(w + 40) == at24);
    expect("str q", W, 16, 32, 1);
    __asm__ volatile("ldp q0, q1, [%0]" : : "r"(w) : "v0", "v1", "memory");
    expect("ldp q", R, 32, 0, 1);
    __asm__ volatile("ldr d0, [%0, #8]" : : "r"(w) : "v0", "memory");
    expect("ldr d", R, 8, 8, 1);
    __asm__ volatile("ld1 {v0.16b, v1.16b, v2.16b, v3.16b}, [%0]" : : "r"(w) : "v0", "v1", "v2", "v3", "memory");
    expect("ld1 x4", R, 64, 0, 1);
    base = (uint64_t)(uintptr_t)w + 48;
    __asm__ volatile("st1 {v3.16b}, [%0], #16" : "+r"(base) : : "memory");
    CHECK(base == (uint64_t)(uintptr_t)w + 64);
    expect("st1 post-index", W, 16, 48, 1);
    __asm__ volatile("ld1r {v0.4s}, [%0]" : : "r"(w + 20) : "v0", "memory");
    expect("ld1r", R, 4, 20, 1);
    base = (uint64_t)(uintptr_t)w + 4;
    idx = 12;
    uint64_t lane = 0;
    __asm__ volatile("movi v0.16b, #0\n ld1 {v0.s}[1], [%0], %2\n umov %1, v0.d[0]"
                     : "+r"(base), "=r"(lane)
                     : "r"(idx)
                     : "v0", "memory");
    CHECK(base == (uint64_t)(uintptr_t)w + 16 && (lane >> 32) == (uint32_t)(at0 >> 32));
    expect("ld1 lane, post-index by register", R, 4, 4, 1);
    base = (uint64_t)(uintptr_t)w;
    __asm__ volatile("ld4 {v0.4s, v1.4s, v2.4s, v3.4s}, [%0], #64" : "+r"(base) : : "v0", "v1", "v2", "v3", "memory");
    CHECK(base == (uint64_t)(uintptr_t)w + 64);
    expect("ld4 post-index", R, 64, 0, 1);
    fill();

    // --- atomics: one instruction, reported once, still atomic ------------------------------
    uint64_t add = 5, old = 0;
    tagwatch_poke(w, &(uint64_t){100}, 8);
    __asm__ volatile("ldaddal %0, %1, [%2]" : "=&r"(old) : "0"(add), "r"(w) : "memory");
    (void)add;
    expect("ldaddal", RW, 8, 0, 1);
    CHECK(peek64(w) == 105);
    uint64_t cmp = 105, newv = 200;
    __asm__ volatile("casal %0, %1, [%2]" : "+r"(cmp) : "r"(newv), "r"(w) : "memory");
    CHECK(cmp == 105 && peek64(w) == 200);
    expect("casal hit", RW, 8, 0, 1);
    cmp = 1;
    __asm__ volatile("casal %0, %1, [%2]" : "+r"(cmp) : "r"(newv), "r"(w) : "memory");
    CHECK(cmp == 200 && peek64(w) == 200); // failed compare leaves memory alone and returns the current value
    expect("casal miss", RW, 8, 0, 1);
    uint64_t sw = 77;
    __asm__ volatile("swpal %0, %0, [%1]" : "+r"(sw) : "r"(w) : "memory");
    CHECK(sw == 200 && peek64(w) == 77);
    expect("swpal", RW, 8, 0, 1);
    __asm__ volatile("ldar %0, [%1]" : "=&r"(v) : "r"(w) : "memory");
    CHECK(v == 77);
    expect("ldar", R, 8, 0, 1);
    __asm__ volatile("stlrb %w0, [%1]" : : "r"(v), "r"(w + 9) : "memory");
    expect("stlrb", W, 1, 9, 1);
    __asm__ volatile("ldapr %0, [%1]" : "=&r"(v) : "r"(w) : "memory");
    CHECK(v == 77);
    expect("ldapr", R, 8, 0, 1);
    __asm__ volatile("stlur %0, [%1, #-8]" : : "r"(v), "r"(w + 24) : "memory");
    CHECK(peek64(w + 16) == 77);
    expect("stlur", W, 8, 16, 1);
    __asm__ volatile("ldapur %0, [%1, #16]" : "=&r"(v2) : "r"(w) : "memory");
    CHECK(v2 == 77);
    expect("ldapur", R, 8, 16, 1);
    // CASP: 16 bytes compared and swapped as one; the old pair comes back in x0/x1.
    tagwatch_poke(w + 32, &(uint64_t){5}, 8);
    tagwatch_poke(w + 40, &(uint64_t){6}, 8);
    {
        register uint64_t c0 __asm__("x0") = 5, c1 __asm__("x1") = 6;
        register uint64_t n0 __asm__("x2") = 50, n1 __asm__("x3") = 60;
        __asm__ volatile("caspal x0, x1, x2, x3, [%2]" : "+r"(c0), "+r"(c1) : "r"(w + 32), "r"(n0), "r"(n1) : "memory");
        CHECK(c0 == 5 && c1 == 6 && peek64(w + 32) == 50 && peek64(w + 40) == 60);
    }
    expect("caspal", RW, 16, 32, 1);

    // --- LL/SC: emulated as compare-and-swap ---------------------------------------------------
    tagwatch_stats s0, s1;
    tagwatch_get_stats(&s0);
    uint64_t status = 9, loaded = 0;
    tagwatch_poke(w + 16, &(uint64_t){40}, 8);
    __asm__ volatile("1: ldxr %0, [%2]\n"
                     "   add %0, %0, #2\n"
                     "   stxr %w1, %0, [%2]\n"
                     "   cbnz %w1, 1b\n"
                     : "=&r"(loaded), "=&r"(status)
                     : "r"(w + 16)
                     : "memory");
    CHECK(status == 0 && loaded == 42 && peek64(w + 16) == 42);
    CHECK_EQ(mt_count(), 2);
    CHECK(mt_events[0].access == R && (mt_events[0].flags & TAGWATCH_EV_ATOMIC) && mt_events[0].size == 8);
    CHECK(mt_events[1].access == W && (mt_events[1].flags & TAGWATCH_EV_ATOMIC) && mt_events[1].offset == 16);
    mt_reset();
    // A store-exclusive without a matching load must fail, as on real hardware after an exception.
    __asm__ volatile("clrex\n stxr %w0, %1, [%2]" : "=&r"(status) : "r"(v), "r"(w + 16) : "memory");
    CHECK(status == 1 && peek64(w + 16) == 42);
    mt_reset();
    uint32_t l32 = 0;
    tagwatch_poke(w + 24, &(uint32_t){7}, 4);
    __asm__ volatile("1: ldaxr %w0, [%2]\n"
                     "   add %w0, %w0, #1\n"
                     "   stlxr %w1, %w0, [%2]\n"
                     "   cbnz %w1, 1b\n"
                     : "=&r"(l32), "=&r"(status)
                     : "r"(w + 24)
                     : "memory");
    tagwatch_peek(&l32, w + 24, 4);
    CHECK(l32 == 8);
    uint64_t lo = 0, hi = 0;
    tagwatch_poke(w + 32, &(uint64_t){1}, 8);
    tagwatch_poke(w + 40, &(uint64_t){2}, 8);
    __asm__ volatile("1: ldxp %0, %1, [%3]\n"
                     "   add %0, %0, #10\n"
                     "   add %1, %1, #20\n"
                     "   stxp %w2, %0, %1, [%3]\n"
                     "   cbnz %w2, 1b\n"
                     : "=&r"(lo), "=&r"(hi), "=&r"(status)
                     : "r"(w + 32)
                     : "memory");
    CHECK(peek64(w + 32) == 11 && peek64(w + 40) == 22);
    uint32_t lo32 = 0, hi32 = 0, lo0, hi0;
    uint8_t b0;
    tagwatch_peek(&lo0, w + 48, 4);
    tagwatch_peek(&hi0, w + 52, 4);
    tagwatch_peek(&b0, w + 60, 1);
    __asm__ volatile("1: ldaxp %w0, %w1, [%3]\n"
                     "   add %w0, %w0, #1\n"
                     "   add %w1, %w1, #2\n"
                     "   stlxp %w2, %w0, %w1, [%3]\n"
                     "   cbnz %w2, 1b\n"
                     : "=&r"(lo32), "=&r"(hi32), "=&r"(status)
                     : "r"(w + 48)
                     : "memory");
    tagwatch_peek(&lo32, w + 48, 4);
    tagwatch_peek(&hi32, w + 52, 4);
    CHECK(lo32 == lo0 + 1 && hi32 == hi0 + 2);
    uint32_t b8 = 0;
    __asm__ volatile("1: ldxrb %w0, [%2]\n"
                     "   add %w0, %w0, #1\n"
                     "   stxrb %w1, %w0, [%2]\n"
                     "   cbnz %w1, 1b\n"
                     : "=&r"(b8), "=&r"(status)
                     : "r"(w + 60)
                     : "memory");
    CHECK(b8 == (uint8_t)(b0 + 1));
    tagwatch_peek(&b0, w + 60, 1);
    CHECK(b0 == b8);
    tagwatch_get_stats(&s1);
    CHECK_EQ(s1.emulated - s0.emulated, 11);
    mt_reset();
    fill();

    // --- DC ZVA: 64 bytes zeroed by one instruction ------------------------------------------------
    __asm__ volatile("dc zva, %0" : : "r"(w) : "memory");
    expect("dc zva", W, 64, 0, 1);
    CHECK(peek64(w) == 0 && peek64(w + 56) == 0);
    CHECK(peek64(w - 8) != 0 && peek64(w + 64) != 0); // neighbours untouched
    fill();

    // --- accesses that straddle the edge of the watch ----------------------------------------------
    v = 0x1111111111111111ull;
    __asm__ volatile("stur %0, [%1, #-4]" : : "r"(v), "r"(w) : "memory");
    expect("store straddling in", W, 8, -4, 1);
    CHECK((uint32_t)peek64(w - 4) == 0x11111111u && (uint32_t)peek64(w) == 0x11111111u);
    __asm__ volatile("stur %0, [%1, #60]" : : "r"(v), "r"(w) : "memory");
    expect("store straddling out", W, 8, 60, 1);
    __asm__ volatile("ldur %0, [%1, #-7]" : "=&r"(v) : "r"(w) : "memory");
    expect("load straddling in", R, 8, -7, 1);
    // Just outside: no trap.
    __asm__ volatile("ldur %0, [%1, #-8]" : "=&r"(v) : "r"(w) : "memory");
    __asm__ volatile("ldr %0, [%1, #64]" : "=&r"(v) : "r"(w) : "memory");
    CHECK_EQ(mt_count(), 0);
    fill();

    // --- an instruction the decoder does not know: SME, in streaming mode ---------------------------------
    // It is still let through (the slot re-executes whatever faulted); the
    // report falls back to the fault address and the syndrome's direction.
    int sme = 0;
    size_t sme_len = sizeof sme;
    if (sysctlbyname("hw.optional.arm.FEAT_SME", &sme, &sme_len, NULL, 0) == 0 && sme) {
        uint8_t row[64];
        memset(row, 0, sizeof row);
        __asm__ volatile(".arch_extension sme\n"
                         "smstart\n"
                         "ptrue p0.b\n"
                         "mov w12, #0\n"
                         "ld1b {za0h.b[w12, 0]}, p0/z, [%0]\n"
                         "ptrue p0.b, vl32\n" // the window is 64 bytes; the row may be longer
                         "st1b {za0h.b[w12, 0]}, p0, [%1]\n"
                         "smstop\n"
                         :
                         : "r"(w), "r"(row)
                         : "memory", "x12", "p0");
        // Only the first 32 bytes were stored back; the load covered the vector length.
        for (int i = 0; i < 32; i++) CHECK(row[i] == (uint8_t)(w - blk + i));
        CHECK(mt_count() >= 1);
        if (mt_count() >= 1) CHECK(mt_events[0].access == R && mt_events[0].size == 1 && mt_events[0].offset >= 0);
        mt_reset();
    }

    // --- code in system libraries ----------------------------------------------------------------------
    uint8_t copy[64], ref[64];
    for (int i = 0; i < 64; i++) ref[i] = (uint8_t)(w - blk + i);
    memcpy(copy, w, 64);
    CHECK(mt_count() >= 1 && memcmp(copy, ref, 64) == 0);
    for (int i = 0; i < mt_count(); i++) CHECK(mt_events[i].access == R && mt_events[i].nframes >= 2);
    mt_reset();
    memset(w, 0xaa, 64);
    CHECK(mt_count() >= 1);
    tagwatch_peek(copy, w, 64);
    for (int i = 0; i < 64; i++) CHECK(copy[i] == 0xaa);
    mt_reset();
    tagwatch_poke(w, "hello, world", 13);
    CHECK(strlen((const char *)w) == 12);
    CHECK(mt_count() >= 1);
    mt_reset();
    // zlib computes over the buffer in its own code, far from this binary.
    fill();
    uLong crc_watched = crc32(0, w, 64), crc_ref = crc32(0, ref, 64);
    CHECK(crc_watched == crc_ref);
    CHECK(mt_count() >= 1);
    tagwatch_get_stats(&s1);
    printf("     (libz crc32 over the watched window: %d traps; %llu traps so far took the slow return path)\n", mt_count(),
           (unsigned long long)s1.far_traps);
    CHECK(s1.violations == 0);
    free(blk);
    return mt_done();
}

// Decoder tests against encodings produced by the real assembler: the
// instruction words live in tw_vec_code (generated from insn_vectors.def and
// linked into this test), the expectations come from the same file.
#include "../../src/insn.h"
#include "t.h"

extern const uint32_t tw_vec_code[];

#define R TW_ACC_READ
#define W TW_ACC_WRITE
#define RW TW_ACC_RW
#define NONE TW_ACC_NONE
#define X(n) (regs[n])
#define SP (sp)
#define STRIP(a) ((uint64_t)(a) & 0x00ffffffffffffffull)

int main(void) {
    uint64_t regs[31], sp = 0x7fff0000;
    for (int i = 0; i < 31; i++) regs[i] = 0x100000ull * (uint64_t)(i + 1) + (uint64_t)i;
    regs[2] = 0xffffffff80000010ull; // negative as a 32-bit index, large as 64-bit

    static const struct {
        const char *text;
        unsigned access;
        unsigned size;
    } meta[] = {
#define V(text, access, size, ea) {text, access, size},
#include "insn_vectors.def"
#undef V
    };
    const uint64_t ea[] = {
#define V(text, access, size, ea) STRIP(ea),
#include "insn_vectors.def"
#undef V
    };
    int n = (int)(sizeof meta / sizeof meta[0]);
    for (int i = 0; i < n; i++) {
        tw_insn d;
        int ok = tw_insn_decode(tw_vec_code[i], &d);
        if (meta[i].access == NONE) {
            if (ok) fprintf(stderr, "  vector %d '%s' (%08x) decoded as an access\n", i, meta[i].text, tw_vec_code[i]);
            CHECK(!ok);
            continue;
        }
        if (!ok || d.access != meta[i].access || d.size != meta[i].size)
            fprintf(stderr, "  vector %d '%s' (%08x): ok=%d access=%u size=%u\n", i, meta[i].text, tw_vec_code[i], ok, d.access,
                    d.size);
        CHECK(ok);
        CHECK_EQ(d.access, meta[i].access);
        CHECK_EQ(d.size, meta[i].size);
        uint64_t got = tw_insn_ea(&d, regs, sp);
        if (got != ea[i]) fprintf(stderr, "  vector %d '%s': ea %#llx, expected %#llx\n", i, meta[i].text, (unsigned long long)got, (unsigned long long)ea[i]);
        CHECK(got == ea[i]);
    }

    // Exclusive classification drives the LL/SC emulation in the handler.
    tw_insn d;
    for (int i = 0; i < n; i++) {
        tw_insn_decode(tw_vec_code[i], &d);
        int is_ldx = !strncmp(meta[i].text, "ldx", 3) || !strncmp(meta[i].text, "ldax", 4);
        int is_stx = !strncmp(meta[i].text, "stx", 3) || !strncmp(meta[i].text, "stlx", 4);
        CHECK_EQ(d.excl, is_ldx ? TW_EXCL_LOAD : is_stx ? TW_EXCL_STORE : TW_EXCL_NONE);
        if (is_ldx || is_stx) CHECK_EQ(d.pair, meta[i].text[3] == 'p' || meta[i].text[4] == 'p');
    }

    // Robustness: the decoder must accept any 32-bit word without misbehaving,
    // and whatever it accepts must have a sane width.
    uint64_t st = t_seed(0x696e736e64656321ull);
    for (int i = 0; i < 2000000; i++) {
        uint32_t w = (uint32_t)t_rand(&st);
        if (tw_insn_decode(w, &d)) {
            CHECK(d.size >= 1 && d.size <= 64);
            CHECK(d.access >= TW_ACC_READ && d.access <= TW_ACC_RW);
            CHECK(d.rn <= 31 && d.rm <= 31);
            (void)tw_insn_ea(&d, regs, sp);
        } else {
            CHECK(d.access == TW_ACC_NONE);
        }
    }
    CHECK_STR(tw_access_name(TW_ACC_READ), "read");
    CHECK_STR(tw_access_name(TW_ACC_WRITE), "write");
    CHECK_STR(tw_access_name(TW_ACC_RW), "rw");
    return t_done("insn");
}

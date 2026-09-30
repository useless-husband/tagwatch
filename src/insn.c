#include "insn.h"

#include <string.h>

#define BITS(w, hi, lo) (((w) >> (lo)) & ((1u << ((hi) - (lo) + 1)) - 1))
#define BIT(w, n) (((w) >> (n)) & 1u)

static int64_t sext(uint32_t v, unsigned bits) {
    uint64_t m = 1ull << (bits - 1);
    return (int64_t)((v ^ m) - m);
}

const char *tw_access_name(unsigned access) {
    switch (access) {
    case TW_ACC_READ: return "read";
    case TW_ACC_WRITE: return "write";
    case TW_ACC_RW: return "rw";
    default: return "?";
    }
}

// size/V/opc -> direction and width for the "load/store register" family.
// Returns 0 for prefetch and unallocated encodings.
static int reg_kind(uint32_t size, uint32_t v, uint32_t opc, tw_insn *o, unsigned *scale) {
    if (v) {
        if (opc == 0 || opc == 1) {
            o->size = (uint16_t)(1u << size);
            *scale = size;
        } else {
            if (size != 0) return 0;
            o->size = 16;
            *scale = 4;
        }
        o->access = (opc & 1) ? TW_ACC_READ : TW_ACC_WRITE;
        return 1;
    }
    *scale = size;
    o->size = (uint16_t)(1u << size);
    switch (opc) {
    case 0: o->access = TW_ACC_WRITE; return 1;
    case 1: o->access = TW_ACC_READ; return 1;
    case 2:
        if (size == 3) return 0; // PRFM
        o->access = TW_ACC_READ; // LDRSB/LDRSH/LDRSW to X
        return 1;
    default:
        if (size >= 2) return 0;
        o->access = TW_ACC_READ; // LDRSB/LDRSH to W
        return 1;
    }
}

static int decode_simd(uint32_t w, tw_insn *o) {
    // Advanced SIMD load/store structures: 0 Q 0011 0x ...
    if (BIT(w, 31)) return 0;
    uint32_t q = BIT(w, 30), op2 = BITS(w, 24, 23), l = BIT(w, 22);
    o->rn = (uint8_t)BITS(w, 9, 5);
    o->rt = (uint8_t)BITS(w, 4, 0);
    o->ea_mode = TW_EA_BASE_IMM;
    o->imm = 0;
    o->access = l ? TW_ACC_READ : TW_ACC_WRITE;
    if (op2 == 0 || op2 == 1) { // multiple structures (op2==1: post-index)
        if (op2 == 0 && BITS(w, 21, 16) != 0) return 0;
        if (op2 == 1 && BIT(w, 21)) return 0;
        unsigned regs;
        switch (BITS(w, 15, 12)) {
        case 0x0: regs = 4; break; // LD4/ST4
        case 0x2: regs = 4; break; // LD1/ST1, four registers
        case 0x4: regs = 3; break; // LD3/ST3
        case 0x6: regs = 3; break; // LD1/ST1, three registers
        case 0x7: regs = 1; break; // LD1/ST1, one register
        case 0x8: regs = 2; break; // LD2/ST2
        case 0xa: regs = 2; break; // LD1/ST1, two registers
        default: return 0;
        }
        o->size = (uint16_t)(regs * (q ? 16 : 8));
        return 1;
    }
    // single structure (op2==3: post-index)
    if (op2 == 2 && BITS(w, 20, 16) != 0) return 0;
    uint32_t r = BIT(w, 21), opcode = BITS(w, 15, 13), s = BIT(w, 12), size = BITS(w, 11, 10);
    unsigned selem = (((opcode & 1) << 1) | r) + 1;
    unsigned scale = opcode >> 1;
    unsigned esize;
    switch (scale) {
    case 0: esize = 1; break;
    case 1:
        if (size & 1) return 0;
        esize = 2;
        break;
    case 2:
        if ((size & 2) != 0) return 0;
        if ((size & 1) == 0) {
            esize = 4;
        } else {
            if (s) return 0;
            esize = 8;
        }
        break;
    default: // LDnR: load one element and replicate
        if (!l || s) return 0;
        esize = 1u << size;
        break;
    }
    o->size = (uint16_t)(selem * esize);
    return 1;
}

static int decode_excl(uint32_t w, tw_insn *o) {
    // size 001000 o2 L o1 Rs o0 Rt2 Rn Rt
    uint32_t size = BITS(w, 31, 30), o2 = BIT(w, 23), l = BIT(w, 22), o1 = BIT(w, 21);
    o->rs = (uint8_t)BITS(w, 20, 16);
    o->rt2 = (uint8_t)BITS(w, 14, 10);
    o->rn = (uint8_t)BITS(w, 9, 5);
    o->rt = (uint8_t)BITS(w, 4, 0);
    o->ea_mode = TW_EA_BASE_IMM;
    o->imm = 0;
    if (!o2 && !o1) { // STXR / LDXR (and the acquire/release forms)
        o->size = (uint16_t)(1u << size);
        o->access = l ? TW_ACC_READ : TW_ACC_WRITE;
        o->excl = l ? TW_EXCL_LOAD : TW_EXCL_STORE;
        return 1;
    }
    if (!o2 && o1) {
        if (BIT(w, 31)) { // STXP / LDXP
            o->size = (uint16_t)(2u << (2 + BIT(w, 30)));
            o->access = l ? TW_ACC_READ : TW_ACC_WRITE;
            o->excl = l ? TW_EXCL_LOAD : TW_EXCL_STORE;
            o->pair = 1;
            return 1;
        }
        if (o->rt2 != 31) return 0;
        o->size = (uint16_t)(2u << (2 + BIT(w, 30))); // CASP
        o->access = TW_ACC_RW;
        return 1;
    }
    if (o2 && !o1) { // STLR / LDAR / STLLR / LDLAR
        o->size = (uint16_t)(1u << size);
        o->access = l ? TW_ACC_READ : TW_ACC_WRITE;
        return 1;
    }
    if (o->rt2 != 31) return 0;
    o->size = (uint16_t)(1u << size); // CAS
    o->access = TW_ACC_RW;
    return 1;
}

static int decode(uint32_t w, tw_insn *o) {
    // DC ZVA, Xt
    if ((w & 0xffffffe0u) == 0xd50b7420u) {
        o->access = TW_ACC_WRITE;
        o->size = 64;
        o->ea_mode = TW_EA_ZVA;
        o->rn = (uint8_t)BITS(w, 4, 0);
        return 1;
    }
    // Loads and stores: op0 (bits 28:25) = x1x0
    if ((w & 0x0a000000u) != 0x08000000u) return 0;
    uint32_t top = BITS(w, 29, 28), v = BIT(w, 26), b24 = BIT(w, 24);
    uint32_t size = BITS(w, 31, 30), opc = BITS(w, 23, 22);
    unsigned scale = 0;

    switch (top) {
    case 0:
        if (v) return decode_simd(w, o);
        if (b24) return 0;
        return decode_excl(w, o);
    case 1:
        if (!b24) return 0; // load literal: never tag-checked
        if (v || BIT(w, 21) || BITS(w, 11, 10) != 0) return 0; // memory-tag instructions are unchecked
        // LDAPUR / STLUR (unscaled, RCPC)
        o->rn = (uint8_t)BITS(w, 9, 5);
        o->rt = (uint8_t)BITS(w, 4, 0);
        o->imm = sext(BITS(w, 20, 12), 9);
        o->ea_mode = TW_EA_BASE_IMM;
        o->size = (uint16_t)(1u << size);
        if (opc == 0) o->access = TW_ACC_WRITE;
        else if (opc == 1) o->access = TW_ACC_READ;
        else if (opc == 2 && size != 3) o->access = TW_ACC_READ;
        else if (opc == 3 && size < 2) o->access = TW_ACC_READ;
        else return 0;
        return 1;
    case 2: { // load/store pair
        uint32_t popc = BITS(w, 31, 30), l = BIT(w, 22), type = BITS(w, 24, 23);
        o->rn = (uint8_t)BITS(w, 9, 5);
        o->rt = (uint8_t)BITS(w, 4, 0);
        o->rt2 = (uint8_t)BITS(w, 14, 10);
        if (v) {
            if (popc == 3) return 0;
            scale = 2 + popc;
        } else {
            if (popc == 3) return 0;
            if (popc == 1 && !l) return 0; // STGP writes the tag itself: unchecked
            scale = 2 + (popc >> 1);
        }
        o->size = (uint16_t)(2u << scale);
        o->access = l ? TW_ACC_READ : TW_ACC_WRITE;
        o->ea_mode = TW_EA_BASE_IMM;
        o->imm = type == 1 ? 0 : sext(BITS(w, 21, 15), 7) * (1 << scale);
        return 1;
    }
    default:
        break;
    }

    // top == 3: load/store register
    o->rn = (uint8_t)BITS(w, 9, 5);
    o->rt = (uint8_t)BITS(w, 4, 0);
    if (b24) { // unsigned scaled immediate
        if (!reg_kind(size, v, opc, o, &scale)) return 0;
        o->ea_mode = TW_EA_BASE_IMM;
        o->imm = (int64_t)BITS(w, 21, 10) << scale;
        return 1;
    }
    if (!BIT(w, 21)) { // imm9: unscaled / post-index / unprivileged / pre-index
        if (!reg_kind(size, v, opc, o, &scale)) return 0;
        o->ea_mode = TW_EA_BASE_IMM;
        o->imm = BITS(w, 11, 10) == 1 ? 0 : sext(BITS(w, 20, 12), 9);
        return 1;
    }
    switch (BITS(w, 11, 10)) {
    case 0: // atomic memory operations (LDADD, LDCLR, LDEOR, LDSET, LDSMAX, ..., SWP)
        if (v) return 0;
        o->rs = (uint8_t)BITS(w, 20, 16);
        o->size = (uint16_t)(1u << size);
        o->ea_mode = TW_EA_BASE_IMM;
        if (!BIT(w, 15) || BITS(w, 14, 12) == 0) { // LDADD..LDUMIN, or SWP
            o->access = TW_ACC_RW;
            return 1;
        }
        if (BITS(w, 14, 12) == 4 && opc == 2 && o->rs == 31) { // LDAPR
            o->access = TW_ACC_READ;
            return 1;
        }
        return 0; // ST64B and friends: not generated for user code on this platform
    case 2: { // register offset
        if (!reg_kind(size, v, opc, o, &scale)) return 0;
        uint32_t option = BITS(w, 15, 13);
        if (!(option & 2)) return 0;
        o->ea_mode = TW_EA_BASE_REG;
        o->rm = (uint8_t)BITS(w, 20, 16);
        o->ext = (uint8_t)option;
        o->shift = (uint8_t)(BIT(w, 12) ? scale : 0);
        return 1;
    }
    default: // LDRAA / LDRAB
        if (size != 3 || v) return 0;
        o->size = 8;
        o->access = TW_ACC_READ;
        o->ea_mode = TW_EA_UNKNOWN;
        o->imm = sext((BIT(w, 22) << 9) | BITS(w, 20, 12), 10) * 8;
        return 1;
    }
}

int tw_insn_decode(uint32_t word, tw_insn *out) {
    memset(out, 0, sizeof *out);
    if (decode(word, out)) return 1;
    memset(out, 0, sizeof *out); // a rejected word leaves no partial description behind
    return 0;
}

uint64_t tw_insn_ea(const tw_insn *in, const uint64_t x[31], uint64_t sp) {
    const uint64_t strip = 0x00ffffffffffffffull;
    uint64_t base = in->rn == 31 ? sp : x[in->rn];
    switch (in->ea_mode) {
    case TW_EA_BASE_IMM: return (base + (uint64_t)in->imm) & strip;
    case TW_EA_BASE_REG: {
        uint64_t idx = in->rm == 31 ? 0 : x[in->rm];
        switch (in->ext) {
        case 2: idx = (uint32_t)idx; break;                   // UXTW
        case 6: idx = (uint64_t)(int64_t)(int32_t)idx; break; // SXTW
        default: break;                                       // LSL / SXTX
        }
        return (base + (idx << in->shift)) & strip;
    }
    case TW_EA_ZVA: return in->rn == 31 ? 0 : (x[in->rn] & strip) & ~63ull;
    default: return 0;
    }
}

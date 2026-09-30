// insn: decode the AArch64 instructions that can take an MTE tag-check fault.
//
// tagwatch never needs the decoder to let an access proceed (the instruction
// is re-executed out of line, see tramp.h). The decoder is used to describe
// the access in the log: exact effective address, width, and direction.
// It also recognises LDXR/STXR, which are the one family that cannot simply
// be re-executed (see exc.c).
#ifndef TW_INSN_H
#define TW_INSN_H

#include <stdint.h>

enum {
    TW_ACC_NONE = 0,  // not a tag-checked memory access (or not recognised)
    TW_ACC_READ = 1,
    TW_ACC_WRITE = 2,
    TW_ACC_RW = 3,    // atomic read-modify-write (CAS, SWP, LDADD, ...)
};

enum {
    TW_EA_BASE_IMM = 0, // Xn + imm (imm is 0 for post-indexed forms)
    TW_EA_BASE_REG,     // Xn + extend(Rm) << shift
    TW_EA_ZVA,          // Xt & ~63 (DC ZVA)
    TW_EA_UNKNOWN,      // pointer-authenticated base: use the fault address
};

enum {
    TW_EXCL_NONE = 0,
    TW_EXCL_LOAD,  // LDXR / LDAXR / LDXP / LDAXP
    TW_EXCL_STORE, // STXR / STLXR / STXP / STLXP
};

typedef struct {
    uint8_t access; // TW_ACC_*
    uint8_t ea_mode;
    uint8_t excl;   // TW_EXCL_*
    uint8_t pair;   // exclusive pair (two registers)
    uint16_t size;  // bytes touched
    uint8_t rn;     // base register, 31 = SP
    uint8_t rm;     // index register for TW_EA_BASE_REG, 31 = XZR
    uint8_t ext;    // extend option bits for TW_EA_BASE_REG
    uint8_t shift;  // left shift applied to the index
    uint8_t rt;     // first data register
    uint8_t rt2;    // second data register (pairs)
    uint8_t rs;     // status register (store-exclusive)
    int64_t imm;
} tw_insn;

// Returns 1 if the word is a recognised tag-checked memory access.
int tw_insn_decode(uint32_t word, tw_insn *out);

// Effective address of the access given the general registers at the fault.
// x[0..30] are X0..X30; the top byte is cleared from the result. Returns 0
// when the address cannot be computed from the registers (TW_EA_UNKNOWN).
uint64_t tw_insn_ea(const tw_insn *in, const uint64_t x[31], uint64_t sp);

const char *tw_access_name(unsigned access); // "read" / "write" / "rw" / "?"

#endif

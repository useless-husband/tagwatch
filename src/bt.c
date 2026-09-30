// bt: frame-pointer backtraces.
//
// Apple's arm64 ABI keeps a frame record {caller's x29, return address} at
// x29 in every non-leaf function, so walking the chain is reliable. The one
// subtlety is frame 0: a leaf function (memcpy and friends, where many
// interesting writes happen) has no record of its own, and its caller is
// only in x30. Whether the function at pc is such a leaf is read from its
// compact unwind encoding.
#include <pthread.h>

#include "internal.h"
#include "symtab.h"

static int readable_frame(uint64_t fp, uint64_t lo, uint64_t hi) {
    return fp >= lo && fp + 16 <= hi && (fp & 7) == 0;
}

unsigned tw_backtrace(uint64_t pc, uint64_t lr, uint64_t fp, uint64_t stack_lo, uint64_t stack_hi, uint64_t *frames,
                      unsigned max) {
    unsigned n = 0;
    if (max == 0) return 0;
    frames[n++] = pc & TW_VA_MASK;
    lr &= TW_VA_MASK;
    uint64_t saved_lr = 0;
    if (readable_frame(fp, stack_lo, stack_hi)) saved_lr = ((const uint64_t *)(uintptr_t)fp)[1] & TW_VA_MASK;
    int mode = tw_unwind_mode(pc & TW_VA_MASK);
    int lr_is_caller;
    switch (mode) {
    case TW_UNW_FRAME: lr_is_caller = 0; break;
    case TW_UNW_FRAMELESS:
    case TW_UNW_NONE: lr_is_caller = 1; break;
    default: lr_is_caller = lr != saved_lr && tw_addr_is_code(lr); break; // no unwind info: best effort
    }
    if (lr_is_caller && lr && n < max) frames[n++] = lr;
    while (n < max && readable_frame(fp, stack_lo, stack_hi)) {
        const uint64_t *rec = (const uint64_t *)(uintptr_t)fp;
        uint64_t next = rec[0], ret = rec[1] & TW_VA_MASK;
        if (!ret) break;
        frames[n++] = ret;
        if (next <= fp) break; // frames must move towards the stack base
        fp = next;
    }
    return n;
}

unsigned tw_backtrace_fp(const void *frame, uint64_t *frames, unsigned max) {
    pthread_t self = pthread_self();
    uint64_t hi = (uint64_t)(uintptr_t)pthread_get_stackaddr_np(self);
    uint64_t lo = hi - pthread_get_stacksize_np(self);
    uint64_t fp = (uint64_t)(uintptr_t)frame;
    unsigned n = 0;
    while (n < max && readable_frame(fp, lo, hi)) {
        const uint64_t *rec = (const uint64_t *)(uintptr_t)fp;
        uint64_t next = rec[0], ret = rec[1] & TW_VA_MASK;
        if (!ret) break;
        frames[n++] = ret;
        if (next <= fp) break;
        fp = next;
    }
    return n;
}

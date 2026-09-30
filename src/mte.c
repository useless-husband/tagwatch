// The only translation unit that contains MTE instructions. It is compiled
// with -march=armv8.5-a+memtag; nothing here runs unless
// tw_mte_process_enabled() returned 1, so the library still loads (and stays
// passive) on CPUs without MTE.
#include <mach/mach_vm.h>
#include <sys/sysctl.h>

#include "internal.h"

#ifndef VM_FLAGS_MTE
#define VM_FLAGS_MTE 0x00002000
#endif

// stg and ldg with a fault fix-up. If the address is unmapped, or (for stg)
// not in an MTE mapping, the instruction raises a fault; the exception
// thread then resumes the caller at the matching *_fail label instead (see
// tw_mte_recover_pc), and the function returns an error.
__asm__(".text\n"
        ".p2align 2\n"
        ".private_extern _tw_mte_try_stg\n"
        ".private_extern _tw_mte_try_stg_insn\n"
        ".private_extern _tw_mte_try_stg_fail\n"
        "_tw_mte_try_stg:\n"
        "_tw_mte_try_stg_insn:\n"
        "    stg x0, [x0]\n"
        "    mov w0, #0\n"
        "    ret\n"
        "_tw_mte_try_stg_fail:\n"
        "    mov w0, #1\n"
        "    ret\n"
        ".private_extern _tw_mte_try_ldg\n"
        ".private_extern _tw_mte_try_ldg_insn\n"
        ".private_extern _tw_mte_try_ldg_fail\n"
        "_tw_mte_try_ldg:\n"
        "_tw_mte_try_ldg_insn:\n"
        "    ldg x0, [x0]\n"
        "    ubfx x0, x0, #56, #4\n"
        "    ret\n"
        "_tw_mte_try_ldg_fail:\n"
        "    mov x0, #-1\n"
        "    ret\n");

extern int tw_mte_try_stg(uint64_t tagged);
extern int64_t tw_mte_try_ldg(uint64_t addr);
extern const char tw_mte_try_stg_insn[], tw_mte_try_stg_fail[], tw_mte_try_ldg_insn[], tw_mte_try_ldg_fail[];

static inline uint64_t with_tag(uint64_t addr, unsigned tag) {
    return (addr & TW_ADDR_MASK & ~TW_GRANULE_MASK) | ((uint64_t)(tag & 0xf) << 56);
}

int tw_mte_process_enabled(void) {
    static int cached = -1;
    if (cached >= 0) return cached;
    int hw = 0;
    size_t len = sizeof hw;
    if (sysctlbyname("hw.optional.arm.FEAT_MTE", &hw, &len, NULL, 0) != 0 || !hw) return cached = 0;
    // The kernel accepts VM_FLAGS_MTE only from tasks that run with MTE on.
    mach_vm_address_t addr = 0;
    kern_return_t kr = mach_vm_map(mach_task_self(), &addr, 1 << 14, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE, MACH_PORT_NULL, 0,
                                   FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_DEFAULT);
    if (kr != KERN_SUCCESS) return cached = 0;
    mach_vm_deallocate(mach_task_self(), addr, 1 << 14);
    return cached = 1;
}

unsigned tw_mte_get_tag(uint64_t addr) {
    uint64_t p = addr & TW_ADDR_MASK & ~TW_GRANULE_MASK;
    __asm__ volatile("ldg %0, [%0]" : "+r"(p));
    return (unsigned)(p >> 56) & 0xf;
}

void tw_mte_set_tag(uint64_t addr, unsigned tag) {
    uint64_t p = with_tag(addr, tag);
    __asm__ volatile("stg %0, [%0]" : : "r"(p) : "memory");
}

int tw_mte_try_set_tag(uint64_t addr, unsigned tag) { return tw_mte_try_stg(with_tag(addr, tag)) ? -1 : 0; }

int tw_mte_try_get_tag(uint64_t addr) { return (int)tw_mte_try_ldg(addr & TW_ADDR_MASK & ~TW_GRANULE_MASK); }

uint64_t tw_mte_recover_pc(uint64_t pc) {
    if (pc == (uint64_t)(uintptr_t)tw_mte_try_stg_insn) return (uint64_t)(uintptr_t)tw_mte_try_stg_fail;
    if (pc == (uint64_t)(uintptr_t)tw_mte_try_ldg_insn) return (uint64_t)(uintptr_t)tw_mte_try_ldg_fail;
    return 0;
}

uint64_t tw_tco_save_and_set(void) {
    uint64_t old;
    __asm__ volatile("mrs %0, tco" : "=r"(old));
    __asm__ volatile("msr tco, #1");
    return old;
}

void tw_tco_restore(uint64_t saved) { __asm__ volatile("msr tco, %0" : : "r"(saved)); }

void tw_tco_force(int on) {
    if (on) __asm__ volatile("msr tco, #1");
    else __asm__ volatile("msr tco, #0");
}

int tw_tco_is_set(void) {
    uint64_t v;
    __asm__ volatile("mrs %0, tco" : "=r"(v));
    return (v >> 25) & 1;
}

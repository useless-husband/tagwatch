// Page-granular memory straight from the kernel. The runtime cannot use
// malloc for its own bookkeeping: it interposes malloc, and its fault handler
// runs while program threads may hold the allocator's locks.
#include <mach/mach_vm.h>

#include "internal.h"

#ifndef VM_FLAGS_MTE
#define VM_FLAGS_MTE 0x00002000
#endif

static size_t tw_round_page(size_t n) { return (n + TW_PAGE_SIZE - 1) & ~(size_t)(TW_PAGE_SIZE - 1); }

void *tw_vm_alloc(size_t size) {
    mach_vm_address_t addr = 0;
    if (size == 0) return NULL;
    if (mach_vm_allocate(mach_task_self(), &addr, tw_round_page(size), VM_FLAGS_ANYWHERE) != KERN_SUCCESS) return NULL;
    return (void *)(uintptr_t)addr;
}

void tw_vm_free(void *p, size_t size) {
    if (p) mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)(uintptr_t)p, tw_round_page(size));
}

void *tw_vm_alloc_mte(size_t size) {
    mach_vm_address_t addr = 0;
    if (size == 0) return NULL;
    kern_return_t kr = mach_vm_map(mach_task_self(), &addr, tw_round_page(size), 0, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE,
                                   MACH_PORT_NULL, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE,
                                   VM_INHERIT_DEFAULT);
    return kr == KERN_SUCCESS ? (void *)(uintptr_t)addr : NULL;
}

// The watch table asks for 4 KB cell arrays at a high rate when many small
// objects are watched; carve those out of 16 KB pages and recycle them.
#define SMALL 4096
static os_unfair_lock small_lock = OS_UNFAIR_LOCK_INIT;
static void *small_free; // singly linked through the first word

static void *mem_alloc(size_t size) {
    if (size != SMALL) return tw_vm_alloc(size);
    os_unfair_lock_lock(&small_lock);
    if (!small_free) {
        char *page = tw_vm_alloc(64 * SMALL);
        if (page)
            for (int i = 0; i < 64; i++) {
                *(void **)(void *)(page + i * SMALL) = small_free;
                small_free = page + i * SMALL;
            }
    }
    void *p = small_free;
    if (p) {
        small_free = *(void **)p;
        *(void **)p = NULL; // blocks are handed out zero-filled
    }
    os_unfair_lock_unlock(&small_lock);
    return p;
}

static void mem_release(void *p, size_t size) {
    if (size != SMALL) {
        tw_vm_free(p, size);
        return;
    }
    __builtin_memset(p, 0, SMALL);
    os_unfair_lock_lock(&small_lock);
    *(void **)p = small_free;
    small_free = p;
    os_unfair_lock_unlock(&small_lock);
}

const tw_mem tw_vm_mem = {mem_alloc, mem_release};

// adopt: make ordinary memory taggable.
//
// MTE tags only exist for pages in MTE-enabled mappings. Globals live in the
// image's __DATA segment, thread stacks in plain anonymous memory, and the
// system allocator does not tag large blocks; none of those can be armed as
// they are. Adoption replaces such pages, in place, with fresh MTE-enabled
// pages holding the same bytes. Addresses do not change and the new pages
// carry tag 0, which is what the program's untagged pointers expect.
//
// The replacement is not atomic (map, then copy back), so every other thread
// is suspended while it happens.
#include <mach/mach_vm.h>
#include <pthread.h>
#include <string.h>

#include "internal.h"

#ifndef VM_FLAGS_MTE
#define VM_FLAGS_MTE 0x00002000
#endif

static int page_is_taggable(uint64_t page) {
    // Storing the tag a granule already has changes nothing, and fails
    // (recoverably) exactly when the page is not an MTE mapping.
    return tw_mte_try_set_tag(page, tw_mte_get_tag(page)) == 0;
}

static kern_return_t region_prot(uint64_t addr, vm_prot_t *prot, vm_prot_t *max_prot) {
    mach_vm_address_t a = addr;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(mach_task_self(), &a, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj);
    if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);
    if (kr != KERN_SUCCESS) return kr;
    if (a > addr) return KERN_INVALID_ADDRESS; // addr is in a hole
    *prot = info.protection;
    *max_prot = info.max_protection;
    return KERN_SUCCESS;
}

static void all_other_threads(int suspend) {
    thread_act_array_t list = NULL;
    mach_msg_type_number_t n = 0;
    if (task_threads(mach_task_self(), &list, &n) != KERN_SUCCESS) return;
    thread_t self = mach_thread_self();
    for (mach_msg_type_number_t i = 0; i < n; i++) {
        if (list[i] != self) {
            if (suspend) thread_suspend(list[i]);
            else thread_resume(list[i]);
        }
        mach_port_deallocate(mach_task_self(), list[i]);
    }
    mach_port_deallocate(mach_task_self(), self);
    mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)(uintptr_t)list, n * sizeof *list);
}

int tw_adopt(uint64_t addr, uint64_t len) {
    addr &= TW_ADDR_MASK;
    if (len == 0 || addr + len < addr) return -TAGWATCH_EINVAL;
    uint64_t lo = addr & ~(TW_PAGE_SIZE - 1), hi = (addr + len + TW_PAGE_SIZE - 1) & ~(TW_PAGE_SIZE - 1);

    // The copy-back below runs on this thread's stack; it cannot pull its own
    // stack out from under itself. (Another thread can adopt it for us.)
    pthread_t me = pthread_self();
    uint64_t stack_hi = (uint64_t)(uintptr_t)pthread_get_stackaddr_np(me);
    uint64_t stack_lo = stack_hi - pthread_get_stacksize_np(me);

    // Pass 1, with the process running: find the pages that need replacing
    // and check that they can be. (The taggability probe relies on the
    // exception thread, so it must not run while the world is stopped.)
    uint64_t npages = (hi - lo) >> TW_PAGE_SHIFT, todo = 0;
    uint8_t *plan = tw_vm_alloc(npages); // per page: 0 = leave, else 1 + protection
    if (!plan) return -TAGWATCH_ENOMEM;
    int rc = 0;
    for (uint64_t i = 0; i < npages && rc == 0; i++) {
        uint64_t page = lo + (i << TW_PAGE_SHIFT);
        if (page_is_taggable(page)) continue;
        vm_prot_t prot, max_prot;
        if (region_prot(page, &prot, &max_prot) != KERN_SUCCESS) rc = -TAGWATCH_EINVAL; // not mapped
        else if ((prot & VM_PROT_EXECUTE) || !(prot & VM_PROT_READ) || (page < stack_hi && page + TW_PAGE_SIZE > stack_lo))
            rc = -TAGWATCH_ENOTTAGGED; // code, unreadable memory, or our own stack
        else {
            plan[i] = (uint8_t)(1 + (prot & 7));
            todo++;
        }
    }
    void *tmp = NULL;
    if (rc == 0 && todo && !(tmp = tw_vm_alloc(TW_PAGE_SIZE))) rc = -TAGWATCH_ENOMEM;
    if (rc != 0 || todo == 0) {
        tw_vm_free(plan, npages);
        return rc;
    }

    // Pass 2, with every other thread suspended: nothing here takes a lock.
    all_other_threads(1);
    for (uint64_t i = 0; i < npages; i++) {
        if (!plan[i]) continue;
        uint64_t page = lo + (i << TW_PAGE_SHIFT);
        vm_prot_t prot = (vm_prot_t)(plan[i] - 1);
        memcpy(tmp, (const void *)(uintptr_t)page, TW_PAGE_SIZE);
        mach_vm_address_t a = page;
        kern_return_t kr = mach_vm_map(mach_task_self(), &a, TW_PAGE_SIZE, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_FLAGS_MTE,
                                       MACH_PORT_NULL, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE,
                                       VM_INHERIT_DEFAULT);
        if (kr != KERN_SUCCESS) {
            rc = -TAGWATCH_ENOTTAGGED; // e.g. inside the dyld shared region; the old page is untouched
            break;
        }
        memcpy((void *)(uintptr_t)page, tmp, TW_PAGE_SIZE);
        if (!(prot & VM_PROT_WRITE)) mach_vm_protect(mach_task_self(), page, TW_PAGE_SIZE, FALSE, prot);
    }
    all_other_threads(0);
    tw_vm_free(tmp, TW_PAGE_SIZE);
    tw_vm_free(plan, npages);
    return rc;
}

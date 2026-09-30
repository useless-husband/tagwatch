// Shared by the comparison baselines (pagewatch, hwwatch, naive_step): an
// in-process Mach exception server and the single-step switch, i.e. the
// plumbing a debugger uses, without a debugger.
#ifndef BENCH_EXCPORT_H
#define BENCH_EXCPORT_H

#include <mach/mach.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#pragma pack(push, 4)
typedef struct {
    mach_msg_header_t head;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t ndr;
    exception_type_t exception;
    mach_msg_type_number_t code_count;
    int64_t code[2];
    char trailer[128];
} bx_request;
typedef struct {
    mach_msg_header_t head;
    NDR_record_t ndr;
    kern_return_t ret;
} bx_reply;
#pragma pack(pop)

// Returns KERN_SUCCESS to resume the thread, anything else to pass the exception on.
typedef kern_return_t (*bx_handler)(thread_t thread, exception_type_t exception, int64_t code0, int64_t code1);

static mach_port_t bx_port;
static bx_handler bx_fn;

static inline kern_return_t bx_single_step(thread_t th, int on) {
    arm_debug_state64_t ds;
    mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
    kern_return_t kr = thread_get_state(th, ARM_DEBUG_STATE64, (thread_state_t)&ds, &cnt);
    if (kr) return kr;
    if (on) ds.__mdscr_el1 |= 1;
    else ds.__mdscr_el1 &= ~1ull;
    return thread_set_state(th, ARM_DEBUG_STATE64, (thread_state_t)&ds, ARM_DEBUG_STATE64_COUNT);
}

static void *bx_main(void *arg) {
    (void)arg;
    for (;;) {
        bx_request rq;
        if (mach_msg(&rq.head, MACH_RCV_MSG, 0, sizeof rq, bx_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) != KERN_SUCCESS) return NULL;
        bx_reply rp;
        memset(&rp, 0, sizeof rp);
        rp.head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(rq.head.msgh_bits), 0);
        rp.head.msgh_size = sizeof rp;
        rp.head.msgh_remote_port = rq.head.msgh_remote_port;
        rp.head.msgh_id = rq.head.msgh_id + 100;
        rp.ndr = NDR_record;
        rp.ret = bx_fn(rq.thread.name, rq.exception, rq.code[0], rq.code[1]);
        mach_msg(&rp.head, MACH_SEND_MSG, sizeof rp, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        mach_port_deallocate(mach_task_self(), rq.thread.name);
        mach_port_deallocate(mach_task_self(), rq.task.name);
    }
}

static inline int bx_start(bx_handler fn, exception_mask_t mask) {
    pthread_t t;
    bx_fn = fn;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &bx_port) != KERN_SUCCESS) return -1;
    if (mach_port_insert_right(mach_task_self(), bx_port, bx_port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) return -1;
    if (task_set_exception_ports(mach_task_self(), mask, bx_port, (exception_behavior_t)(EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES),
                                 THREAD_STATE_NONE) != KERN_SUCCESS)
        return -1;
    return pthread_create(&t, NULL, bx_main, NULL);
}

#endif

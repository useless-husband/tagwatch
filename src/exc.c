// exc: the exception thread — fault, classify, log, resume.
//
// The task's EXC_BAD_ACCESS and EXC_BREAKPOINT exceptions are routed to a
// Mach port served by one thread inside the process. The messages carry the
// faulting thread's register state and the reply carries the state to resume
// with (EXCEPTION_STATE_IDENTITY), so handling a trap costs one receive and
// one send and no further system calls on the hot path.
//
// For a tag-check fault on a watched granule the handler logs the access and
// points the thread's pc at a slot that re-executes the instruction with tag
// checks suppressed (tramp.c). The granule's tag is never changed, so other
// threads keep trapping throughout: no access is let through unseen.
#include <mach/mach_vm.h>
#include <mach/thread_info.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <string.h>

#include "insn.h"
#include "internal.h"

#define EXC_CODE_MTE_TAGCHECK 0x106 // EXC_ARM_MTE_TAGCHECK_FAIL
#define MSG_ID_RAISE_STATE_IDENTITY 2407
#define STATE_WORDS 1296

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
    int flavor;
    mach_msg_type_number_t state_count;
    natural_t state[STATE_WORDS];
    char trailer[128];
} request_t;

typedef struct {
    mach_msg_header_t head;
    NDR_record_t ndr;
    kern_return_t ret;
    int flavor;
    mach_msg_type_number_t state_count;
    natural_t state[STATE_WORDS];
} reply_t;
#pragma pack(pop)

// Per-thread facts that are expensive to obtain, cached by thread port name.
#define TCACHE 256
typedef struct {
    mach_port_t port; // we hold one send right per entry so the name stays ours
    uint64_t tid;
    uint64_t stack_lo, stack_hi;
    // pending load-exclusive (see emulate_exclusive)
    uint64_t ll_addr;
    unsigned ll_size;
    uint64_t ll_val[2];
    // consecutive "tags match now, retry" decisions at the same pc
    uint64_t retry_pc, retry_gen;
    unsigned retries;
} tinfo_t;

static mach_port_t exc_port = MACH_PORT_NULL;
static pthread_t exc_pthread;
static thread_t exc_thread = MACH_PORT_NULL;
static tinfo_t tcache[TCACHE];
static _Atomic uint64_t seq;

thread_t tw_exc_thread_port(void) { return exc_thread; }

static void stack_bounds(uint64_t sp, uint64_t *lo, uint64_t *hi) {
    mach_vm_address_t addr = sp & TW_ADDR_MASK;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    *lo = *hi = 0;
    if (mach_vm_region(mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj) == KERN_SUCCESS &&
        addr <= sp && (info.protection & VM_PROT_READ)) {
        *lo = addr;
        *hi = addr + size;
    }
    if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);
}

static tinfo_t *thread_info_for(mach_port_t port, uint64_t sp) {
    // Open addressing; MACH_PORT_DEAD marks a slot whose thread has exited.
    size_t i = (port >> 8) % TCACHE; // port names advance in steps of 0x100
    tinfo_t *t = NULL, *reuse = NULL;
    for (int probe = 0; probe < TCACHE; probe++, i = (i + 1) % TCACHE) {
        if (tcache[i].port == port) {
            t = &tcache[i];
            break;
        }
        if (tcache[i].port == MACH_PORT_DEAD && !reuse) reuse = &tcache[i];
        if (tcache[i].port == MACH_PORT_NULL) {
            if (!reuse) reuse = &tcache[i];
            break;
        }
    }
    if (!t) {
        t = reuse;
        if (!t) { // more live threads than entries: evict
            t = &tcache[(port >> 8) % TCACHE];
            mach_port_deallocate(mach_task_self(), t->port);
        }
        memset(t, 0, sizeof *t);
        t->port = port;
        // Hold a send right of our own so the name cannot be recycled for
        // another thread while it is cached.
        mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_SEND, 1);
        thread_identifier_info_data_t id;
        mach_msg_type_number_t cnt = THREAD_IDENTIFIER_INFO_COUNT;
        if (thread_info(port, THREAD_IDENTIFIER_INFO, (thread_info_t)&id, &cnt) == KERN_SUCCESS) t->tid = id.thread_id;
    }
    // Threads can switch stacks (sigaltstack, coroutines): re-query when the
    // stack pointer leaves the cached region.
    if (sp < t->stack_lo || sp >= t->stack_hi) stack_bounds(sp, &t->stack_lo, &t->stack_hi);
    return t;
}

// Frees cache entries whose thread has exited (the port became a dead name).
static void tcache_sweep(void) {
    for (int i = 0; i < TCACHE; i++) {
        if (tcache[i].port == MACH_PORT_NULL) continue;
        mach_port_type_t type = 0;
        if (mach_port_type(mach_task_self(), tcache[i].port, &type) != KERN_SUCCESS || (type & MACH_PORT_TYPE_DEAD_NAME)) {
            mach_port_deallocate(mach_task_self(), tcache[i].port);
            // A tombstone, not an empty slot, so probe chains stay intact.
            memset(&tcache[i], 0, sizeof tcache[i]);
            tcache[i].port = MACH_PORT_DEAD;
        }
    }
}

static void regs_from_state(const arm_thread_state64_t *ts, uint64_t x[31]) {
    memcpy(x, ts->__x, 29 * sizeof(uint64_t));
    x[29] = ts->__fp;
    x[30] = ts->__lr;
}

static void set_reg(arm_thread_state64_t *ts, unsigned r, uint64_t v) {
    if (r < 29) ts->__x[r] = v;
    else if (r == 29) ts->__fp = v;
    else if (r == 30) ts->__lr = v;
    // r == 31 is the zero register: writes are discarded
}

static uint64_t get_reg(const arm_thread_state64_t *ts, unsigned r) {
    if (r < 29) return ts->__x[r];
    if (r == 29) return ts->__fp;
    if (r == 30) return ts->__lr;
    return 0;
}

static void report(const tw_watch *w, uint64_t addr, unsigned size, unsigned access, unsigned flags, const tinfo_t *ti,
                   const arm_thread_state64_t *ts) {
    static tagwatch_event ev; // only the exception thread reports
    uint64_t n = atomic_fetch_add(&tw_rt.n_events, 1) + 1;
    if (tw_rt.max_events && n > tw_rt.max_events) return;
    ev.seq = atomic_fetch_add(&seq, 1) + 1;
    ev.time_ns = tw_now_ns();
    ev.addr = addr;
    ev.size = size;
    ev.access = access;
    ev.watch = w->id;
    ev.watch_serial = w->serial;
    ev.watch_base = w->base;
    ev.watch_len = w->len;
    ev.offset = (int64_t)(addr - w->base);
    ev.label = w->label;
    ev.thread_id = ti->tid;
    ev.pc = ts->__pc & TW_VA_MASK;
    ev.flags = flags | ((w->flags & TW_WF_FREED) ? TAGWATCH_EV_FREED : 0);
    ev.syscall = NULL;
    ev.nframes = tw_backtrace(ts->__pc, ts->__lr, ts->__fp, ti->stack_lo, ti->stack_hi, ev.frames,
                              tw_rt.bt_depth < TAGWATCH_MAX_FRAMES ? tw_rt.bt_depth : TAGWATCH_MAX_FRAMES);
    if (tw_rt.cb && tw_rt.cb(&ev, tw_rt.cb_ctx)) return;
    tw_emit_access(&ev);
}

// LDXR/STXR cannot be re-executed: taking the exception clears the CPU's
// exclusive monitor, so a store-exclusive that traps would fail forever and
// the retry loop around it would never end. The pair is emulated instead,
// the way QEMU does it: the load records the value it returned, the store
// becomes a compare-and-swap against that value. (Like any CAS-based LL/SC
// this cannot see an A->B->A change between the two.)
static int emulate_exclusive(const tw_insn *d, uint64_t ea, tinfo_t *ti, arm_thread_state64_t *ns) {
    unsigned sz = d->pair ? d->size / 2u : d->size;
    void *mem = (void *)(uintptr_t)ea;
    if (d->excl == TW_EXCL_LOAD) {
        uint64_t v[2] = {0, 0};
        for (unsigned i = 0; i < (d->pair ? 2u : 1u); i++) {
            const char *p = (const char *)mem + i * sz;
            switch (sz) {
            case 1: v[i] = __atomic_load_n((const uint8_t *)p, __ATOMIC_SEQ_CST); break;
            case 2: v[i] = __atomic_load_n((const uint16_t *)(const void *)p, __ATOMIC_SEQ_CST); break;
            case 4: v[i] = __atomic_load_n((const uint32_t *)(const void *)p, __ATOMIC_SEQ_CST); break;
            default: v[i] = __atomic_load_n((const uint64_t *)(const void *)p, __ATOMIC_SEQ_CST); break;
            }
        }
        set_reg(ns, d->rt, v[0]);
        if (d->pair) set_reg(ns, d->rt2, v[1]);
        ti->ll_addr = ea;
        ti->ll_size = d->size;
        ti->ll_val[0] = v[0];
        ti->ll_val[1] = v[1];
    } else {
        int ok = 0;
        if (ti->ll_addr == ea && ti->ll_size == d->size) {
            uint64_t nv0 = get_reg(ns, d->rt), nv1 = get_reg(ns, d->rt2);
            if (d->pair && sz == 8) {
                __uint128_t expect = ((__uint128_t)ti->ll_val[1] << 64) | ti->ll_val[0];
                __uint128_t desired = ((__uint128_t)nv1 << 64) | nv0;
                ok = __atomic_compare_exchange_n((__uint128_t *)mem, &expect, desired, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
            } else if (d->pair) {
                uint64_t expect = (ti->ll_val[1] << 32) | (uint32_t)ti->ll_val[0];
                uint64_t desired = (nv1 << 32) | (uint32_t)nv0;
                ok = __atomic_compare_exchange_n((uint64_t *)mem, &expect, desired, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
            } else if (sz == 1) {
                uint8_t expect = (uint8_t)ti->ll_val[0];
                ok = __atomic_compare_exchange_n((uint8_t *)mem, &expect, (uint8_t)nv0, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
            } else if (sz == 2) {
                uint16_t expect = (uint16_t)ti->ll_val[0];
                ok = __atomic_compare_exchange_n((uint16_t *)mem, &expect, (uint16_t)nv0, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
            } else if (sz == 4) {
                uint32_t expect = (uint32_t)ti->ll_val[0];
                ok = __atomic_compare_exchange_n((uint32_t *)mem, &expect, (uint32_t)nv0, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
            } else {
                uint64_t expect = ti->ll_val[0];
                ok = __atomic_compare_exchange_n((uint64_t *)mem, &expect, nv0, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
            }
        }
        ti->ll_addr = 0;
        ti->ll_size = 0;
        set_reg(ns, d->rs, ok ? 0 : 1);
        if (!ok) return 0; // the program's loop will retry from the load
    }
    return 1;
}

// Returns KERN_SUCCESS with *ns updated to resume, or KERN_FAILURE to pass
// the exception on to the default handling (a crash is a crash).
static kern_return_t handle(const request_t *rq, arm_thread_state64_t *ns) {
    uint64_t pc = ns->__pc & TW_VA_MASK;
    uint64_t entry, orig_pc;
    unsigned word;

    if (rq->exception == EXC_BREAKPOINT) {
        // End of a far slot: finish the return the slot could not branch to.
        if (tw_tramp_owner(pc, &entry, &orig_pc, &word) && word == 3) {
            ns->__pc = orig_pc + 4;
            return KERN_SUCCESS;
        }
        return KERN_FAILURE;
    }
    if (rq->exception != EXC_BAD_ACCESS) return KERN_FAILURE;

    uint64_t fix = tw_mte_recover_pc(pc);
    if (fix) { // guarded store in watch.c hit memory that cannot be tagged
        ns->__pc = fix;
        return KERN_SUCCESS;
    }
    if (rq->code[0] != EXC_CODE_MTE_TAGCHECK) {
        if (tw_rt.verbose) { // an ordinary crash: say where, then let it take its course
            char msg[160];
            tw_buf b;
            tw_buf_init(&b, msg, sizeof msg);
            tw_put_fmt(&b, "passing on EXC_BAD_ACCESS (code %lld) at address %p, pc %p", (long long)rq->code[0],
                       (void *)(uintptr_t)rq->code[1], (void *)(uintptr_t)pc);
            tw_emit_note("crash", msg);
        }
        return KERN_FAILURE;
    }

    if (tw_tramp_owner(pc, &entry, &orig_pc, &word)) {
        // A fault inside a slot means the thread lost PSTATE.TCO between the
        // slot's first instruction and the access. That can only happen if a
        // signal handler ran in between and the state it returned to no
        // longer had the bit. Start the slot again.
        ns->__pc = entry;
        return KERN_SUCCESS;
    }

    atomic_fetch_add(&tw_rt.n_traps, 1);
    uint64_t far = (uint64_t)rq->code[1] & TW_ADDR_MASK;
    uint32_t insn = *(const uint32_t *)(uintptr_t)pc;
    tw_insn d;
    uint64_t x[31], ea = 0;
    unsigned size = 0, access = 0;
    regs_from_state(ns, x);
    if (tw_insn_decode(insn, &d)) {
        size = d.size;
        access = d.access;
        ea = tw_insn_ea(&d, x, ns->__sp);
        if (d.ea_mode == TW_EA_UNKNOWN) ea = far;
    }
    if (!access) { // unknown instruction: fall back to the syndrome register
        arm_exception_state64_t es;
        mach_msg_type_number_t cnt = ARM_EXCEPTION_STATE64_COUNT;
        access = TAGWATCH_READ;
        if (thread_get_state(rq->thread.name, ARM_EXCEPTION_STATE64, (thread_state_t)&es, &cnt) == KERN_SUCCESS)
            access = (es.__esr & (1u << 6)) ? TAGWATCH_WRITE : TAGWATCH_READ; // ISS.WnR
        ea = far;
        size = 0;
    }

    tinfo_t *ti = thread_info_for(rq->thread.name, ns->__sp);
    tw_watch w;
    uint64_t slack = 0;
    unsigned tag_now = 0;
    if (!tw_watch_hit(ea, size, far, access, &w, &slack, &tag_now)) {
        // Not a watched granule. If the pointer's tag matches the granule now,
        // the watch was removed while this fault was in flight: just retry.
        // The retry is bounded in case the reported address is not the granule
        // that failed the check, but only while the set of watches stands
        // still: under arm/disarm churn any number of retries is legitimate.
        unsigned ptag = (unsigned)((uint64_t)rq->code[1] >> 56) & 0xf;
        if (tag_now == ptag) {
            uint64_t gen = atomic_load(&tw_watch_generation);
            if (ti->retry_pc != pc || ti->retry_gen != gen) ti->retries = 0;
            ti->retry_pc = pc;
            ti->retry_gen = gen;
            if (++ti->retries <= 16) return KERN_SUCCESS;
        }
        atomic_fetch_add(&tw_rt.n_violations, 1);
        uint64_t frames[TAGWATCH_MAX_FRAMES];
        unsigned n = tw_backtrace(ns->__pc, ns->__lr, ns->__fp, ti->stack_lo, ti->stack_hi, frames, TAGWATCH_MAX_FRAMES);
        tw_emit_violation(far, pc, ti->tid, access, size, frames, n);
        return KERN_FAILURE;
    }

    ti->retries = 0;
    unsigned flags = 0;
    if (slack || !(access & w.mode)) atomic_fetch_add(&tw_rt.n_filtered, 1);
    else {
        if (d.excl) flags |= TAGWATCH_EV_ATOMIC;
        report(&w, size ? ea : far, size ? size : 1, access, flags, ti, ns);
    }

    if (d.excl) {
        atomic_fetch_add(&tw_rt.n_emulated, 1);
        emulate_exclusive(&d, ea, ti, ns);
        ns->__pc += 4;
        return KERN_SUCCESS;
    }
    int is_far = 0;
    uint64_t slot = tw_tramp_get(pc, insn, &is_far);
    if (!slot) {
        tw_emit_note("error", "cannot allocate an execution slot; the watch on this object is removed");
        tw_watch_remove_addr(w.gbase, "no-slot");
        return KERN_SUCCESS; // retry the instruction, now unwatched
    }
    if (is_far) atomic_fetch_add(&tw_rt.n_far, 1);
    ns->__pc = slot;
    return KERN_SUCCESS;
}

static void *exc_main(void *arg) {
    (void)arg;
    pthread_setname_np("tagwatch");
    // This thread reads watched memory (LL/SC emulation, peeking at frames)
    // and must never trap on it: it would be waiting for itself.
    tw_tco_force(1);
    static request_t rq;
    static reply_t rp;
    mach_msg_option_t opt = MACH_RCV_MSG;
    mach_msg_size_t send_size = 0;
    unsigned since_sweep = 0;
    for (;;) {
        // Reply to the previous exception and wait for the next in one call.
        memcpy(&rq, &rp, send_size);
        kern_return_t kr = mach_msg(&rq.head, opt, send_size, sizeof rq, exc_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            if (kr == MACH_RCV_PORT_DIED || kr == MACH_RCV_INVALID_NAME) return NULL;
            opt = MACH_RCV_MSG; // the send half failed (thread gone); keep serving
            send_size = 0;
            continue;
        }
        kern_return_t ret = KERN_FAILURE;
        mach_msg_type_number_t count = 0;
        if (rq.head.msgh_id == MSG_ID_RAISE_STATE_IDENTITY && rq.flavor == ARM_THREAD_STATE64 &&
            rq.state_count == ARM_THREAD_STATE64_COUNT) {
            count = rq.state_count;
            memcpy(rp.state, rq.state, count * sizeof(natural_t));
            ret = handle(&rq, (arm_thread_state64_t *)(void *)rp.state);
        }
        rp.head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(rq.head.msgh_bits), 0);
        rp.head.msgh_remote_port = rq.head.msgh_remote_port;
        rp.head.msgh_local_port = MACH_PORT_NULL;
        rp.head.msgh_id = rq.head.msgh_id + 100;
        rp.head.msgh_voucher_port = MACH_PORT_NULL;
        rp.ndr = NDR_record;
        rp.ret = ret;
        rp.flavor = rq.flavor;
        rp.state_count = ret == KERN_SUCCESS ? count : 0;
        send_size = (mach_msg_size_t)(offsetof(reply_t, state) + rp.state_count * sizeof(natural_t));
        rp.head.msgh_size = send_size;
        opt = MACH_SEND_MSG | MACH_RCV_MSG;
        // The message gave us send rights for the thread and the task.
        mach_port_deallocate(mach_task_self(), rq.thread.name);
        mach_port_deallocate(mach_task_self(), rq.task.name);
        if (++since_sweep == 4096) {
            since_sweep = 0;
            tcache_sweep();
        }
    }
}

int tw_exc_start(void) {
    mach_port_t self = mach_task_self();
    if (mach_port_allocate(self, MACH_PORT_RIGHT_RECEIVE, &exc_port) != KERN_SUCCESS) return -1;
    if (mach_port_insert_right(self, exc_port, exc_port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) return -1;
    if (task_set_exception_ports(self, EXC_MASK_BAD_ACCESS | EXC_MASK_BREAKPOINT, exc_port,
                                 (exception_behavior_t)(EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES),
                                 ARM_THREAD_STATE64) != KERN_SUCCESS)
        return -1;
    // The thread must not receive signals: a handler might touch watched
    // memory, or need a lock held by the thread this one has frozen.
    sigset_t all, old;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, &old);
    int rc = pthread_create(&exc_pthread, NULL, exc_main, NULL);
    pthread_sigmask(SIG_SETMASK, &old, NULL);
    if (rc != 0) return -1;
    exc_thread = pthread_mach_thread_np(exc_pthread);
    return 0;
}

void tw_exc_after_fork_child(void) {
    // The exception thread does not exist in the child, and the inherited
    // exception port belongs to the parent: detach from it.
    task_set_exception_ports(mach_task_self(), EXC_MASK_BAD_ACCESS | EXC_MASK_BREAKPOINT, MACH_PORT_NULL,
                             EXCEPTION_DEFAULT, THREAD_STATE_NONE);
    exc_port = MACH_PORT_NULL;
    exc_thread = MACH_PORT_NULL;
}

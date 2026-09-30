// interpose: the hooks that only exist when libtagwatch is loaded as a
// dylib at launch (linked or inserted), using dyld's __interpose mechanism.
//
//  * Allocation entry points, to divert allocations matched by an "alloc:"
//    spec into the arena and watch them, and to notice free()/realloc() of
//    system-heap blocks that were watched in place.
//  * The read/write family of system calls. The kernel accesses user buffers
//    with the caller's pointer tag; on a watched granule that mismatch kills
//    the process outright (there is no fault to recover from inside a
//    system call). The shims run such calls against a private bounce buffer
//    and copy with tag checks off, and report the access.
//
//  * sigaction/signal, to wrap handlers (see the end of this file), and the
//    blocking calls most often hit by a side effect of being traced: when a
//    traced process receives any signal it stops, and the stop makes blocking
//    system calls in all its threads return EINTR even though no handler ran.
//    POSIX never does that, so the shims retry in exactly that case.
//
// Calls made from inside this library are not interposed, so malloc() and
// read() below are the real ones.
#include <errno.h>
#include <malloc/malloc.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "internal.h"

#define INTERPOSE(replacement, original)                                                         \
    __attribute__((used)) static const struct {                                                  \
        const void *r, *o;                                                                       \
    } tw_interpose_##original __attribute__((section("__DATA,__interpose"))) = {(const void *)(uintptr_t)&replacement, \
                                                                                 (const void *)(uintptr_t)&original}

#define FRAME __builtin_frame_address(0)

// ---- allocation ---------------------------------------------------------------
static inline int alloc_specs_active(void) { return tw_rt.have_alloc_specs && tw_on(); }

// A system-heap block that was watched in place must be disarmed before the
// allocator sees it again: the allocator checks and rewrites tags itself.
static inline void release_inplace_watch(void *p) {
    if (p && atomic_load_explicit(&tw_armed_granules, memory_order_relaxed) && tw_on() && !tw_arena_owns(p))
        tw_watch_remove_addr((uint64_t)(uintptr_t)p, "free");
}

static void *tw_malloc(size_t size) {
    if (alloc_specs_active()) {
        int i = tw_alloc_match(size, FRAME);
        if (i >= 0) return tw_alloc_watched(size, TW_GRANULE, i, FRAME);
    }
    return malloc(size);
}

static void *tw_calloc(size_t n, size_t size) {
    size_t total;
    if (alloc_specs_active() && !__builtin_mul_overflow(n, size, &total)) {
        int i = tw_alloc_match(total, FRAME);
        if (i >= 0) return tw_alloc_watched(total, TW_GRANULE, i, FRAME);
    }
    return calloc(n, size);
}

static void *tw_valloc(size_t size) {
    if (alloc_specs_active()) {
        int i = tw_alloc_match(size, FRAME);
        if (i >= 0) return tw_alloc_watched(size, TW_PAGE_SIZE, i, FRAME);
    }
    return valloc(size);
}

static void *tw_aligned_alloc(size_t align, size_t size) {
    if (alloc_specs_active() && align && !(align & (align - 1))) {
        int i = tw_alloc_match(size, FRAME);
        if (i >= 0) return tw_alloc_watched(size, align, i, FRAME);
    }
    return aligned_alloc(align, size);
}

static int tw_posix_memalign(void **out, size_t align, size_t size) {
    if (alloc_specs_active() && align >= sizeof(void *) && !(align & (align - 1))) {
        int i = tw_alloc_match(size, FRAME);
        if (i >= 0) {
            void *p = tw_alloc_watched(size, align, i, FRAME);
            if (!p) return ENOMEM;
            *out = p;
            return 0;
        }
    }
    return posix_memalign(out, align, size);
}

static void *tw_malloc_zone_malloc(malloc_zone_t *zone, size_t size) {
    if (alloc_specs_active()) {
        int i = tw_alloc_match(size, FRAME);
        if (i >= 0) return tw_alloc_watched(size, TW_GRANULE, i, FRAME);
    }
    return malloc_zone_malloc(zone, size);
}

static void *tw_malloc_zone_calloc(malloc_zone_t *zone, size_t n, size_t size) {
    size_t total;
    if (alloc_specs_active() && !__builtin_mul_overflow(n, size, &total)) {
        int i = tw_alloc_match(total, FRAME);
        if (i >= 0) return tw_alloc_watched(total, TW_GRANULE, i, FRAME);
    }
    return malloc_zone_calloc(zone, n, size);
}

static void tw_free(void *p) {
    release_inplace_watch(p);
    free(p); // arena blocks reach tw_arena_free through the malloc zone
}

static void *tw_realloc(void *p, size_t size) {
    int ours = p && tw_arena_owns(p);
    int spec = alloc_specs_active() && size ? tw_alloc_match(size, FRAME) : -1;
    if (!ours && spec < 0) {
        release_inplace_watch(p);
        return realloc(p, size);
    }
    // One side of the move lives in the arena: allocate, copy, release. The
    // old object may be armed, so the copy runs with tag checks off.
    if (p && size == 0) {
        free(p);
        return NULL;
    }
    void *q = spec >= 0 ? tw_alloc_watched(size, TW_GRANULE, spec, FRAME) : malloc(size);
    if (!q) return NULL;
    if (p) {
        size_t old = ours ? tw_arena_size(p) : malloc_size(p);
        tagwatch_poke(q, p, old < size ? old : size);
        release_inplace_watch(p);
        free(p);
    }
    return q;
}

static void *tw_reallocf(void *p, size_t size) {
    void *q = tw_realloc(p, size);
    if (!q && p && size) {
        release_inplace_watch(p);
        free(p);
    }
    return q;
}

INTERPOSE(tw_malloc, malloc);
INTERPOSE(tw_calloc, calloc);
INTERPOSE(tw_valloc, valloc);
INTERPOSE(tw_aligned_alloc, aligned_alloc);
INTERPOSE(tw_posix_memalign, posix_memalign);
INTERPOSE(tw_malloc_zone_malloc, malloc_zone_malloc);
INTERPOSE(tw_malloc_zone_calloc, malloc_zone_calloc);
INTERPOSE(tw_free, free);
INTERPOSE(tw_realloc, realloc);
INTERPOSE(tw_reallocf, reallocf);

// ---- spurious EINTR -----------------------------------------------------------------
// Number of signal handlers that have run on the calling thread, kept in a
// pthread key (no allocation, usable from a handler). EINTR with this number
// unchanged means no handler ran: the interruption came from the trace stop.
static pthread_key_t handler_runs_key;
static _Atomic int handler_runs_ready;

static inline uintptr_t handler_runs(void) {
    return atomic_load_explicit(&handler_runs_ready, memory_order_relaxed) ? (uintptr_t)pthread_getspecific(handler_runs_key) : 0;
}

#define RETRY_EINTR(result, call)                                                   \
    do {                                                                            \
        uintptr_t before_ = handler_runs();                                         \
        result = (call);                                                            \
        if (result != -1 || errno != EINTR || !tw_on() || handler_runs() != before_) break; \
    } while (1)

static pid_t tw_waitpid(pid_t pid, int *status, int options) {
    pid_t r;
    RETRY_EINTR(r, waitpid(pid, status, options));
    return r;
}
static pid_t tw_wait(int *status) {
    pid_t r;
    RETRY_EINTR(r, wait(status));
    return r;
}
static pid_t tw_wait4(pid_t pid, int *status, int options, struct rusage *ru) {
    pid_t r;
    RETRY_EINTR(r, wait4(pid, status, options, ru));
    return r;
}
INTERPOSE(tw_waitpid, waitpid);
INTERPOSE(tw_wait, wait);
INTERPOSE(tw_wait4, wait4);

// ---- system calls on watched buffers -----------------------------------------------
static inline int touches_watch(const void *buf, size_t len) {
    return atomic_load_explicit(&tw_armed_granules, memory_order_relaxed) && tw_on() &&
           tw_watch_overlaps((uint64_t)(uintptr_t)buf, len);
}

// Kernel writes into the user's buffer (read-like calls).
#define BOUNCE_IN(name, call_with_tmp, buf, len)                                                 \
    do {                                                                                         \
        void *tmp = tw_vm_alloc(len);                                                            \
        if (!tmp) {                                                                              \
            errno = ENOMEM;                                                                      \
            return -1;                                                                           \
        }                                                                                        \
        ssize_t r;                                                                               \
        RETRY_EINTR(r, call_with_tmp);                                                           \
        int saved_errno = errno;                                                                 \
        if (r > 0) {                                                                             \
            tw_report_syscall(name, (uint64_t)(uintptr_t)(buf), (uint64_t)r, TAGWATCH_WRITE, FRAME); \
            tagwatch_poke(buf, tmp, (size_t)r);                                                  \
        }                                                                                        \
        tw_vm_free(tmp, len);                                                                    \
        errno = saved_errno;                                                                     \
        return r;                                                                                \
    } while (0)

// Kernel reads the user's buffer (write-like calls).
#define BOUNCE_OUT(name, call_with_tmp, buf, len)                                                \
    do {                                                                                         \
        void *tmp = tw_vm_alloc(len);                                                            \
        if (!tmp) {                                                                              \
            errno = ENOMEM;                                                                      \
            return -1;                                                                           \
        }                                                                                        \
        tagwatch_peek(tmp, buf, len);                                                            \
        ssize_t r;                                                                               \
        RETRY_EINTR(r, call_with_tmp);                                                           \
        int saved_errno = errno;                                                                 \
        if (r > 0) tw_report_syscall(name, (uint64_t)(uintptr_t)(buf), (uint64_t)r, TAGWATCH_READ, FRAME); \
        tw_vm_free(tmp, len);                                                                    \
        errno = saved_errno;                                                                     \
        return r;                                                                                \
    } while (0)

static ssize_t tw_read(int fd, void *buf, size_t len) {
    if (len && touches_watch(buf, len)) BOUNCE_IN("read", read(fd, tmp, len), buf, len);
    ssize_t r;
    RETRY_EINTR(r, read(fd, buf, len));
    return r;
}
static ssize_t tw_pread(int fd, void *buf, size_t len, off_t off) {
    if (len && touches_watch(buf, len)) BOUNCE_IN("pread", pread(fd, tmp, len, off), buf, len);
    ssize_t r;
    RETRY_EINTR(r, pread(fd, buf, len, off));
    return r;
}
static ssize_t tw_recv(int fd, void *buf, size_t len, int flags) {
    if (len && touches_watch(buf, len)) BOUNCE_IN("recv", recv(fd, tmp, len, flags), buf, len);
    ssize_t r;
    RETRY_EINTR(r, recv(fd, buf, len, flags));
    return r;
}
static ssize_t tw_write(int fd, const void *buf, size_t len) {
    if (len && touches_watch(buf, len)) BOUNCE_OUT("write", write(fd, tmp, len), buf, len);
    ssize_t r;
    RETRY_EINTR(r, write(fd, buf, len));
    return r;
}
static ssize_t tw_pwrite(int fd, const void *buf, size_t len, off_t off) {
    if (len && touches_watch(buf, len)) BOUNCE_OUT("pwrite", pwrite(fd, tmp, len, off), buf, len);
    ssize_t r;
    RETRY_EINTR(r, pwrite(fd, buf, len, off));
    return r;
}
static ssize_t tw_send(int fd, const void *buf, size_t len, int flags) {
    if (len && touches_watch(buf, len)) BOUNCE_OUT("send", send(fd, tmp, len, flags), buf, len);
    ssize_t r;
    RETRY_EINTR(r, send(fd, buf, len, flags));
    return r;
}

// stdio reaches the kernel through its own buffer for small requests, but
// hands large ones straight to read/write with the caller's pointer, from
// inside libsystem where the shims above are not seen. Handle the FILE*
// calls at the API boundary instead.
static size_t tw_fread(void *buf, size_t size, size_t n, FILE *f) {
    size_t total;
    if (!__builtin_mul_overflow(size, n, &total) && total && touches_watch(buf, total)) {
        void *tmp = tw_vm_alloc(total);
        if (!tmp) return 0;
        size_t got = fread(tmp, size, n, f);
        if (got) {
            tw_report_syscall("fread", (uint64_t)(uintptr_t)buf, got * size, TAGWATCH_WRITE, FRAME);
            tagwatch_poke(buf, tmp, got * size);
        }
        tw_vm_free(tmp, total);
        return got;
    }
    return fread(buf, size, n, f);
}
static size_t tw_fwrite(const void *buf, size_t size, size_t n, FILE *f) {
    size_t total;
    if (!__builtin_mul_overflow(size, n, &total) && total && touches_watch(buf, total)) {
        void *tmp = tw_vm_alloc(total);
        if (!tmp) return 0;
        tagwatch_peek(tmp, buf, total);
        size_t put = fwrite(tmp, size, n, f);
        if (put) tw_report_syscall("fwrite", (uint64_t)(uintptr_t)buf, put * size, TAGWATCH_READ, FRAME);
        tw_vm_free(tmp, total);
        return put;
    }
    return fwrite(buf, size, n, f);
}

INTERPOSE(tw_read, read);
INTERPOSE(tw_pread, pread);
INTERPOSE(tw_recv, recv);
INTERPOSE(tw_write, write);
INTERPOSE(tw_pwrite, pwrite);
INTERPOSE(tw_send, send);
INTERPOSE(tw_fread, fread);
INTERPOSE(tw_fwrite, fwrite);

// ---- signal handlers ------------------------------------------------------------
// PSTATE.TCO is inherited by a signal handler. If a signal lands on a thread
// that is inside an execution slot (tag checks off for one instruction), the
// whole handler would run unchecked and its accesses to watched memory would
// go unreported. Handlers are therefore wrapped: the wrapper turns checks
// back on, and sigreturn restores the interrupted state afterwards.
static _Atomic(uintptr_t) user_handler[NSIG];
static _Atomic int user_siginfo[NSIG];

static void signal_entry(int sig, siginfo_t *si, void *uc) {
    tw_tco_force(0);
    if (atomic_load_explicit(&handler_runs_ready, memory_order_relaxed))
        pthread_setspecific(handler_runs_key, (void *)((uintptr_t)pthread_getspecific(handler_runs_key) + 1));
    uintptr_t h = atomic_load(&user_handler[sig]);
    if (atomic_load(&user_siginfo[sig])) ((void (*)(int, siginfo_t *, void *))h)(sig, si, uc);
    else ((void (*)(int))h)(sig);
}

static int is_real_handler(const struct sigaction *sa) {
    return sa->sa_handler != SIG_DFL && sa->sa_handler != SIG_IGN && sa->sa_handler != SIG_ERR;
}

void tw_interpose_init(void) {
    if (pthread_key_create(&handler_runs_key, NULL) == 0) atomic_store(&handler_runs_ready, 1);
}

static int tw_sigaction(int sig, const struct sigaction *act, struct sigaction *oact) {
    if (!tw_on() || sig <= 0 || sig >= NSIG) return sigaction(sig, act, oact);
    uintptr_t prev_handler = atomic_load(&user_handler[sig]);
    int prev_siginfo = atomic_load(&user_siginfo[sig]);
    struct sigaction mine, old;
    const struct sigaction *use = act;
    if (act && is_real_handler(act)) {
        mine = *act;
        atomic_store(&user_siginfo[sig], (act->sa_flags & SA_SIGINFO) != 0);
        atomic_store(&user_handler[sig], (uintptr_t)act->sa_sigaction);
        mine.sa_sigaction = signal_entry;
        mine.sa_flags |= SA_SIGINFO;
        use = &mine;
    }
    int rc = sigaction(sig, use, &old);
    if (rc != 0) {
        if (use == &mine) {
            atomic_store(&user_handler[sig], prev_handler);
            atomic_store(&user_siginfo[sig], prev_siginfo);
        }
        return rc;
    }
    if (oact) {
        *oact = old;
        if (old.sa_sigaction == signal_entry) { // report the program's own handler, not the wrapper
            oact->sa_sigaction = (void (*)(int, siginfo_t *, void *))prev_handler;
            if (!prev_siginfo) oact->sa_flags &= ~SA_SIGINFO;
        }
    }
    return 0;
}

static sig_t tw_signal(int sig, sig_t handler) {
    if (!tw_on()) return signal(sig, handler);
    struct sigaction sa, old;
    sa.sa_handler = handler;
    sa.sa_flags = SA_RESTART; // BSD signal() semantics
    sigemptyset(&sa.sa_mask);
    if (tw_sigaction(sig, &sa, &old) != 0) return SIG_ERR;
    return old.sa_handler;
}

INTERPOSE(tw_sigaction, sigaction);
INTERPOSE(tw_signal, signal);

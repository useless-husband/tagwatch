/*
 * tagwatch — data watchpoints built on ARM MTE tag-check faults.
 *
 * Link against libtagwatch.dylib (or let `tagwatch run` inject it) and watch
 * any number of address ranges at 16-byte granularity. Every access to a
 * watched range is reported with its address, width, direction, thread and
 * backtrace, then allowed to proceed.
 *
 * Requirements: an Apple Silicon Mac with MTE (M5 or later) and a process
 * that has MTE enabled — either started by `tagwatch run`, or signed with the
 * hardened-process entitlements (see README). On anything else
 * tagwatch_init() returns TAGWATCH_ENOTSUP and every call is a harmless no-op.
 */
#ifndef TAGWATCH_H
#define TAGWATCH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
#pragma GCC visibility push(default)

#define TAGWATCH_VERSION "0.1.0"
#define TAGWATCH_GRANULE 16
#define TAGWATCH_MAX_FRAMES 32

/* Error codes (returned negated). */
enum {
    TAGWATCH_OK = 0,
    TAGWATCH_ENOTSUP = 1,   /* no MTE hardware, or MTE not enabled for this process */
    TAGWATCH_EINVAL = 2,    /* bad argument */
    TAGWATCH_EEXIST = 3,    /* range overlaps an existing watch */
    TAGWATCH_ENOTTAGGED = 4,/* memory is not in an MTE mapping (see tagwatch_adopt) */
    TAGWATCH_ENOMEM = 5,
    TAGWATCH_ENOENT = 6,    /* no such watch */
    TAGWATCH_ESETUP = 7,    /* could not install the fault handler */
    TAGWATCH_EBUSY = 8,     /* cannot be done in the current state */
};

/* Which accesses a watch reports. The CPU traps both; filtering only
 * decides what is logged. */
enum {
    TAGWATCH_READ = 1,
    TAGWATCH_WRITE = 2,
    TAGWATCH_RW = 3,
};

/* Event flags. */
enum {
    TAGWATCH_EV_FREED = 1 << 0,   /* object was already freed (quarantined): use-after-free */
    TAGWATCH_EV_SYSCALL = 1 << 1, /* access made by the kernel on behalf of a system call */
    TAGWATCH_EV_ATOMIC = 1 << 2,  /* LDXR/STXR pair emulated as compare-and-swap */
};

typedef int64_t tagwatch_id;

typedef struct tagwatch_event {
    uint64_t seq;       /* 1, 2, 3, ... in the order the accesses were handled */
    uint64_t time_ns;   /* since tagwatch_init */
    uint64_t addr;      /* first byte accessed */
    uint32_t size;      /* bytes accessed */
    uint32_t access;    /* TAGWATCH_READ, TAGWATCH_WRITE or TAGWATCH_RW */
    tagwatch_id watch;  /* the id tagwatch_watch() returned for this watch */
    uint64_t watch_serial; /* the "#N" shown in the log and the trace */
    uint64_t watch_base;/* start of the watched object */
    uint64_t watch_len;
    int64_t offset;     /* addr - watch_base */
    const char *label;
    uint64_t thread_id; /* system-wide thread id (as shown by lldb and sample) */
    uint64_t pc;
    uint32_t flags;     /* TAGWATCH_EV_* */
    uint32_t nframes;
    uint64_t frames[TAGWATCH_MAX_FRAMES]; /* frames[0] == pc */
    const char *syscall;/* name, when TAGWATCH_EV_SYSCALL is set */
} tagwatch_event;

/*
 * Called on tagwatch's handler thread for every reported access, while the
 * accessing thread is frozen at the instruction. (Accesses made by the kernel
 * in a wrapped system call are reported on the calling thread instead, so
 * the callback can run on two threads at once.) It must not call malloc,
 * stdio, or anything else that may take a lock the frozen thread holds, and
 * it must not touch watched memory through ordinary pointers — use
 * tagwatch_peek(). Return nonzero to suppress the default log output.
 */
typedef int (*tagwatch_callback)(const tagwatch_event *ev, void *ctx);

typedef struct tagwatch_stats {
    uint64_t events;        /* accesses reported */
    uint64_t traps;         /* tag-check faults taken on watched granules */
    uint64_t filtered;      /* traps not reported (read/write filter, granule neighbour) */
    uint64_t far_traps;     /* traps that needed the two-exception return path */
    uint64_t emulated;      /* LDXR/STXR handled by emulation */
    uint64_t syscalls;      /* system calls redirected around watched memory */
    uint64_t violations;    /* genuine MTE faults that were not watchpoints */
    uint64_t watches_live;
    uint64_t watches_total;
    uint64_t granules_live;
    uint64_t trampolines;
} tagwatch_stats;

/* Sets up the fault handler. Idempotent. Call it early in main(), before
 * other threads exist: unless the process was started by `tagwatch run`,
 * this forks a small supervisor (see README, "How it works"). Returns 0 or
 * a negated TAGWATCH_E* code. */
int tagwatch_init(void);

/* 1 if watches can be armed in this process. */
int tagwatch_available(void);

/* Watches [addr, addr+len). The memory must live in an MTE mapping: a small
 * malloc block in an MTE-enabled process, memory from tagwatch_alloc(), or
 * pages converted with tagwatch_adopt(). Returns an id > 0 or a negated
 * TAGWATCH_E* code. The label is copied. */
tagwatch_id tagwatch_watch(const void *addr, size_t len, const char *label);
tagwatch_id tagwatch_watch_mode(const void *addr, size_t len, const char *label, int mode);

int tagwatch_unwatch(tagwatch_id id);
/* Removes the watch covering addr, if any. */
int tagwatch_unwatch_addr(const void *addr);

/* Allocates `size` bytes from tagwatch's own MTE-backed arena (any size; the
 * system allocator only tags small blocks). Release with free(). */
void *tagwatch_alloc(size_t size);
/* Same, and watches the whole block; the watch ends when it is freed. */
void *tagwatch_alloc_watched(size_t size, const char *label);

/* Replaces the pages covering [addr, addr+len) by MTE-backed copies so that
 * globals (and other private, writable memory) can be watched. Other threads
 * are suspended for the duration. */
int tagwatch_adopt(void *addr, size_t len);

/* Reads or writes watched memory without triggering a report. */
void tagwatch_peek(void *dst, const void *src, size_t len);
void tagwatch_poke(void *dst, const void *src, size_t len);

/* Suppresses tag checks on the calling thread until the matching resume.
 * Nests. Accesses made while paused are not reported. */
void tagwatch_pause(void);
void tagwatch_resume(void);

int tagwatch_set_callback(tagwatch_callback cb, void *ctx);

/* Output. log_fd < 0 disables the human-readable log; trace_path NULL
 * disables the JSON-lines trace. Defaults: log to stderr, no trace, unless
 * overridden by TAGWATCH_LOG / TAGWATCH_TRACE. */
int tagwatch_set_output(int log_fd, const char *trace_path);

void tagwatch_get_stats(tagwatch_stats *out);

const char *tagwatch_strerror(int code);

#pragma GCC visibility pop
#ifdef __cplusplus
}
#endif

#endif

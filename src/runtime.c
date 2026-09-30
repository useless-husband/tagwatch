// runtime: initialisation, the public API, and the glue between modules.
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

#include "internal.h"
#include "supervise.h"
#include "symtab.h"

tw_runtime tw_rt = {.bt_depth = 16};

static _Atomic int init_phase; // 0 = not started, 1 = running, 2 = finished
static int init_result;
static pthread_key_t pause_key;

const char *tagwatch_strerror(int code) {
    switch (code < 0 ? -code : code) {
    case TAGWATCH_OK: return "ok";
    case TAGWATCH_ENOTSUP: return "MTE is not available or not enabled for this process";
    case TAGWATCH_EINVAL: return "invalid argument";
    case TAGWATCH_EEXIST: return "range overlaps an existing watch";
    case TAGWATCH_ENOTTAGGED: return "memory is not in an MTE mapping";
    case TAGWATCH_ENOMEM: return "out of memory";
    case TAGWATCH_ENOENT: return "no such watch";
    case TAGWATCH_ESETUP: return "could not install the fault handler";
    case TAGWATCH_EBUSY: return "not possible in the current state";
    default: return "unknown error";
    }
}

// ---- fork -------------------------------------------------------------------
// Watches do not follow fork. The child has no exception thread and is not
// traced, so a tag fault there would simply kill it; instead every granule
// gets its original tag back before the child runs any program code.
static void atfork_child(void) {
    if (!tw_on()) return;
    tw_rt.state = TW_STATE_FORKED;
    tw_out_after_fork();
    tw_watch_disarm_all();
    tw_exc_after_fork_child();
    tw_tco_force(0);
    tw_emit_note("fork", "forked child runs without watches (tagwatch does not follow fork)");
}

// ---- configuration from the environment -------------------------------------
static uint64_t env_u64(const char *name, uint64_t dflt) {
    const char *v = getenv(name);
    uint64_t out;
    if (!v || tw_parse_u64(v, strlen(v), &out) != 0) return dflt;
    return out;
}

static void apply_static_specs(void) {
    for (int i = 0; i < tw_rt.nspecs; i++) {
        tw_spec *s = &tw_rt.specs[i];
        if (s->kind == TW_SPEC_ALLOC) {
            tw_rt.have_alloc_specs = 1;
            continue;
        }
        uint64_t addr = s->base, len = s->len;
        const char *label = s->label;
        if (s->kind == TW_SPEC_SYMBOL) {
            uint64_t size = 0;
            if (!tw_sym_find(s->image, s->name, &addr, &size)) {
                tw_log("cannot watch symbol '%s': not found in %s", s->name, s->image[0] ? s->image : "the main executable");
                continue;
            }
            addr += s->off;
            if (!len) len = size > s->off ? size - s->off : TAGWATCH_GRANULE;
            if (!label[0]) label = s->name;
        }
        // Globals and arbitrary addresses are usually not in tagged memory.
        int rc = tw_adopt(addr, len);
        tagwatch_id id = rc == 0 ? tw_watch_add(addr, len, label, s->mode,
                                                s->kind == TW_SPEC_SYMBOL ? TW_ORIGIN_SYMBOL : TW_ORIGIN_ADDR, NULL, 0)
                                 : rc;
        if (id < 0) tw_log("cannot watch %s at %llx: %s", label[0] ? label : "range", (unsigned long long)addr, tagwatch_strerror((int)id));
    }
}

// The injected library must not leak into programs the target launches: they
// are not MTE-enabled and have no supervisor.
static void scrub_environment(void) {
    const char *ins = getenv("DYLD_INSERT_LIBRARIES");
    if (ins) {
        char kept[4096];
        tw_buf b;
        tw_buf_init(&b, kept, sizeof kept);
        const char *p = ins;
        while (*p) {
            const char *e = strchr(p, ':');
            size_t n = e ? (size_t)(e - p) : strlen(p);
            int ours = n >= 17 && memcmp(p + n - 17, "libtagwatch.dylib", 17) == 0;
            if (!ours && n) {
                if (b.len) tw_put_char(&b, ':');
                tw_put_mem(&b, p, n);
            }
            p += n + (e ? 1 : 0);
        }
        if (b.len) setenv("DYLD_INSERT_LIBRARIES", kept, 1);
        else unsetenv("DYLD_INSERT_LIBRARIES");
    }
    static const char *vars[] = {"TAGWATCH_AUTO", "TAGWATCH_SUPERVISED", "TAGWATCH_WATCH", "TAGWATCH_TRACE", "TAGWATCH_LOG",
                                 "TAGWATCH_VERBOSE", "TAGWATCH_BT_DEPTH", "TAGWATCH_MAX_EVENTS", "TAGWATCH_QUARANTINE"};
    for (size_t i = 0; i < sizeof vars / sizeof vars[0]; i++) unsetenv(vars[i]);
}

// Library mode without `tagwatch run`: become our own supervisor. The
// original process stays behind as the tracer and the program continues in
// the child, which is why this has to happen before other threads exist.
static int self_supervise(void) {
    if (pthread_is_threaded_np()) return -TAGWATCH_EBUSY;
    pid_t child = fork();
    if (child < 0) return -TAGWATCH_ESETUP;
    if (child == 0) return 0;
    int termsig = 0;
    int status = tw_supervise(child, &termsig);
    if (termsig) { // die the way the program died, so the shell reports it faithfully
        signal(termsig, SIG_DFL);
        kill(getpid(), termsig);
    }
    _exit(status);
}

static int init_once(void) {
    if (!tw_mte_process_enabled()) {
        tw_rt.state = TW_STATE_UNAVAILABLE;
        return -TAGWATCH_ENOTSUP;
    }
    tw_rt.verbose = env_u64("TAGWATCH_VERBOSE", 0) != 0;
    tw_rt.bt_depth = (unsigned)env_u64("TAGWATCH_BT_DEPTH", 16);
    if (tw_rt.bt_depth < 1) tw_rt.bt_depth = 1;
    tw_rt.max_events = env_u64("TAGWATCH_MAX_EVENTS", 0);
    tw_rt.supervised = getenv("TAGWATCH_SUPERVISED") != NULL;
    const char *watch = getenv("TAGWATCH_WATCH");
    if (watch) {
        char err[160];
        int n = tw_spec_parse_list(watch, tw_rt.specs, (int)(sizeof tw_rt.specs / sizeof tw_rt.specs[0]), err, sizeof err);
        if (n < 0) tw_log("ignoring TAGWATCH_WATCH: %s", err);
        else tw_rt.nspecs = n;
    }

    if (!tw_rt.supervised && !getenv("TAGWATCH_NO_FORK")) {
        int rc = self_supervise();
        if (rc != 0) {
            tw_rt.state = TW_STATE_UNAVAILABLE;
            return rc;
        }
    }
    // From here on a tag-check fault is delivered as an ordinary Mach
    // exception instead of killing the process.
    if (ptrace(PT_TRACE_ME, 0, 0, 0) != 0) {
        tw_rt.state = TW_STATE_UNAVAILABLE;
        return -TAGWATCH_ESETUP;
    }

    tw_out_init();
    const char *log = getenv("TAGWATCH_LOG");
    const char *trace = getenv("TAGWATCH_TRACE");
    int log_fd = 2;
    if (log) {
        uint64_t fd;
        if (!strcmp(log, "none")) log_fd = -1;
        else if (tw_parse_u64(log, strlen(log), &fd) == 0) log_fd = (int)fd;
    }
    tw_out_set(log_fd, trace && trace[0] ? trace : NULL);
    tw_symtab_init();
    if (tw_watch_module_init() != 0 || tw_tramp_init() != 0 || tw_arena_init() != 0 || tw_exc_start() != 0) {
        tw_rt.state = TW_STATE_UNAVAILABLE;
        return -TAGWATCH_ESETUP;
    }
    tw_arena_set_quarantine(env_u64("TAGWATCH_QUARANTINE", 1 << 20));
    pthread_key_create(&pause_key, NULL);
    pthread_atfork(NULL, NULL, atfork_child);
    tw_rt.state = TW_STATE_ON;
    tw_emit_start("out-of-line");
    apply_static_specs();
    if (getenv("TAGWATCH_AUTO")) scrub_environment();
    return 0;
}

int tagwatch_init(void) {
    // Not a lock: initialisation may fork, and an os_unfair_lock taken before
    // fork cannot be released by the child.
    int expected = 0;
    if (atomic_compare_exchange_strong(&init_phase, &expected, 1)) {
        init_result = init_once();
        atomic_store(&init_phase, 2);
    } else {
        while (atomic_load(&init_phase) != 2) usleep(100);
    }
    return init_result;
}

// When injected by `tagwatch run`, start before the program's own code.
__attribute__((constructor)) static void tw_constructor(void) {
    if (!getenv("TAGWATCH_AUTO")) return;
    int rc = tagwatch_init();
    if (rc != 0) {
        tw_log("not tracing this process: %s", tagwatch_strerror(rc));
        scrub_environment();
    }
}

__attribute__((destructor)) static void tw_destructor(void) {
    if (tw_on()) tw_emit_stats();
}

int tagwatch_available(void) { return tw_on(); }

// ---- watches ------------------------------------------------------------------
tagwatch_id tagwatch_watch_mode(const void *addr, size_t len, const char *label, int mode) {
    if (!tw_on()) return -TAGWATCH_ENOTSUP;
    if (!addr || !len || (mode & ~TAGWATCH_RW) || !mode) return -TAGWATCH_EINVAL;
    return tw_watch_add((uint64_t)(uintptr_t)addr, len, label, (unsigned)mode, TW_ORIGIN_API, NULL, 0);
}

tagwatch_id tagwatch_watch(const void *addr, size_t len, const char *label) {
    return tagwatch_watch_mode(addr, len, label, TAGWATCH_RW);
}

int tagwatch_unwatch(tagwatch_id id) {
    if (!tw_on()) return -TAGWATCH_ENOTSUP;
    return tw_watch_remove_id(id, "unwatch");
}

int tagwatch_unwatch_addr(const void *addr) {
    if (!tw_on()) return -TAGWATCH_ENOTSUP;
    return tw_watch_remove_addr((uint64_t)(uintptr_t)addr, "unwatch");
}

int tagwatch_adopt(void *addr, size_t len) {
    if (!tw_on()) return -TAGWATCH_ENOTSUP;
    if (!addr || !len) return -TAGWATCH_EINVAL;
    return tw_adopt((uint64_t)(uintptr_t)addr, len);
}

void *tagwatch_alloc(size_t size) {
    if (!tw_on()) return malloc(size);
    return tw_arena_alloc(size, TAGWATCH_GRANULE);
}

void *tagwatch_alloc_watched(size_t size, const char *label) {
    if (!tw_on()) return malloc(size);
    void *p = tw_arena_alloc(size, TAGWATCH_GRANULE);
    if (!p) return NULL;
    uint64_t bt[TW_ALLOC_BT];
    unsigned n = tw_backtrace_fp(__builtin_frame_address(0), bt, TW_ALLOC_BT);
    tw_watch_add((uint64_t)(uintptr_t)p, size ? size : 1, label ? label : "", TAGWATCH_RW, TW_ORIGIN_ALLOC, bt, n);
    return p;
}

// ---- allocation matching (called from the malloc interposers) -------------------
static int caller_matches(const tw_spec *s, const uint64_t *bt, unsigned n) {
    for (unsigned i = 0; i < n && i < s->depth; i++) {
        tw_sym sym;
        if (tw_sym_lookup(bt[i] - 1, &sym) && sym.name && !strcmp(sym.name, s->caller)) return 1;
    }
    return 0;
}

int tw_alloc_match(size_t size, const void *frame) {
    if (!tw_on() || !tw_rt.have_alloc_specs) return -1;
    uint64_t bt[64];
    int have_bt = 0;
    unsigned n = 0;
    for (int i = 0; i < tw_rt.nspecs; i++) {
        const tw_spec *s = &tw_rt.specs[i];
        if (s->kind != TW_SPEC_ALLOC || !tw_spec_size_match(s, size)) continue;
        if (s->caller[0]) {
            if (!have_bt) {
                n = tw_backtrace_fp(frame, bt, 64);
                have_bt = 1;
            }
            if (!caller_matches(s, bt, n)) continue;
        }
        uint64_t seen = atomic_fetch_add(&tw_rt.spec_seen[i], 1);
        if (seen < s->skip || (seen - s->skip) % s->every != 0) continue;
        if (s->limit && atomic_fetch_add(&tw_rt.spec_taken[i], 1) >= s->limit) continue;
        return i;
    }
    return -1;
}

void *tw_alloc_watched(size_t size, size_t align, int spec_idx, const void *frame) {
    const tw_spec *s = &tw_rt.specs[spec_idx];
    void *p = tw_arena_alloc(size, align);
    if (!p) return NULL;
    uint64_t bt[TW_ALLOC_BT];
    unsigned n = tw_backtrace_fp(frame, bt, TW_ALLOC_BT);
    const char *label = s->label[0] ? s->label : s->caller; // may be empty
    tw_watch_add((uint64_t)(uintptr_t)p, size ? size : 1, label, s->mode, TW_ORIGIN_ALLOC, bt, n);
    return p;
}

// ---- kernel accesses (called from the system-call interposers) -------------------
void tw_report_syscall(const char *name, uint64_t addr, uint64_t len, unsigned access, const void *frame) {
    tw_watch w;
    uint64_t slack = 0;
    atomic_fetch_add(&tw_rt.n_syscalls, 1);
    if (!tw_watch_hit(addr, len, addr, access, &w, &slack) || slack || !(access & w.mode)) return;
    static _Atomic uint64_t sys_seq;
    tagwatch_event ev;
    memset(&ev, 0, sizeof ev);
    uint64_t n = atomic_fetch_add(&tw_rt.n_events, 1) + 1;
    if (tw_rt.max_events && n > tw_rt.max_events) return;
    // Clip the reported range to the watched object.
    uint64_t lo = addr > w.base ? addr : w.base;
    uint64_t hi = addr + len < w.base + w.len ? addr + len : w.base + w.len;
    ev.seq = (1ull << 40) + atomic_fetch_add(&sys_seq, 1) + 1; // separate numbering from trap events
    ev.time_ns = tw_now_ns();
    ev.addr = lo;
    ev.size = (uint32_t)(hi - lo);
    ev.access = access;
    ev.watch = (tagwatch_id)w.serial;
    ev.watch_base = w.base;
    ev.watch_len = w.len;
    ev.offset = (int64_t)(lo - w.base);
    ev.label = w.label;
    pthread_threadid_np(NULL, &ev.thread_id);
    ev.flags = TAGWATCH_EV_SYSCALL | ((w.flags & TW_WF_FREED) ? TAGWATCH_EV_FREED : 0);
    ev.syscall = name;
    ev.nframes = tw_backtrace_fp(frame, ev.frames, tw_rt.bt_depth < TAGWATCH_MAX_FRAMES ? tw_rt.bt_depth : TAGWATCH_MAX_FRAMES);
    ev.pc = ev.nframes ? ev.frames[0] : 0;
    if (tw_rt.cb && tw_rt.cb(&ev, tw_rt.cb_ctx)) return;
    tw_emit_access(&ev);
}

// ---- unchecked access ---------------------------------------------------------------
void tagwatch_peek(void *dst, const void *src, size_t len) {
    if (!tw_on()) {
        memcpy(dst, src, len);
        return;
    }
    uint64_t saved = tw_tco_save_and_set();
    memcpy(dst, src, len);
    tw_tco_restore(saved);
}

void tagwatch_poke(void *dst, const void *src, size_t len) { tagwatch_peek(dst, src, len); }

void tagwatch_pause(void) {
    if (!tw_on()) return;
    uintptr_t depth = (uintptr_t)pthread_getspecific(pause_key);
    pthread_setspecific(pause_key, (void *)(depth + 1));
    tw_tco_force(1);
}

void tagwatch_resume(void) {
    if (!tw_on()) return;
    uintptr_t depth = (uintptr_t)pthread_getspecific(pause_key);
    if (depth == 0) return;
    pthread_setspecific(pause_key, (void *)(depth - 1));
    if (depth == 1) tw_tco_force(0);
}

int tagwatch_set_callback(tagwatch_callback cb, void *ctx) {
    tw_rt.cb_ctx = ctx;
    tw_rt.cb = cb;
    return 0;
}

int tagwatch_set_output(int log_fd, const char *trace_path) {
    if (!tw_on()) return -TAGWATCH_ENOTSUP;
    int rc = tw_out_set(log_fd, trace_path);
    if (rc == 0 && trace_path) tw_emit_start("out-of-line");
    return rc;
}

void tagwatch_get_stats(tagwatch_stats *out) {
    memset(out, 0, sizeof *out);
    out->events = atomic_load(&tw_rt.n_events);
    out->traps = atomic_load(&tw_rt.n_traps);
    out->filtered = atomic_load(&tw_rt.n_filtered);
    out->far_traps = atomic_load(&tw_rt.n_far);
    out->emulated = atomic_load(&tw_rt.n_emulated);
    out->syscalls = atomic_load(&tw_rt.n_syscalls);
    out->violations = atomic_load(&tw_rt.n_violations);
    if (tw_on()) {
        tw_watch_counts(&out->watches_live, &out->watches_total, &out->granules_live);
        out->trampolines = tw_tramp_count();
    }
}

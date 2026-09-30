// trace: the three outputs — a human-readable live log, a JSON-lines trace,
// and (through the CLI, which reads the trace) the summary.
//
// Everything is formatted into stack buffers and written with one write(2)
// per record, so records from different threads never interleave and the
// handler never touches stdio.
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach/mach_time.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

#include "insn.h"
#include "internal.h"
#include "symtab.h"

static int log_fd = 2, trace_fd = -1;
static os_unfair_lock out_lock = OS_UNFAIR_LOCK_INIT;
static uint64_t t0;
static mach_timebase_info_data_t tb;

void tw_out_init(void) {
    mach_timebase_info(&tb);
    t0 = mach_absolute_time();
}

uint64_t tw_now_ns(void) {
    if (!tb.denom) return 0;
    return (mach_absolute_time() - t0) * tb.numer / tb.denom;
}

void tw_out_after_fork(void) { out_lock = OS_UNFAIR_LOCK_INIT; }

int tw_out_set(int new_log_fd, const char *trace_path) {
    int nt = -1;
    if (trace_path) {
        int fd = open(trace_path, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND | O_CLOEXEC, 0644);
        if (fd < 0) return -TAGWATCH_EINVAL;
        // Keep the descriptor out of the range programs usually use.
        nt = fcntl(fd, F_DUPFD_CLOEXEC, 200);
        if (nt < 0) nt = fd;
        else close(fd);
    }
    os_unfair_lock_lock(&out_lock);
    int old = trace_fd;
    trace_fd = nt;
    log_fd = new_log_fd;
    os_unfair_lock_unlock(&out_lock);
    if (old >= 0) close(old);
    return 0;
}

static void write_all(int fd, const char *p, size_t n) {
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) return;
        p += w;
        n -= (size_t)w;
    }
}

static void flush(int fd, tw_buf *b) {
    if (fd < 0 || b->len == 0) return;
    os_unfair_lock_lock(&out_lock);
    write_all(fd, b->buf, b->len);
    os_unfair_lock_unlock(&out_lock);
}

void tw_log(const char *fmt, ...) {
    if (log_fd < 0) return;
    char s[512];
    tw_buf b;
    tw_buf_init(&b, s, sizeof s);
    tw_put_str(&b, "tagwatch: ");
    va_list ap;
    va_start(ap, fmt);
    tw_put_vfmt(&b, fmt, ap);
    va_end(ap);
    tw_put_char(&b, '\n');
    flush(log_fd, &b);
}

// "symbol+0x12 (image)" or "0x1234 (image)" or "0x1234".
static void put_frame_text(tw_buf *b, uint64_t pc, int is_return_address) {
    tw_sym s;
    // A return address points after the call; look up the call itself so a
    // call in the last instruction of a function is not attributed to the next.
    if (tw_sym_lookup(is_return_address ? pc - 1 : pc, &s)) {
        if (s.name) {
            tw_put_str(b, s.name);
            tw_put_str(b, "+");
            tw_put_hex(b, pc - s.addr);
        } else {
            tw_put_hex(b, pc);
        }
        tw_put_str(b, " (");
        tw_put_str(b, s.image);
        tw_put_char(b, ')');
    } else {
        tw_put_hex(b, pc);
    }
}

static void put_frames_json(tw_buf *b, const uint64_t *frames, unsigned n) {
    tw_put_str(b, "\"bt\":[");
    for (unsigned i = 0; i < n; i++) {
        tw_sym s;
        if (i) tw_put_char(b, ',');
        tw_put_str(b, "{\"pc\":\"");
        tw_put_hex(b, frames[i]);
        tw_put_char(b, '"');
        if (tw_sym_lookup(i ? frames[i] - 1 : frames[i], &s)) {
            if (s.name) {
                tw_put_str(b, ",\"sym\":");
                tw_put_json_str(b, s.name);
                tw_put_str(b, ",\"off\":");
                tw_put_dec(b, frames[i] - s.addr);
            }
            tw_put_str(b, ",\"img\":");
            tw_put_json_str(b, s.image);
            tw_put_str(b, ",\"imgoff\":");
            tw_put_dec(b, frames[i] - s.image_base);
        }
        tw_put_char(b, '}');
    }
    tw_put_char(b, ']');
}

static const char *origin_name(unsigned origin) {
    switch (origin) {
    case TW_ORIGIN_ALLOC: return "alloc";
    case TW_ORIGIN_SYMBOL: return "symbol";
    case TW_ORIGIN_ADDR: return "addr";
    default: return "api";
    }
}

void tw_emit_start(const char *engine) {
    if (trace_fd < 0) return;
    char s[1536];
    tw_buf b;
    tw_buf_init(&b, s, sizeof s);
    char exe[1024];
    uint32_t n = sizeof exe;
    if (_NSGetExecutablePath(exe, &n) != 0) exe[0] = 0;
    tw_put_str(&b, "{\"ev\":\"start\",\"version\":\"" TAGWATCH_VERSION "\",\"pid\":");
    tw_put_dec(&b, (uint64_t)getpid());
    tw_put_str(&b, ",\"exe\":");
    tw_put_json_str(&b, exe);
    tw_put_str(&b, ",\"engine\":");
    tw_put_json_str(&b, engine);
    tw_put_str(&b, ",\"granule\":16}\n");
    flush(trace_fd, &b);
}

void tw_emit_watch(const tw_watch *w, const uint64_t *bt, unsigned nbt) {
    char s[2048];
    tw_buf b;
    if (trace_fd >= 0) {
        tw_buf_init(&b, s, sizeof s);
        tw_put_str(&b, "{\"ev\":\"watch\",\"id\":");
        tw_put_dec(&b, w->serial);
        tw_put_str(&b, ",\"t_ns\":");
        tw_put_dec(&b, tw_now_ns());
        tw_put_str(&b, ",\"base\":\"");
        tw_put_hex(&b, w->base);
        tw_put_str(&b, "\",\"len\":");
        tw_put_dec(&b, w->len);
        tw_put_str(&b, ",\"armed_base\":\"");
        tw_put_hex(&b, w->gbase);
        tw_put_str(&b, "\",\"armed_len\":");
        tw_put_dec(&b, w->glen);
        tw_put_str(&b, ",\"origin\":\"");
        tw_put_str(&b, origin_name(w->origin));
        tw_put_str(&b, "\",\"label\":");
        tw_put_json_str(&b, w->label);
        if (nbt) {
            tw_put_char(&b, ',');
            // Allocation backtraces hold return addresses only.
            tw_put_str(&b, "\"bt\":[");
            for (unsigned i = 0; i < nbt; i++) {
                tw_sym sy;
                if (i) tw_put_char(&b, ',');
                tw_put_str(&b, "{\"pc\":\"");
                tw_put_hex(&b, bt[i]);
                tw_put_char(&b, '"');
                if (tw_sym_lookup(bt[i] - 1, &sy)) {
                    if (sy.name) {
                        tw_put_str(&b, ",\"sym\":");
                        tw_put_json_str(&b, sy.name);
                        tw_put_str(&b, ",\"off\":");
                        tw_put_dec(&b, bt[i] - sy.addr);
                    }
                    tw_put_str(&b, ",\"img\":");
                    tw_put_json_str(&b, sy.image);
                }
                tw_put_char(&b, '}');
            }
            tw_put_char(&b, ']');
        }
        tw_put_str(&b, "}\n");
        flush(trace_fd, &b);
    }
    if (log_fd >= 0 && (tw_rt.verbose || w->origin != TW_ORIGIN_ALLOC)) {
        tw_buf_init(&b, s, sizeof s);
        tw_put_str(&b, "tagwatch: watch #");
        tw_put_dec(&b, w->serial);
        tw_put_str(&b, " armed: ");
        tw_put_dec(&b, w->len);
        tw_put_str(&b, " bytes at ");
        tw_put_hex(&b, w->base);
        if (w->label[0]) {
            tw_put_str(&b, " \"");
            tw_put_str(&b, w->label);
            tw_put_char(&b, '"');
        }
        if (nbt) {
            tw_put_str(&b, " allocated by ");
            put_frame_text(&b, bt[0], 1);
        }
        tw_put_char(&b, '\n');
        flush(log_fd, &b);
    }
}

void tw_emit_unwatch(uint64_t serial, const char *reason, uint64_t reads, uint64_t writes) {
    char s[256];
    tw_buf b;
    if (trace_fd >= 0) {
        tw_buf_init(&b, s, sizeof s);
        tw_put_str(&b, "{\"ev\":\"unwatch\",\"id\":");
        tw_put_dec(&b, serial);
        tw_put_str(&b, ",\"t_ns\":");
        tw_put_dec(&b, tw_now_ns());
        tw_put_str(&b, ",\"reason\":");
        tw_put_json_str(&b, reason);
        tw_put_str(&b, ",\"reads\":");
        tw_put_dec(&b, reads);
        tw_put_str(&b, ",\"writes\":");
        tw_put_dec(&b, writes);
        tw_put_str(&b, "}\n");
        flush(trace_fd, &b);
    }
    if (log_fd >= 0 && tw_rt.verbose) {
        tw_buf_init(&b, s, sizeof s);
        tw_put_str(&b, "tagwatch: watch #");
        tw_put_dec(&b, serial);
        tw_put_str(&b, " removed (");
        tw_put_str(&b, reason);
        tw_put_str(&b, ")\n");
        flush(log_fd, &b);
    }
}

void tw_emit_freed(uint64_t serial) {
    if (trace_fd < 0) return;
    char s[128];
    tw_buf b;
    tw_buf_init(&b, s, sizeof s);
    tw_put_str(&b, "{\"ev\":\"free\",\"id\":");
    tw_put_dec(&b, serial);
    tw_put_str(&b, ",\"t_ns\":");
    tw_put_dec(&b, tw_now_ns());
    tw_put_str(&b, "}\n");
    flush(trace_fd, &b);
}

void tw_emit_access(const tagwatch_event *ev) {
    char s[8192];
    tw_buf b;
    const char *kind = tw_access_name(ev->access);
    if (trace_fd >= 0) {
        tw_buf_init(&b, s, sizeof s);
        tw_put_str(&b, "{\"ev\":\"access\",\"seq\":");
        tw_put_dec(&b, ev->seq);
        tw_put_str(&b, ",\"t_ns\":");
        tw_put_dec(&b, ev->time_ns);
        tw_put_str(&b, ",\"kind\":\"");
        tw_put_str(&b, kind);
        tw_put_str(&b, "\",\"size\":");
        tw_put_dec(&b, ev->size);
        tw_put_str(&b, ",\"addr\":\"");
        tw_put_hex(&b, ev->addr);
        tw_put_str(&b, "\",\"watch\":");
        tw_put_sdec(&b, ev->watch);
        tw_put_str(&b, ",\"off\":");
        tw_put_sdec(&b, ev->offset);
        tw_put_str(&b, ",\"tid\":");
        tw_put_dec(&b, ev->thread_id);
        if (ev->flags & TAGWATCH_EV_FREED) tw_put_str(&b, ",\"freed\":true");
        if (ev->flags & TAGWATCH_EV_ATOMIC) tw_put_str(&b, ",\"llsc\":true");
        if (ev->flags & TAGWATCH_EV_SYSCALL) {
            tw_put_str(&b, ",\"syscall\":");
            tw_put_json_str(&b, ev->syscall);
        }
        tw_put_char(&b, ',');
        put_frames_json(&b, ev->frames, ev->nframes);
        tw_put_str(&b, "}\n");
        if (!b.truncated) flush(trace_fd, &b);
    }
    if (log_fd >= 0) {
        tw_buf_init(&b, s, sizeof s);
        tw_put_str(&b, "tagwatch: #");
        tw_put_dec(&b, ev->seq);
        tw_put_char(&b, ' ');
        tw_put_str(&b, ev->access == TAGWATCH_READ ? "READ " : ev->access == TAGWATCH_WRITE ? "WRITE" : "RW   ");
        tw_put_char(&b, ' ');
        tw_put_dec(&b, ev->size);
        tw_put_str(&b, ev->size == 1 ? " byte  at " : " bytes at ");
        tw_put_hex(&b, ev->addr);
        tw_put_str(&b, "  watch #");
        tw_put_sdec(&b, ev->watch);
        if (ev->label && ev->label[0]) {
            tw_put_str(&b, " \"");
            tw_put_str(&b, ev->label);
            tw_put_char(&b, '"');
        }
        tw_put_str(&b, ev->offset < 0 ? " " : " +");
        tw_put_sdec(&b, ev->offset);
        tw_put_str(&b, "  thread ");
        tw_put_dec(&b, ev->thread_id);
        if (ev->flags & TAGWATCH_EV_FREED) tw_put_str(&b, "  [USE AFTER FREE]");
        if (ev->flags & TAGWATCH_EV_SYSCALL) {
            tw_put_str(&b, "  [kernel, ");
            tw_put_str(&b, ev->syscall);
            tw_put_str(&b, "()]");
        }
        tw_put_char(&b, '\n');
        for (unsigned i = 0; i < ev->nframes; i++) {
            tw_put_str(&b, "    ");
            put_frame_text(&b, ev->frames[i], i != 0);
            tw_put_char(&b, '\n');
        }
        flush(log_fd, &b);
    }
}

void tw_emit_violation(uint64_t addr, uint64_t pc, uint64_t tid, unsigned access, unsigned size, const uint64_t *frames,
                       unsigned nframes) {
    char s[8192];
    tw_buf b;
    if (trace_fd >= 0) {
        tw_buf_init(&b, s, sizeof s);
        tw_put_str(&b, "{\"ev\":\"violation\",\"t_ns\":");
        tw_put_dec(&b, tw_now_ns());
        tw_put_str(&b, ",\"kind\":\"");
        tw_put_str(&b, tw_access_name(access));
        tw_put_str(&b, "\",\"size\":");
        tw_put_dec(&b, size);
        tw_put_str(&b, ",\"addr\":\"");
        tw_put_hex(&b, addr);
        tw_put_str(&b, "\",\"tid\":");
        tw_put_dec(&b, tid);
        tw_put_char(&b, ',');
        put_frames_json(&b, frames, nframes);
        tw_put_str(&b, "}\n");
        flush(trace_fd, &b);
    }
    if (log_fd >= 0) {
        tw_buf_init(&b, s, sizeof s);
        tw_put_str(&b, "tagwatch: MTE tag-check fault that is NOT a watchpoint: ");
        tw_put_str(&b, tw_access_name(access));
        tw_put_str(&b, " at ");
        tw_put_hex(&b, addr);
        tw_put_str(&b, ", pc ");
        tw_put_hex(&b, pc);
        tw_put_str(&b, ", thread ");
        tw_put_dec(&b, tid);
        tw_put_str(&b, "\ntagwatch: this is a memory-safety error in the program (or in memory tagwatch does not track);"
                       " the kernel will now terminate it.\n");
        for (unsigned i = 0; i < nframes; i++) {
            tw_put_str(&b, "    ");
            put_frame_text(&b, frames[i], i != 0);
            tw_put_char(&b, '\n');
        }
        flush(log_fd, &b);
    }
}

static void emit_note(const char *kind, const char *msg, int to_log) {
    char s[512];
    tw_buf b;
    if (trace_fd >= 0) {
        tw_buf_init(&b, s, sizeof s);
        tw_put_str(&b, "{\"ev\":\"note\",\"t_ns\":");
        tw_put_dec(&b, tw_now_ns());
        tw_put_str(&b, ",\"kind\":");
        tw_put_json_str(&b, kind);
        tw_put_str(&b, ",\"msg\":");
        tw_put_json_str(&b, msg);
        tw_put_str(&b, "}\n");
        flush(trace_fd, &b);
    }
    if (to_log && log_fd >= 0) {
        tw_buf_init(&b, s, sizeof s);
        tw_put_str(&b, "tagwatch: ");
        tw_put_str(&b, msg);
        tw_put_char(&b, '\n');
        flush(log_fd, &b);
    }
}

void tw_emit_note(const char *kind, const char *msg) { emit_note(kind, msg, 1); }

// Problems the user must see even when the live log is off: always on
// stderr, and recorded in the trace so the summary repeats them.
void tw_warn(const char *fmt, ...) {
    char msg[400], line[512];
    tw_buf b;
    tw_buf_init(&b, msg, sizeof msg);
    va_list ap;
    va_start(ap, fmt);
    tw_put_vfmt(&b, fmt, ap);
    va_end(ap);
    emit_note("warning", msg, 0);
    tw_buf_init(&b, line, sizeof line);
    tw_put_str(&b, "tagwatch: ");
    tw_put_str(&b, msg);
    tw_put_char(&b, '\n');
    flush(2, &b);
}

void tw_emit_stats(void) {
    if (trace_fd < 0) return;
    char s[512];
    tw_buf b;
    tagwatch_stats st;
    tagwatch_get_stats(&st);
    tw_buf_init(&b, s, sizeof s);
    tw_put_fmt(&b,
               "{\"ev\":\"stats\",\"t_ns\":%llu,\"events\":%llu,\"traps\":%llu,\"filtered\":%llu,\"far_traps\":%llu,"
               "\"emulated\":%llu,\"syscalls\":%llu,\"violations\":%llu,\"watches_total\":%llu,\"watches_live\":%llu,"
               "\"trampolines\":%llu}\n",
               (unsigned long long)tw_now_ns(), (unsigned long long)st.events, (unsigned long long)st.traps,
               (unsigned long long)st.filtered, (unsigned long long)st.far_traps, (unsigned long long)st.emulated,
               (unsigned long long)st.syscalls, (unsigned long long)st.violations, (unsigned long long)st.watches_total,
               (unsigned long long)st.watches_live, (unsigned long long)st.trampolines);
    flush(trace_fd, &b);
}

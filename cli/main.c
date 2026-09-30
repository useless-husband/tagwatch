// tagwatch: command-line front end.
//
//   tagwatch run [options] -- program [args...]   launch and watch a program
//   tagwatch report [options] trace.jsonl         summarise a saved trace
//   tagwatch check                                is this machine usable?
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../include/tagwatch.h"
#include "../src/fmt.h"
#include "../src/spec.h"
#include "../src/supervise.h"
#include "report.h"

extern char **environ;

#ifndef _POSIX_SPAWN_DISABLE_ASLR
#define _POSIX_SPAWN_DISABLE_ASLR 0x0100
#endif

// Private libsystem_kernel SPI (declared in XNU's bsd/sys/spawn_internal.h).
// Asks the kernel to start the child with the security-transition shims,
// which is what turns MTE on for a binary that carries no entitlements.
typedef int (*shim_fn)(posix_spawnattr_t *attr, uint32_t flags);
#define SHIM_SPI "posix_spawnattr_set_use_sec_transition_shims_np"

static void usage(FILE *out) {
    fprintf(out,
            "tagwatch " TAGWATCH_VERSION " - MTE data watchpoints for Apple Silicon (M5 or later)\n"
            "\n"
            "usage: tagwatch run [options] -- program [args...]\n"
            "       tagwatch report [options] trace.jsonl\n"
            "       tagwatch check\n"
            "\n"
            "what to watch (repeatable):\n"
            "  -a, --watch-alloc SPEC     heap objects by size and/or allocating function:\n"
            "                             size=48   size=32..128   caller=make_node   size=48,caller=f,every=10\n"
            "                             other keys: depth=N skip=N limit=N rw=r|w|rw label=NAME\n"
            "  -s, --watch-symbol NAME[:LEN]   a global variable of the program (image=NAME for a library)\n"
            "  -x, --watch-addr ADDR:LEN       an address range (use with --no-aslr)\n"
            "\n"
            "output:\n"
            "  -t, --trace FILE           keep the JSON-lines trace in FILE\n"
            "  -l, --log FILE             write the live log to FILE instead of stderr\n"
            "  -q, --quiet                no live log (summary only)\n"
            "      --no-summary           do not print the summary at exit\n"
            "      --heatmap              add per-offset heat maps to the summary\n"
            "      --top N                access sites shown in the summary (default 20, 0 = all)\n"
            "      --frames N             frames that identify an access site (default 6)\n"
            "\n"
            "behaviour:\n"
            "  -w, --writes-only          report writes only (reads still trap, but are not logged)\n"
            "      --depth N              backtrace depth (default 16, max 32)\n"
            "      --max-events N         stop logging after N accesses\n"
            "      --quarantine BYTES     freed watched objects kept armed to catch use-after-free (default 1m, 0 = off)\n"
            "      --no-aslr              load the program at fixed addresses\n"
            "      --lib PATH             location of libtagwatch.dylib\n"
            "      --no-runtime           only enable MTE for the program; insert nothing, watch nothing (for measurements)\n"
            "  -v, --verbose              also log watches as they are armed and removed\n");
}

static int hw_has_mte(void) {
    int v = 0;
    size_t n = sizeof v;
    return sysctlbyname("hw.optional.arm.FEAT_MTE", &v, &n, NULL, 0) == 0 && v;
}

// libtagwatch.dylib lives next to this executable, or in ../lib.
static int find_lib(const char *override, char *out, size_t cap) {
    if (override) {
        if (!realpath(override, out)) return -1;
        return access(out, R_OK);
    }
    char exe[PATH_MAX], real[PATH_MAX];
    uint32_t n = sizeof exe;
    if (_NSGetExecutablePath(exe, &n) != 0 || !realpath(exe, real)) return -1;
    char *slash = strrchr(real, '/');
    if (!slash) return -1;
    *slash = 0;
    static const char *rel[] = {"%s/libtagwatch.dylib", "%s/../lib/libtagwatch.dylib"};
    for (size_t i = 0; i < 2; i++) {
        char cand[PATH_MAX];
        snprintf(cand, sizeof cand, rel[i], real);
        if (access(cand, R_OK) == 0 && realpath(cand, out)) return 0;
    }
    (void)cap;
    return -1;
}

static int find_program(const char *name, char *out) {
    if (strchr(name, '/')) return realpath(name, out) && access(out, X_OK) == 0 ? 0 : -1;
    const char *path = getenv("PATH");
    if (!path) path = "/usr/bin:/bin";
    while (*path) {
        const char *e = strchr(path, ':');
        size_t n = e ? (size_t)(e - path) : strlen(path);
        char cand[PATH_MAX];
        snprintf(cand, sizeof cand, "%.*s/%s", (int)n, path, name);
        if (n && access(cand, X_OK) == 0 && realpath(cand, out)) return 0;
        path += n + (e ? 1 : 0);
    }
    return -1;
}

// Launches argv with MTE enabled and the runtime inserted; returns the pid.
// lib == NULL starts the program with MTE on but without the runtime.
static pid_t launch(const char *prog, char **argv, const char *lib, int no_aslr, char *const extra_env[], int n_extra) {
    shim_fn set_shims = (shim_fn)dlsym(RTLD_DEFAULT, SHIM_SPI);
    if (!set_shims) {
        fprintf(stderr, "tagwatch: this macOS has no " SHIM_SPI "; cannot enable MTE for the program\n");
        return -1;
    }
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    if (set_shims(&attr, 1) != 0) {
        fprintf(stderr, "tagwatch: " SHIM_SPI " failed\n");
        return -1;
    }
    short flags = POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK;
    if (no_aslr) flags |= _POSIX_SPAWN_DISABLE_ASLR;
    sigset_t none, all;
    sigemptyset(&none);
    sigfillset(&all);
    posix_spawnattr_setsigmask(&attr, &none);
    posix_spawnattr_setsigdefault(&attr, &all);
    posix_spawnattr_setflags(&attr, flags);

    // Environment: ours plus the insertion and the configuration.
    size_t n_env = 0;
    while (environ[n_env]) n_env++;
    char **env = calloc(n_env + (size_t)n_extra + 2, sizeof *env);
    if (!env) return -1;
    size_t k = 0;
    char *insert = NULL;
    for (size_t i = 0; i < n_env; i++) {
        if (lib && !strncmp(environ[i], "DYLD_INSERT_LIBRARIES=", 22)) {
            if (asprintf(&insert, "DYLD_INSERT_LIBRARIES=%s:%s", lib, environ[i] + 22) < 0) return -1;
            continue;
        }
        if (!strncmp(environ[i], "TAGWATCH_", 9)) continue; // only what this invocation asks for
        env[k++] = environ[i];
    }
    if (lib && !insert && asprintf(&insert, "DYLD_INSERT_LIBRARIES=%s", lib) < 0) return -1;
    if (insert) env[k++] = insert;
    for (int i = 0; lib && i < n_extra; i++) env[k++] = extra_env[i];
    env[k] = NULL;

    pid_t pid = -1;
    int rc = posix_spawn(&pid, prog, NULL, &attr, argv, env);
    posix_spawnattr_destroy(&attr);
    free(insert);
    free(env);
    if (rc != 0) {
        fprintf(stderr, "tagwatch: cannot start %s: %s\n", prog, strerror(rc));
        return -1;
    }
    return pid;
}

static char *env_pair(const char *name, const char *value) {
    char *s = NULL;
    if (asprintf(&s, "%s=%s", name, value) < 0) exit(2);
    return s;
}

static int64_t need_number(const char *opt, const char *val) {
    uint64_t v;
    if (!val || tw_parse_u64(val, strlen(val), &v) != 0) {
        fprintf(stderr, "tagwatch: %s needs a number\n", opt);
        exit(2);
    }
    return (int64_t)v;
}

// Appends one canonical spec to the ';'-separated list, after validating it.
static void add_spec(char *list, size_t cap, const char *text, int writes_only) {
    tw_spec s;
    char err[160], canon[512];
    if (tw_spec_parse(text, strlen(text), &s, err, sizeof err) != 0) {
        fprintf(stderr, "tagwatch: bad watch '%s': %s\n", text, err);
        exit(2);
    }
    if (writes_only && s.mode == TW_MODE_RW) s.mode = TW_MODE_WRITE;
    if (tw_spec_format(&s, canon, sizeof canon) < 0 || strlen(list) + strlen(canon) + 2 > cap) {
        fprintf(stderr, "tagwatch: too many watch specifications\n");
        exit(2);
    }
    if (list[0]) strlcat(list, ";", cap);
    strlcat(list, canon, cap);
}

static int cmd_run(int argc, char **argv) {
    char raw[16][600];
    int n_raw = 0;
    const char *trace = NULL, *log = NULL, *lib_override = NULL;
    int quiet = 0, no_summary = 0, writes_only = 0, no_aslr = 0, verbose = 0, no_runtime = 0;
    int64_t depth = -1, max_events = -1, quarantine = -1;
    tw_report_opts ropts;
    tw_report_default_opts(&ropts);

    int i = 0;
    for (; i < argc; i++) {
        const char *a = argv[i];
        const char *val = i + 1 < argc ? argv[i + 1] : NULL;
#define IS(s, l) (!strcmp(a, s) || !strcmp(a, l))
#define NEED_VAL()                                                       \
    do {                                                                 \
        if (!val) {                                                      \
            fprintf(stderr, "tagwatch: %s needs an argument\n", a);      \
            return 2;                                                    \
        }                                                                \
        i++;                                                             \
    } while (0)
        if (!strcmp(a, "--")) {
            i++;
            break;
        }
        if (a[0] != '-') break; // first non-option starts the program
        if (n_raw == 16 && (IS("-a", "--watch-alloc") || IS("-s", "--watch-symbol") || IS("-x", "--watch-addr"))) {
            fprintf(stderr, "tagwatch: at most 16 watch specifications\n");
            return 2;
        }
        if (IS("-a", "--watch-alloc")) {
            NEED_VAL();
            snprintf(raw[n_raw++], sizeof raw[0], "alloc:%s", val);
        } else if (IS("-s", "--watch-symbol")) {
            NEED_VAL();
            if (strchr(val, '=')) snprintf(raw[n_raw++], sizeof raw[0], "symbol:%s", val);
            else {
                const char *colon = strrchr(val, ':');
                if (colon) snprintf(raw[n_raw++], sizeof raw[0], "symbol:name=%.*s,len=%s", (int)(colon - val), val, colon + 1);
                else snprintf(raw[n_raw++], sizeof raw[0], "symbol:name=%s", val);
            }
        } else if (IS("-x", "--watch-addr")) {
            NEED_VAL();
            if (strchr(val, '=')) snprintf(raw[n_raw++], sizeof raw[0], "addr:%s", val);
            else {
                const char *colon = strrchr(val, ':');
                if (!colon) {
                    fprintf(stderr, "tagwatch: --watch-addr wants ADDR:LEN\n");
                    return 2;
                }
                snprintf(raw[n_raw++], sizeof raw[0], "addr:base=%.*s,len=%s", (int)(colon - val), val, colon + 1);
            }
        } else if (IS("-t", "--trace")) {
            NEED_VAL();
            trace = val;
        } else if (IS("-l", "--log")) {
            NEED_VAL();
            log = val;
        } else if (IS("-q", "--quiet")) quiet = 1;
        else if (!strcmp(a, "--no-summary")) no_summary = 1;
        else if (!strcmp(a, "--heatmap")) ropts.heatmap = 1;
        else if (!strcmp(a, "--top")) {
            NEED_VAL();
            ropts.top = (int)need_number(a, val);
        } else if (!strcmp(a, "--frames")) {
            NEED_VAL();
            ropts.frames = (int)need_number(a, val);
        } else if (IS("-w", "--writes-only")) writes_only = 1;
        else if (!strcmp(a, "--depth")) {
            NEED_VAL();
            depth = need_number(a, val);
        } else if (!strcmp(a, "--max-events")) {
            NEED_VAL();
            max_events = need_number(a, val);
        } else if (!strcmp(a, "--quarantine")) {
            NEED_VAL();
            quarantine = need_number(a, val);
        } else if (!strcmp(a, "--no-aslr")) no_aslr = 1;
        else if (!strcmp(a, "--no-runtime")) no_runtime = 1;
        else if (!strcmp(a, "--lib")) {
            NEED_VAL();
            lib_override = val;
        } else if (IS("-v", "--verbose")) verbose = 1;
        else if (IS("-h", "--help")) {
            usage(stdout);
            return 0;
        } else {
            fprintf(stderr, "tagwatch: unknown option %s (try tagwatch --help)\n", a);
            return 2;
        }
    }
    if (i >= argc) {
        fprintf(stderr, "tagwatch: no program given (usage: tagwatch run [options] -- program [args...])\n");
        return 2;
    }
    static char specs[8192];
    for (int k = 0; k < n_raw; k++) add_spec(specs, sizeof specs, raw[k], writes_only);
    if (n_raw == 0 && !no_runtime)
        fprintf(stderr, "tagwatch: no --watch-* option given; the program will run with MTE enabled and only watches\n"
                        "tagwatch: it sets itself through the tagwatch API will be reported\n");

    if (!hw_has_mte()) {
        fprintf(stderr, "tagwatch: this CPU has no Memory Tagging Extension (hw.optional.arm.FEAT_MTE is 0); an M5 or later is required\n");
        return 2;
    }
    char lib[PATH_MAX], prog[PATH_MAX];
    if (find_lib(lib_override, lib, sizeof lib) != 0) {
        fprintf(stderr, "tagwatch: cannot find libtagwatch.dylib (looked next to the tagwatch binary and in ../lib; use --lib)\n");
        return 2;
    }
    if (find_program(argv[i], prog) != 0) {
        fprintf(stderr, "tagwatch: %s: not found or not executable\n", argv[i]);
        return 2;
    }

    // The summary is built from the trace, so there is always one; it is a
    // temporary file unless the user asked to keep it.
    char tmp_trace[PATH_MAX];
    const char *tmpdir = getenv("TMPDIR");
    snprintf(tmp_trace, sizeof tmp_trace, "%s/tagwatch.XXXXXX", tmpdir && tmpdir[0] ? tmpdir : "/tmp");
    int temp = 0;
    if (!trace) {
        int fd = mkstemp(tmp_trace);
        if (fd < 0) {
            perror("tagwatch: mkstemp");
            return 2;
        }
        close(fd);
        trace = tmp_trace;
        temp = 1;
    }
    char trace_abs[PATH_MAX];
    if (trace[0] != '/') {
        char cwd[PATH_MAX];
        if (!getcwd(cwd, sizeof cwd)) return 2;
        snprintf(trace_abs, sizeof trace_abs, "%s/%s", cwd, trace);
    } else {
        snprintf(trace_abs, sizeof trace_abs, "%s", trace);
    }

    char *extra[12];
    int ne = 0;
    char num[32];
    extra[ne++] = env_pair("TAGWATCH_AUTO", "1");
    extra[ne++] = env_pair("TAGWATCH_SUPERVISED", "1");
    extra[ne++] = env_pair("TAGWATCH_TRACE", trace_abs);
    if (specs[0]) extra[ne++] = env_pair("TAGWATCH_WATCH", specs);
    if (verbose) extra[ne++] = env_pair("TAGWATCH_VERBOSE", "1");
    int log_fd = -1;
    if (quiet) extra[ne++] = env_pair("TAGWATCH_LOG", "none");
    else if (log) {
        log_fd = open(log, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
        if (log_fd < 0) {
            fprintf(stderr, "tagwatch: cannot open %s: %s\n", log, strerror(errno));
            return 2;
        }
        snprintf(num, sizeof num, "%d", log_fd); // inherited by the child
        extra[ne++] = env_pair("TAGWATCH_LOG", num);
    }
    if (depth >= 0) {
        snprintf(num, sizeof num, "%lld", (long long)depth);
        extra[ne++] = env_pair("TAGWATCH_BT_DEPTH", num);
    }
    if (max_events >= 0) {
        snprintf(num, sizeof num, "%lld", (long long)max_events);
        extra[ne++] = env_pair("TAGWATCH_MAX_EVENTS", num);
    }
    if (quarantine >= 0) {
        snprintf(num, sizeof num, "%lld", (long long)quarantine);
        extra[ne++] = env_pair("TAGWATCH_QUARANTINE", num);
    }

    pid_t pid = launch(prog, argv + i, no_runtime ? NULL : lib, no_aslr, extra, ne);
    if (pid < 0) {
        if (temp) unlink(tmp_trace);
        return 2;
    }
    int termsig = 0;
    int status = tw_supervise(pid, &termsig);
    if (no_runtime) { // nothing was traced: there is no summary to print
        if (temp) unlink(tmp_trace);
        return status;
    }
    if (log_fd >= 0) close(log_fd);

    tw_report *rep = tw_report_new(&ropts);
    tw_report_totals tot;
    memset(&tot, 0, sizeof tot);
    if (rep) {
        tw_report_read(rep, trace_abs);
        tw_report_get_totals(rep, &tot);
        if (!tot.started)
            fprintf(stderr, "tagwatch: the runtime never started inside %s, so nothing was watched.\n"
                            "tagwatch: binaries with the hardened runtime, and system binaries protected by SIP, ignore\n"
                            "tagwatch: DYLD_INSERT_LIBRARIES and cannot be traced.\n",
                    prog);
        else if (!no_summary) {
            fputc('\n', stderr);
            tw_report_print(rep, stderr);
        }
        tw_report_free(rep);
    }
    if (termsig) fprintf(stderr, "tagwatch: %s was terminated by signal %d (%s)\n", argv[i], termsig, strsignal(termsig));
    if (temp) unlink(tmp_trace);
    return status;
}

static int cmd_report(int argc, char **argv) {
    tw_report_opts o;
    tw_report_default_opts(&o);
    const char *path = NULL;
    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--heatmap")) o.heatmap = 1;
        else if (!strcmp(a, "--no-demangle")) o.demangle = 0;
        else if (!strcmp(a, "--top") && i + 1 < argc) o.top = (int)need_number(a, argv[++i]);
        else if (!strcmp(a, "--frames") && i + 1 < argc) o.frames = (int)need_number(a, argv[++i]);
        else if (!strcmp(a, "--heat-bytes") && i + 1 < argc) o.heat_bytes = (int)need_number(a, argv[++i]);
        else if (a[0] == '-') {
            fprintf(stderr, "tagwatch report: unknown option %s\n"
                            "usage: tagwatch report [--heatmap] [--heat-bytes N] [--top N] [--frames N] [--no-demangle] trace.jsonl\n", a);
            return 2;
        } else path = a;
    }
    if (!path) {
        fprintf(stderr, "usage: tagwatch report [--heatmap] [--heat-bytes N] [--top N] [--frames N] [--no-demangle] trace.jsonl\n");
        return 2;
    }
    tw_report *rep = tw_report_new(&o);
    if (!rep || tw_report_read(rep, path) < 0) {
        fprintf(stderr, "tagwatch: cannot read %s: %s\n", path, strerror(errno));
        return 1;
    }
    tw_report_print(rep, stdout);
    tw_report_free(rep);
    return 0;
}

// Child side of `tagwatch check`: started with the shims and the runtime
// inserted. A 4321-byte allocation is watched by the parent's spec; touch it.
static int check_child(void) {
    volatile char *p = malloc(4321);
    if (!p) return 3;
    p[7] = 1;
    char c = p[7];
    free((void *)p);
    return c == 1 ? 0 : 4;
}

static int cmd_check(int argc, char **argv) {
    int quiet = argc > 0 && !strcmp(argv[0], "--quiet");
#define SAY(...)                                 \
    do {                                         \
        if (!quiet) printf(__VA_ARGS__);         \
    } while (0)
    int ok = 1;
    int mte = hw_has_mte();
    SAY("CPU has MTE (hw.optional.arm.FEAT_MTE)      %s\n", mte ? "yes" : "NO  - an Apple M5 or later is required");
    ok &= mte;
    int spi = dlsym(RTLD_DEFAULT, SHIM_SPI) != NULL;
    SAY("spawn SPI to enable MTE in a child          %s\n", spi ? "yes" : "NO  - " SHIM_SPI " is missing");
    ok &= spi;
    char lib[PATH_MAX] = "";
    int have_lib = find_lib(NULL, lib, sizeof lib) == 0;
    SAY("libtagwatch.dylib                           %s\n", have_lib ? lib : "NOT FOUND next to the tagwatch binary");
    ok &= have_lib;
    if (ok) {
        // End to end: launch ourselves, watch one allocation, expect its two accesses.
        char exe[PATH_MAX], real[PATH_MAX], trace[PATH_MAX];
        const char *tmpdir = getenv("TMPDIR");
        snprintf(trace, sizeof trace, "%s/tagwatch-check.XXXXXX", tmpdir && tmpdir[0] ? tmpdir : "/tmp");
        uint32_t n = sizeof exe;
        int fd = mkstemp(trace);
        if (fd >= 0) close(fd);
        char *child_argv[] = {real, "__check_child", NULL};
        char *extra[] = {env_pair("TAGWATCH_AUTO", "1"), env_pair("TAGWATCH_SUPERVISED", "1"), env_pair("TAGWATCH_TRACE", trace),
                         env_pair("TAGWATCH_WATCH", "alloc:size=4321"), env_pair("TAGWATCH_LOG", "none")};
        uint64_t accesses = 0;
        int status = -1;
        if (fd >= 0 && _NSGetExecutablePath(exe, &n) == 0 && realpath(exe, real)) {
            pid_t pid = launch(real, child_argv, lib, 0, extra, 5);
            if (pid > 0) {
                status = tw_supervise(pid, NULL);
                tw_report_opts o;
                tw_report_default_opts(&o);
                tw_report *rep = tw_report_new(&o);
                tw_report_totals tot;
                if (rep) {
                    tw_report_read(rep, trace);
                    tw_report_get_totals(rep, &tot);
                    accesses = tot.accesses;
                    tw_report_free(rep);
                }
            }
        }
        unlink(trace);
        int e2e = status == 0 && accesses == 2;
        SAY("end-to-end self test (watch, trap, resume)  %s\n", e2e ? "passed" : "FAILED");
        if (!e2e) SAY("    child status %d, %llu accesses reported (expected 0 and 2)\n", status, (unsigned long long)accesses);
        ok &= e2e;
    }
    SAY("%s\n", ok ? "tagwatch can be used on this machine." : "tagwatch cannot be used on this machine.");
    return ok ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc >= 2 && !strcmp(argv[1], "__check_child")) return check_child();
    if (argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") || !strcmp(argv[1], "help")) {
        usage(argc < 2 ? stderr : stdout);
        return argc < 2 ? 2 : 0;
    }
    if (!strcmp(argv[1], "--version") || !strcmp(argv[1], "version")) {
        printf("tagwatch " TAGWATCH_VERSION "\n");
        return 0;
    }
    if (!strcmp(argv[1], "run")) return cmd_run(argc - 2, argv + 2);
    if (!strcmp(argv[1], "report")) return cmd_report(argc - 2, argv + 2);
    if (!strcmp(argv[1], "check")) return cmd_check(argc - 2, argv + 2);
    fprintf(stderr, "tagwatch: unknown command '%s' (run, report, check)\n", argv[1]);
    return 2;
}

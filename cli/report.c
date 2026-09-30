#include "report.h"

#include <stdlib.h>
#include <string.h>

#include "json.h"

extern char *__cxa_demangle(const char *mangled, char *buf, size_t *len, int *status);

#define MAX_FRAMES 32
#define SITE_BUCKETS 4096
#define HEAT_MAX_ROWS 4096

typedef struct {
    int64_t id;
    uint64_t base, len;
    char *label, *origin, *site; // site: where it was allocated
    uint64_t reads, writes, rw, after_free, by_kernel;
    int seen, live;
    char *end_reason;
    uint32_t *heat_r, *heat_w;
    uint32_t heat_rows;
} watch_t;

typedef struct site {
    struct site *next;
    char *key;
    char *frames[MAX_FRAMES];
    int nframes;
    char kind[8];
    uint64_t count;
    uint64_t size_min, size_max;
    int64_t off_min, off_max;
    int64_t first_watch;
    uint64_t n_watches; // distinct watches hit (exact while small)
    int64_t watches[8];
    uint64_t tids[8];
    int n_tids;
    int after_free, by_kernel;
    char *syscall;
} site_t;

typedef struct {
    char *kind, *addr;
    char *frames[MAX_FRAMES];
    int nframes;
} violation_t;

struct tw_report {
    tw_report_opts opts;
    watch_t *watches;
    size_t n_watches_cap;
    site_t *buckets[SITE_BUCKETS];
    uint64_t n_sites;
    violation_t violations[16];
    char *notes[32];
    int n_notes;
    uint64_t tids[256];
    int n_tids;
    char *exe;
    int64_t pid;
    tw_report_totals tot;
    int have_stats;
    int64_t st_traps, st_filtered, st_far, st_emulated, st_tramps;
};

void tw_report_default_opts(tw_report_opts *o) {
    o->top = 20;
    o->frames = 6;
    o->heatmap = 0;
    o->heat_bytes = 8;
    o->demangle = 1;
}

tw_report *tw_report_new(const tw_report_opts *o) {
    tw_report *r = calloc(1, sizeof *r);
    if (!r) return NULL;
    r->opts = *o;
    if (r->opts.frames < 1) r->opts.frames = 1;
    if (r->opts.frames > MAX_FRAMES) r->opts.frames = MAX_FRAMES;
    if (r->opts.heat_bytes < 1) r->opts.heat_bytes = 1;
    return r;
}

void tw_report_free(tw_report *r) {
    if (!r) return;
    for (size_t i = 0; i < r->n_watches_cap; i++) {
        watch_t *w = &r->watches[i];
        free(w->label), free(w->origin), free(w->site), free(w->end_reason), free(w->heat_r), free(w->heat_w);
    }
    free(r->watches);
    for (int b = 0; b < SITE_BUCKETS; b++)
        for (site_t *s = r->buckets[b], *n; s; s = n) {
            n = s->next;
            for (int i = 0; i < s->nframes; i++) free(s->frames[i]);
            free(s->key), free(s->syscall), free(s);
        }
    for (int i = 0; i < 16; i++) {
        free(r->violations[i].kind), free(r->violations[i].addr);
        for (int k = 0; k < r->violations[i].nframes; k++) free(r->violations[i].frames[k]);
    }
    for (int i = 0; i < r->n_notes; i++) free(r->notes[i]);
    free(r->exe);
    free(r);
}

static watch_t *watch_slot(tw_report *r, int64_t id) {
    if (id <= 0 || id > (1 << 26)) return NULL;
    if ((size_t)id >= r->n_watches_cap) {
        size_t ncap = r->n_watches_cap ? r->n_watches_cap : 64;
        while (ncap <= (size_t)id) ncap *= 2;
        watch_t *nw = realloc(r->watches, ncap * sizeof *nw);
        if (!nw) return NULL;
        memset(nw + r->n_watches_cap, 0, (ncap - r->n_watches_cap) * sizeof *nw);
        r->watches = nw;
        r->n_watches_cap = ncap;
    }
    return &r->watches[id];
}

// "symbol+0x12 (image)", demangled if requested. Returns a malloc'd string.
static char *frame_text(const tw_report *r, const jval *f) {
    const char *sym = json_str(f, "sym", NULL), *img = json_str(f, "img", NULL), *pc = json_str(f, "pc", "?");
    char *dem = NULL;
    if (sym && r->opts.demangle && sym[0] == '_' && sym[1] == 'Z') {
        int status = 0;
        dem = __cxa_demangle(sym, NULL, NULL, &status);
        if (status != 0) {
            free(dem);
            dem = NULL;
        }
    }
    char buf[1024];
    if (sym && img) snprintf(buf, sizeof buf, "%s+0x%llx (%s)", dem ? dem : sym, (unsigned long long)json_int(f, "off", 0), img);
    else if (img) snprintf(buf, sizeof buf, "%s (%s)", pc, img);
    else snprintf(buf, sizeof buf, "%s", pc);
    free(dem);
    return strdup(buf);
}

static uint64_t hash_str(const char *s) {
    uint64_t h = 1469598103934665603ull;
    for (; *s; s++) h = (h ^ (unsigned char)*s) * 1099511628211ull;
    return h;
}

static void note_tid(uint64_t *set, int *n, int cap, uint64_t tid) {
    for (int i = 0; i < *n; i++)
        if (set[i] == tid) return;
    if (*n < cap) set[(*n)++] = tid;
}

static void heat_add(const tw_report *r, watch_t *w, const char *kind, int64_t off, uint64_t size) {
    if (!r->opts.heatmap || !w->len) return;
    if (!w->heat_r) {
        uint64_t rows = (w->len + (uint64_t)r->opts.heat_bytes - 1) / (uint64_t)r->opts.heat_bytes;
        if (rows > HEAT_MAX_ROWS) rows = HEAT_MAX_ROWS;
        w->heat_rows = (uint32_t)rows;
        w->heat_r = calloc(rows, sizeof *w->heat_r);
        w->heat_w = calloc(rows, sizeof *w->heat_w);
        if (!w->heat_r || !w->heat_w) return;
    }
    // Clip the access to the object, then mark every row it overlaps.
    int64_t lo = off < 0 ? 0 : off, hi = off + (int64_t)size;
    if (hi > (int64_t)w->len) hi = (int64_t)w->len;
    uint64_t row_bytes = (w->len + w->heat_rows - 1) / w->heat_rows;
    if (row_bytes < (uint64_t)r->opts.heat_bytes) row_bytes = (uint64_t)r->opts.heat_bytes;
    for (int64_t b = lo; b < hi;) {
        uint64_t row = (uint64_t)b / row_bytes;
        if (row >= w->heat_rows) break;
        if (kind[0] == 'r') w->heat_r[row]++; // "read" and "rw"
        if (kind[0] == 'w' || kind[1] == 'w') w->heat_w[row]++;
        b = (int64_t)((row + 1) * row_bytes);
    }
}

static void feed_access(tw_report *r, const jval *o) {
    const char *kind = json_str(o, "kind", "?");
    int64_t id = json_int(o, "watch", 0), off = json_int(o, "off", 0);
    uint64_t size = (uint64_t)json_int(o, "size", 0), tid = (uint64_t)json_int(o, "tid", 0);
    int after_free = json_int(o, "freed", 0) != 0;
    const char *syscall = json_str(o, "syscall", NULL);
    r->tot.accesses++;
    if (!strcmp(kind, "read")) r->tot.reads++;
    else if (!strcmp(kind, "write")) r->tot.writes++;
    else r->tot.rw++;
    if (after_free) r->tot.after_free++;
    if (syscall) r->tot.by_kernel++;
    note_tid(r->tids, &r->n_tids, 256, tid);

    watch_t *w = watch_slot(r, id);
    if (w) {
        if (!strcmp(kind, "read")) w->reads++;
        else if (!strcmp(kind, "write")) w->writes++;
        else w->rw++;
        if (after_free) w->after_free++;
        if (syscall) w->by_kernel++;
        heat_add(r, w, kind, off, size);
    }

    // Site key: kind, flags and the top frames.
    char *frames[MAX_FRAMES];
    int nf = 0;
    const jval *bt = json_get(o, "bt");
    if (bt && bt->type == J_ARR)
        for (const jval *f = bt->child; f && nf < r->opts.frames; f = f->next) frames[nf++] = frame_text(r, f);
    size_t klen = 32;
    for (int i = 0; i < nf; i++) klen += strlen(frames[i]) + 1;
    char *key = malloc(klen);
    if (!key) return;
    size_t at = (size_t)snprintf(key, klen, "%s|%d|%s", kind, after_free, syscall ? syscall : "");
    for (int i = 0; i < nf; i++) at += (size_t)snprintf(key + at, klen - at, "|%s", frames[i]);

    site_t **bucket = &r->buckets[hash_str(key) % SITE_BUCKETS], *s;
    for (s = *bucket; s && strcmp(s->key, key) != 0; s = s->next) {}
    if (!s) {
        s = calloc(1, sizeof *s);
        if (!s) {
            free(key);
            return;
        }
        s->key = key;
        for (int i = 0; i < nf; i++) s->frames[i] = frames[i];
        s->nframes = nf;
        snprintf(s->kind, sizeof s->kind, "%s", kind);
        s->size_min = s->size_max = size;
        s->off_min = s->off_max = off;
        s->first_watch = id;
        s->after_free = after_free;
        s->by_kernel = syscall != NULL;
        s->syscall = syscall ? strdup(syscall) : NULL;
        s->next = *bucket;
        *bucket = s;
        r->n_sites++;
    } else {
        free(key);
        for (int i = 0; i < nf; i++) free(frames[i]);
    }
    s->count++;
    if (size < s->size_min) s->size_min = size;
    if (size > s->size_max) s->size_max = size;
    if (off < s->off_min) s->off_min = off;
    if (off > s->off_max) s->off_max = off;
    note_tid(s->tids, &s->n_tids, 8, tid);
    int known = 0;
    for (uint64_t i = 0; i < s->n_watches && i < 8; i++) known |= s->watches[i] == id;
    if (!known) {
        if (s->n_watches < 8) s->watches[s->n_watches] = id;
        s->n_watches++; // beyond 8 this over-counts repeats; printed as "8+"
    }
}

int tw_report_feed(tw_report *r, char *line) {
    static jval pool[512];
    r->tot.lines++;
    jval *o = json_parse(line, pool, (int)(sizeof pool / sizeof pool[0]));
    const char *ev = o ? json_str(o, "ev", NULL) : NULL;
    if (!ev) {
        r->tot.bad_lines++;
        return -1;
    }
    if (!strcmp(ev, "access")) {
        feed_access(r, o);
    } else if (!strcmp(ev, "watch")) {
        watch_t *w = watch_slot(r, json_int(o, "id", 0));
        if (w && !w->seen) {
            w->seen = w->live = 1;
            w->id = json_int(o, "id", 0);
            w->base = json_hex(o, "base");
            w->len = (uint64_t)json_int(o, "len", 0);
            w->label = strdup(json_str(o, "label", ""));
            w->origin = strdup(json_str(o, "origin", "api"));
            const jval *bt = json_get(o, "bt");
            if (bt && bt->type == J_ARR && bt->child) w->site = frame_text(r, bt->child);
            r->tot.watches++;
            r->tot.watches_live++;
        }
    } else if (!strcmp(ev, "unwatch")) {
        watch_t *w = watch_slot(r, json_int(o, "id", 0));
        if (w && w->seen && w->live) {
            w->live = 0;
            w->end_reason = strdup(json_str(o, "reason", ""));
            r->tot.watches_live--;
        }
    } else if (!strcmp(ev, "violation")) {
        if (r->tot.violations < 16) {
            violation_t *v = &r->violations[r->tot.violations];
            v->kind = strdup(json_str(o, "kind", "?"));
            v->addr = strdup(json_str(o, "addr", "?"));
            const jval *bt = json_get(o, "bt");
            if (bt && bt->type == J_ARR)
                for (const jval *f = bt->child; f && v->nframes < MAX_FRAMES; f = f->next) v->frames[v->nframes++] = frame_text(r, f);
        }
        r->tot.violations++;
    } else if (!strcmp(ev, "note")) {
        if (r->n_notes < 32) r->notes[r->n_notes++] = strdup(json_str(o, "msg", ""));
    } else if (!strcmp(ev, "start")) {
        if (!r->tot.started) {
            r->tot.started = 1;
            r->exe = strdup(json_str(o, "exe", ""));
            r->pid = json_int(o, "pid", 0);
        }
    } else if (!strcmp(ev, "stats")) {
        r->have_stats = 1;
        r->st_traps = json_int(o, "traps", 0);
        r->st_filtered = json_int(o, "filtered", 0);
        r->st_far = json_int(o, "far_traps", 0);
        r->st_emulated = json_int(o, "emulated", 0);
        r->st_tramps = json_int(o, "trampolines", 0);
    }
    return 0;
}

long tw_report_read(tw_report *r, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char *line = NULL;
    size_t cap = 0;
    long n = 0;
    ssize_t len;
    while ((len = getline(&line, &cap, f)) > 0) {
        if (len == 1 && line[0] == '\n') continue;
        tw_report_feed(r, line);
        n++;
    }
    free(line);
    fclose(f);
    return n;
}

void tw_report_get_totals(const tw_report *r, tw_report_totals *t) {
    *t = r->tot;
    t->sites = r->n_sites;
    t->threads = (uint64_t)r->n_tids;
}

static int by_count_desc(const void *a, const void *b) {
    const site_t *x = *(site_t *const *)a, *y = *(site_t *const *)b;
    if (x->count != y->count) return x->count < y->count ? 1 : -1;
    return strcmp(x->key, y->key); // stable output for equal counts
}

static uint64_t watch_total(const watch_t *w) { return w->reads + w->writes + w->rw; }

static int watch_by_total_desc(const void *a, const void *b) {
    const watch_t *x = *(watch_t *const *)a, *y = *(watch_t *const *)b;
    uint64_t tx = watch_total(x), ty = watch_total(y);
    if (tx != ty) return tx < ty ? 1 : -1;
    return x->id < y->id ? -1 : x->id > y->id;
}

static void print_bar(FILE *out, uint64_t v, uint64_t max) {
    int n = max ? (int)((v * 40 + max - 1) / max) : 0;
    for (int i = 0; i < n; i++) fputc('#', out);
}

static void print_heat(const tw_report *r, const watch_t *w, FILE *out) {
    if (!w->heat_r || !w->heat_w) return;
    uint64_t row_bytes = (w->len + w->heat_rows - 1) / w->heat_rows, max = 0;
    if (row_bytes < (uint64_t)r->opts.heat_bytes) row_bytes = (uint64_t)r->opts.heat_bytes;
    for (uint32_t i = 0; i < w->heat_rows; i++) {
        uint64_t v = (uint64_t)w->heat_r[i] + w->heat_w[i];
        if (v > max) max = v;
    }
    fprintf(out, "\nHeat map of watch #%lld \"%s\" (%llu bytes, %llu bytes per row)\n", (long long)w->id, w->label,
            (unsigned long long)w->len, (unsigned long long)row_bytes);
    fprintf(out, "    offset       reads    writes\n");
    uint32_t skipped = 0;
    for (uint32_t i = 0; i < w->heat_rows; i++) {
        if (!w->heat_r[i] && !w->heat_w[i]) { // collapse runs of untouched rows
            skipped++;
            continue;
        }
        if (skipped) fprintf(out, "    ...          (%u untouched row%s)\n", skipped, skipped == 1 ? "" : "s");
        skipped = 0;
        fprintf(out, "    +%-8llu %8u  %8u  ", (unsigned long long)(i * row_bytes), w->heat_r[i], w->heat_w[i]);
        print_bar(out, (uint64_t)w->heat_r[i] + w->heat_w[i], max);
        fputc('\n', out);
    }
    if (skipped) fprintf(out, "    ...          (%u untouched row%s)\n", skipped, skipped == 1 ? "" : "s");
}

void tw_report_print(const tw_report *r, FILE *out) {
    const tw_report_totals *t = &r->tot;
    fprintf(out, "== tagwatch summary ==\n");
    if (r->exe && r->exe[0]) fprintf(out, "program    %s (pid %lld)\n", r->exe, (long long)r->pid);
    fprintf(out, "accesses   %llu reported: %llu read, %llu write, %llu read-modify-write\n", (unsigned long long)t->accesses,
            (unsigned long long)t->reads, (unsigned long long)t->writes, (unsigned long long)t->rw);
    if (t->by_kernel) fprintf(out, "           %llu made by the kernel in system calls\n", (unsigned long long)t->by_kernel);
    if (t->after_free) fprintf(out, "           %llu to objects that had already been freed\n", (unsigned long long)t->after_free);
    fprintf(out, "watches    %llu armed, %llu still armed at exit\n", (unsigned long long)t->watches,
            (unsigned long long)t->watches_live);
    fprintf(out, "threads    %d\n", r->n_tids);
    if (r->have_stats)
        fprintf(out, "traps      %lld taken (%lld not reported: filtered or granule neighbours; %lld via the slow return path; "
                     "%lld LL/SC emulated); %lld execution slots\n",
                (long long)r->st_traps, (long long)r->st_filtered, (long long)r->st_far, (long long)r->st_emulated,
                (long long)r->st_tramps);
    if (t->violations) fprintf(out, "VIOLATIONS %llu MTE tag-check faults that were not watchpoints (see below)\n", (unsigned long long)t->violations);
    if (t->bad_lines) fprintf(out, "warning    %llu unreadable trace lines were skipped\n", (unsigned long long)t->bad_lines);

    // Watched objects.
    size_t nw = 0;
    watch_t **ws = calloc(r->n_watches_cap + 1, sizeof *ws);
    if (!ws) return;
    for (size_t i = 0; i < r->n_watches_cap; i++)
        if (r->watches[i].seen) ws[nw++] = &r->watches[i];
    qsort(ws, nw, sizeof *ws, watch_by_total_desc);
    if (nw) {
        size_t shown = nw > 12 ? 12 : nw;
        fprintf(out, "\nWatched objects, busiest first%s\n", nw > shown ? " (top 12)" : "");
        for (size_t i = 0; i < shown; i++) {
            const watch_t *w = ws[i];
            fprintf(out, "  #%-4lld %llu bytes at 0x%llx", (long long)w->id, (unsigned long long)w->len, (unsigned long long)w->base);
            if (w->label[0]) fprintf(out, " \"%s\"", w->label);
            if (w->site) fprintf(out, ", allocated by %s", w->site);
            fprintf(out, "\n        %llu reads, %llu writes", (unsigned long long)w->reads, (unsigned long long)w->writes);
            if (w->rw) fprintf(out, ", %llu read-modify-writes", (unsigned long long)w->rw);
            if (w->by_kernel) fprintf(out, ", %llu by the kernel", (unsigned long long)w->by_kernel);
            if (w->after_free) fprintf(out, ", %llu AFTER FREE", (unsigned long long)w->after_free);
            if (!w->live && w->end_reason) fprintf(out, "; ended: %s", w->end_reason);
            fputc('\n', out);
        }
        if (nw > shown) {
            uint64_t rest = 0, idle = 0;
            for (size_t i = shown; i < nw; i++) {
                rest += watch_total(ws[i]);
                idle += watch_total(ws[i]) == 0;
            }
            fprintf(out, "  ... and %zu more objects with %llu accesses in total (%llu never accessed)\n", nw - shown,
                    (unsigned long long)rest, (unsigned long long)idle);
        }
    }

    // Access sites.
    site_t **sites = calloc(r->n_sites + 1, sizeof *sites);
    if (!sites) {
        free(ws);
        return;
    }
    size_t ns = 0;
    for (int b = 0; b < SITE_BUCKETS; b++)
        for (site_t *s = r->buckets[b]; s; s = s->next) sites[ns++] = s;
    qsort(sites, ns, sizeof *sites, by_count_desc);
    if (ns) {
        size_t shown = r->opts.top > 0 && (size_t)r->opts.top < ns ? (size_t)r->opts.top : ns;
        if (shown < ns) fprintf(out, "\nAccess sites, busiest first (top %zu of %zu)\n", shown, ns);
        else fprintf(out, "\nAccess sites, busiest first\n");
        for (size_t i = 0; i < shown; i++) {
            const site_t *s = sites[i];
            fprintf(out, "  %8llu  %-5s ", (unsigned long long)s->count, s->kind);
            if (s->size_min == s->size_max) fprintf(out, "%llu byte%s", (unsigned long long)s->size_min, s->size_min == 1 ? "" : "s");
            else fprintf(out, "%llu..%llu bytes", (unsigned long long)s->size_min, (unsigned long long)s->size_max);
            const watch_t *w = s->first_watch > 0 && (size_t)s->first_watch < r->n_watches_cap ? &r->watches[s->first_watch] : NULL;
            if (s->n_watches == 1 && w && w->seen) {
                fprintf(out, "  watch #%lld", (long long)w->id);
                if (w->label[0]) fprintf(out, " \"%s\"", w->label);
            } else {
                fprintf(out, "  %llu%s watches", (unsigned long long)(s->n_watches > 8 ? 8 : s->n_watches), s->n_watches > 8 ? "+" : "");
                if (w && w->seen && w->label[0]) fprintf(out, " (\"%s\", ...)", w->label);
            }
            if (s->off_min == s->off_max) fprintf(out, "  offset %+lld", (long long)s->off_min);
            else fprintf(out, "  offsets %+lld..%+lld", (long long)s->off_min, (long long)s->off_max);
            if (s->n_tids > 1) fprintf(out, "  %d%s threads", s->n_tids, s->n_tids == 8 ? "+" : "");
            if (s->by_kernel) fprintf(out, "  [kernel, %s()]", s->syscall);
            if (s->after_free) fprintf(out, "  [USE AFTER FREE]");
            fputc('\n', out);
            for (int k = 0; k < s->nframes; k++) fprintf(out, "              %s\n", s->frames[k]);
        }
    }

    if (r->opts.heatmap)
        for (size_t i = 0; i < nw && i < 12; i++) print_heat(r, ws[i], out);

    for (uint64_t i = 0; i < t->violations && i < 16; i++) {
        const violation_t *v = &r->violations[i];
        fprintf(out, "\nViolation %llu: %s at %s\n", (unsigned long long)(i + 1), v->kind, v->addr);
        for (int k = 0; k < v->nframes; k++) fprintf(out, "    %s\n", v->frames[k]);
    }
    if (r->n_notes) {
        fprintf(out, "\nNotes\n");
        for (int i = 0; i < r->n_notes; i++) fprintf(out, "  %s\n", r->notes[i]);
    }
    free(sites);
    free(ws);
}

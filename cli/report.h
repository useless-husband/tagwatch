// report: turns a JSON-lines trace into the end-of-run summary — watched
// objects, access sites with symbolised backtraces, and per-offset heat maps.
#ifndef TW_REPORT_H
#define TW_REPORT_H

#include <stdint.h>
#include <stdio.h>

typedef struct {
    int top;        // access sites to print (0 = all)
    int frames;     // backtrace frames that identify and describe a site
    int heatmap;    // print a heat map per watched object
    int heat_bytes; // bytes per heat-map row
    int demangle;   // demangle C++ names
} tw_report_opts;

typedef struct tw_report tw_report;

void tw_report_default_opts(tw_report_opts *o);
tw_report *tw_report_new(const tw_report_opts *o);
void tw_report_free(tw_report *r);

// Feeds one trace line (modified in place). Returns 0, or -1 if the line is
// not valid JSON (it is counted and otherwise ignored).
int tw_report_feed(tw_report *r, char *line);
// Reads a whole trace file. Returns the number of lines, or -1.
long tw_report_read(tw_report *r, const char *path);
void tw_report_print(const tw_report *r, FILE *out);

// Totals, for tests and for the CLI's one-line status.
typedef struct {
    uint64_t lines, bad_lines;
    uint64_t accesses, reads, writes, rw;
    uint64_t after_free, by_kernel, violations;
    uint64_t watches, watches_live, watches_freed, sites, threads;
    int started; // a "start" record was seen: the runtime was loaded
} tw_report_totals;
void tw_report_get_totals(const tw_report *r, tw_report_totals *t);

#endif

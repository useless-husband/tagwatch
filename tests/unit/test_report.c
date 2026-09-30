#include "../../cli/report.h"
#include "t.h"

static void feed(tw_report *r, const char *line) {
    char buf[2048];
    snprintf(buf, sizeof buf, "%s", line);
    tw_report_feed(r, buf);
}

static char *render(const tw_report *r) {
    static char out[65536];
    FILE *f = fmemopen(out, sizeof out - 1, "w");
    tw_report_print(r, f);
    fclose(f);
    return out;
}

int main(void) {
    tw_report_opts o;
    tw_report_default_opts(&o);
    o.heatmap = 1;
    tw_report *r = tw_report_new(&o);
    CHECK(r != NULL);

    feed(r, "{\"ev\":\"start\",\"version\":\"0.1.0\",\"pid\":77,\"exe\":\"/tmp/demo\",\"engine\":\"out-of-line\",\"granule\":16}");
    feed(r, "{\"ev\":\"watch\",\"id\":1,\"t_ns\":5,\"base\":\"0x1000\",\"len\":48,\"armed_base\":\"0x1000\",\"armed_len\":48,"
            "\"origin\":\"alloc\",\"label\":\"node\",\"bt\":[{\"pc\":\"0x10\",\"sym\":\"make_node\",\"off\":32,\"img\":\"demo\"}]}");
    feed(r, "{\"ev\":\"watch\",\"id\":2,\"t_ns\":6,\"base\":\"0x2000\",\"len\":16,\"armed_base\":\"0x2000\",\"armed_len\":16,"
            "\"origin\":\"symbol\",\"label\":\"g_counter\"}");
    // Three writes from one site, by two threads, at two offsets.
    for (int i = 0; i < 3; i++) {
        char line[512];
        snprintf(line, sizeof line,
                 "{\"ev\":\"access\",\"seq\":%d,\"t_ns\":10,\"kind\":\"write\",\"size\":8,\"addr\":\"0x1010\",\"watch\":1,\"off\":%d,"
                 "\"tid\":%d,\"bt\":[{\"pc\":\"0x20\",\"sym\":\"update\",\"off\":52,\"img\":\"demo\"},"
                 "{\"pc\":\"0x30\",\"sym\":\"main\",\"off\":288,\"img\":\"demo\"}]}",
                 i + 1, i == 2 ? 24 : 16, i == 0 ? 100 : 101);
        feed(r, line);
    }
    // One read elsewhere, one C++ frame, one use-after-free, one kernel access.
    feed(r, "{\"ev\":\"access\",\"seq\":4,\"t_ns\":11,\"kind\":\"read\",\"size\":4,\"addr\":\"0x2000\",\"watch\":2,\"off\":0,\"tid\":100,"
            "\"bt\":[{\"pc\":\"0x40\",\"sym\":\"_ZN4Tree6insertEi\",\"off\":12,\"img\":\"demo\"}]}");
    feed(r, "{\"ev\":\"free\",\"id\":1,\"t_ns\":12}");
    feed(r, "{\"ev\":\"access\",\"seq\":5,\"t_ns\":13,\"kind\":\"rw\",\"size\":8,\"addr\":\"0x1000\",\"watch\":1,\"off\":0,\"tid\":100,"
            "\"freed\":true,\"bt\":[{\"pc\":\"0x50\",\"img\":\"demo\",\"imgoff\":80}]}");
    feed(r, "{\"ev\":\"access\",\"seq\":1099511627777,\"t_ns\":14,\"kind\":\"write\",\"size\":5,\"addr\":\"0x2000\",\"watch\":2,\"off\":0,"
            "\"tid\":100,\"syscall\":\"read\",\"bt\":[{\"pc\":\"0x60\",\"sym\":\"main\",\"off\":300,\"img\":\"demo\"}]}");
    feed(r, "{\"ev\":\"violation\",\"t_ns\":15,\"kind\":\"write\",\"size\":1,\"addr\":\"0x9999\",\"tid\":100,"
            "\"bt\":[{\"pc\":\"0x70\",\"sym\":\"overflow\",\"off\":4,\"img\":\"demo\"}]}");
    feed(r, "{\"ev\":\"unwatch\",\"id\":1,\"t_ns\":15,\"reason\":\"quarantine-evict\",\"reads\":0,\"writes\":3}");
    feed(r, "{\"ev\":\"note\",\"t_ns\":16,\"kind\":\"fork\",\"msg\":\"forked child runs without watches\"}");
    feed(r, "{\"ev\":\"stats\",\"t_ns\":17,\"events\":6,\"traps\":7,\"filtered\":1,\"far_traps\":2,\"emulated\":0,\"syscalls\":1,"
            "\"violations\":1,\"watches_total\":2,\"watches_live\":1,\"trampolines\":4}");
    feed(r, "this is not json");
    feed(r, "{\"no_ev\":1}");

    tw_report_totals t;
    tw_report_get_totals(r, &t);
    CHECK_EQ(t.lines, 16);
    CHECK_EQ(t.watches_freed, 1);
    CHECK_EQ(t.bad_lines, 2);
    CHECK_EQ(t.accesses, 6);
    CHECK_EQ(t.reads, 1);
    CHECK_EQ(t.writes, 4);
    CHECK_EQ(t.rw, 1);
    CHECK_EQ(t.after_free, 1);
    CHECK_EQ(t.by_kernel, 1);
    CHECK_EQ(t.violations, 1);
    CHECK_EQ(t.watches, 2);
    CHECK_EQ(t.watches_live, 1);
    CHECK_EQ(t.sites, 4);
    CHECK_EQ(t.threads, 2);
    CHECK(t.started);

    const char *out = render(r);
    CHECK(strstr(out, "program    /tmp/demo (pid 77)"));
    CHECK(strstr(out, "6 reported: 1 read, 4 write, 1 read-modify-write"));
    CHECK(strstr(out, "2 armed, 1 still armed at exit (1 objects were freed by the program)"));
    CHECK(strstr(out, "allocated by make_node+0x20 (demo)"));
    CHECK(strstr(out, "0 reads, 3 writes, 1 read-modify-writes, 1 AFTER FREE; freed"));
    // The busiest site comes first and merges both offsets and both threads.
    const char *site = strstr(out, "Access sites");
    CHECK(site != NULL);
    if (site) {
        const char *first = strstr(site, "3  write 8 bytes  watch #1 \"node\"  offsets +16..+24  2 threads");
        CHECK(first != NULL);
        CHECK(first && strstr(first, "update+0x34 (demo)") && strstr(first, "main+0x120 (demo)"));
        CHECK(first && strstr(out, "[USE AFTER FREE]") > first);
    }
    CHECK(strstr(out, "Tree::insert(int)+0xc (demo)")); // demangled
    CHECK(strstr(out, "[kernel, read()]"));
    CHECK(strstr(out, "0x50 (demo)")); // frame without a symbol
    CHECK(strstr(out, "Violation 1: write at 0x9999"));
    CHECK(strstr(out, "overflow+0x4 (demo)"));
    CHECK(strstr(out, "forked child runs without watches"));
    CHECK(strstr(out, "2 unreadable trace lines"));
    CHECK(strstr(out, "7 taken (1 not reported"));
    // Heat map of the 48-byte node: writes at +16 (twice) and +24, rw at +0.
    const char *heat = strstr(out, "Heat map of watch #1 \"node\" (48 bytes, 8 bytes per row)");
    CHECK(strstr(out, "Watched objects\n"));
    CHECK(heat != NULL);
    if (heat) {
        CHECK(strstr(heat, "+0               1         1"));
        CHECK(strstr(heat, "+16              0         2"));
        CHECK(strstr(heat, "+24              0         1"));
        CHECK(strstr(heat, "untouched row"));
    }
    tw_report_free(r);

    // --top limits sites; demangling can be turned off; an access that
    // straddles the end of the object is clipped in the heat map.
    o.top = 1;
    o.demangle = 0;
    o.heat_bytes = 16;
    r = tw_report_new(&o);
    feed(r, "{\"ev\":\"watch\",\"id\":1,\"base\":\"0x1000\",\"len\":24,\"origin\":\"api\",\"label\":\"\"}");
    feed(r, "{\"ev\":\"access\",\"seq\":1,\"kind\":\"read\",\"size\":16,\"addr\":\"0xff8\",\"watch\":1,\"off\":-8,\"tid\":1,"
            "\"bt\":[{\"pc\":\"0x40\",\"sym\":\"_ZN4Tree6insertEi\",\"off\":12,\"img\":\"demo\"}]}");
    feed(r, "{\"ev\":\"access\",\"seq\":2,\"kind\":\"write\",\"size\":16,\"addr\":\"0x1010\",\"watch\":1,\"off\":16,\"tid\":1,\"bt\":[]}");
    feed(r, "{\"ev\":\"access\",\"seq\":3,\"kind\":\"write\",\"size\":16,\"addr\":\"0x1010\",\"watch\":1,\"off\":16,\"tid\":1,\"bt\":[]}");
    feed(r, "{\"ev\":\"access\",\"seq\":4,\"kind\":\"write\",\"size\":1,\"addr\":\"0x5000\",\"watch\":999999999,\"off\":0,\"tid\":1,\"bt\":[]}");
    out = render(r);
    CHECK(strstr(out, "(top 1 of 2)"));
    CHECK(strstr(out, "  2 watches  offsets +0..+16")); // watch 1 and the unknown id 999999999
    CHECK(strstr(out, "_ZN4Tree6insertEi") == NULL); // the C++ site is not the busiest
    CHECK(strstr(out, "+0               1         0"));
    CHECK(strstr(out, "+16              0         2"));
    tw_report_get_totals(r, &t);
    CHECK(!t.started);
    CHECK_EQ(t.accesses, 4);
    tw_report_free(r);

    // Many objects of one kind are summarised as a group, with a merged heat map.
    tw_report_default_opts(&o);
    o.heatmap = 1;
    r = tw_report_new(&o);
    for (int i = 1; i <= 40; i++) {
        char line[512];
        snprintf(line, sizeof line,
                 "{\"ev\":\"watch\",\"id\":%d,\"base\":\"0x%x\",\"len\":16,\"origin\":\"alloc\",\"label\":\"node\","
                 "\"bt\":[{\"pc\":\"0x10\",\"sym\":\"make_node\",\"off\":32,\"img\":\"demo\"}]}",
                 i, 0x1000 + i * 32);
        feed(r, line);
        for (int k = 0; k < (i == 7 ? 5 : i <= 30 ? 1 : 0); k++) {
            snprintf(line, sizeof line,
                     "{\"ev\":\"access\",\"seq\":1,\"kind\":\"write\",\"size\":8,\"addr\":\"0x0\",\"watch\":%d,\"off\":8,\"tid\":1,"
                     "\"bt\":[{\"pc\":\"0x20\",\"sym\":\"f\",\"off\":4,\"img\":\"demo\"}]}",
                     i);
            feed(r, line);
        }
        if (i % 2 == 0) {
            snprintf(line, sizeof line, "{\"ev\":\"free\",\"id\":%d}", i);
            feed(r, line);
        }
    }
    feed(r, "{\"ev\":\"watch\",\"id\":41,\"base\":\"0x9000\",\"len\":8,\"origin\":\"symbol\",\"label\":\"g\"}");
    out = render(r);
    CHECK(strstr(out, "40 objects, 16 bytes each \"node\", allocated by make_node+0x20 (demo)"));
    CHECK(strstr(out, "0 reads, 34 writes; 20 freed; 10 never accessed"));
    CHECK(strstr(out, "busiest: #7 (5) #1 (1)"));
    CHECK(strstr(out, "#41   8 bytes at 0x9000 \"g\""));
    CHECK(strstr(out, "34  write 8 bytes  30 watches (\"node\", ...)  offset +8"));
    CHECK(strstr(out, "Heat map of 40 objects \"node\" (16 bytes each, 8 bytes per row)"));
    CHECK(strstr(out, "+8               0        34"));
    tw_report_free(r);

    // An empty trace prints a well-formed, empty summary.
    tw_report_default_opts(&o);
    r = tw_report_new(&o);
    out = render(r);
    CHECK(strstr(out, "accesses   0 reported"));
    CHECK(tw_report_read(r, "/nonexistent/trace.jsonl") == -1);
    tw_report_free(r);
    return t_done("report");
}

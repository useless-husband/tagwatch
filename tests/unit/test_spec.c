#include "../../src/spec.h"
#include "t.h"

static int parse(const char *s, tw_spec *out) {
    char err[128];
    return tw_spec_parse(s, strlen(s), out, err, sizeof err);
}

static const char *parse_err(const char *s) {
    static char err[128];
    tw_spec sp;
    err[0] = 0;
    CHECK(tw_spec_parse(s, strlen(s), &sp, err, sizeof err) == -1);
    return err;
}

int main(void) {
    tw_spec s;
    CHECK(parse("alloc:size=48", &s) == 0);
    CHECK(s.kind == TW_SPEC_ALLOC && s.size_min == 48 && s.size_max == 48 && s.every == 1 && s.depth == 4 && s.mode == TW_MODE_RW);
    CHECK(tw_spec_size_match(&s, 48) && !tw_spec_size_match(&s, 47) && !tw_spec_size_match(&s, 49));

    CHECK(parse("alloc:size=32..128,caller=make_node,depth=2,every=10,skip=3,limit=5,rw=w,label=nodes", &s) == 0);
    CHECK(s.size_min == 32 && s.size_max == 128 && s.depth == 2 && s.every == 10 && s.skip == 3 && s.limit == 5);
    CHECK(s.mode == TW_MODE_WRITE);
    CHECK_STR(s.caller, "make_node");
    CHECK_STR(s.label, "nodes");
    CHECK(parse("alloc:size=4k..", &s) == 0 && s.size_min == 4096 && s.size_max == UINT64_MAX);
    CHECK(parse("alloc:size=..64", &s) == 0 && s.size_min == 0 && s.size_max == 64);
    CHECK(parse("alloc:caller=operator_new", &s) == 0 && s.size_min == 0 && s.size_max == UINT64_MAX);

    CHECK(parse("symbol:name=g_table", &s) == 0 && s.kind == TW_SPEC_SYMBOL && s.len == 0);
    CHECK(parse("symbol:name=g_table,len=64,off=8,image=libfoo.dylib,rw=r", &s) == 0);
    CHECK(s.len == 64 && s.off == 8 && s.mode == TW_MODE_READ);
    CHECK_STR(s.image, "libfoo.dylib");

    CHECK(parse("addr:base=0x100008000,len=16", &s) == 0 && s.kind == TW_SPEC_ADDR && s.base == 0x100008000ull && s.len == 16);

    CHECK(strstr(parse_err("size=48"), "kind:key=value"));
    CHECK(strstr(parse_err("heap:size=48"), "unknown watch kind"));
    CHECK(strstr(parse_err("alloc:"), "needs size= or caller="));
    CHECK(strstr(parse_err("alloc:every=2"), "needs size= or caller="));
    CHECK(strstr(parse_err("alloc:size=128..32"), "bad value"));
    CHECK(strstr(parse_err("alloc:size=abc"), "bad value"));
    CHECK(strstr(parse_err("alloc:size=48,every=0"), "bad value"));
    CHECK(strstr(parse_err("alloc:size=48,depth=0"), "bad value"));
    CHECK(strstr(parse_err("alloc:size=48,rw=x"), "bad value"));
    CHECK(strstr(parse_err("alloc:size=48,"), "trailing comma"));
    CHECK(strstr(parse_err("alloc:size=48,,every=2"), "key=value"));
    CHECK(strstr(parse_err("alloc:size=48,name=x"), "unknown key"));
    CHECK(strstr(parse_err("alloc:size"), "key=value"));
    CHECK(strstr(parse_err("alloc:=5"), "key=value"));
    CHECK(strstr(parse_err("alloc:size=48,label=a b"), "bad value"));
    CHECK(strstr(parse_err("alloc:size=48,label=a\"b"), "bad value"));
    CHECK(strstr(parse_err("symbol:len=8"), "needs name="));
    CHECK(strstr(parse_err("symbol:name=x,len=0"), "bad value"));
    CHECK(strstr(parse_err("symbol:name=x,size=4"), "unknown key"));
    CHECK(strstr(parse_err("addr:base=0x1000"), "needs base= and len="));
    CHECK(strstr(parse_err("addr:base=0xfffffffffffffff0,len=32"), "wraps"));
    char longname[300];
    memset(longname, 'a', sizeof longname);
    memcpy(longname, "symbol:name=", 12);
    longname[299] = 0;
    CHECK(strstr(parse_err(longname), "bad value"));

    // Lists.
    tw_spec list[4];
    char err[128];
    CHECK(tw_spec_parse_list("alloc:size=48;symbol:name=g;;addr:base=16,len=16;", list, 4, err, sizeof err) == 3);
    CHECK(list[0].kind == TW_SPEC_ALLOC && list[1].kind == TW_SPEC_SYMBOL && list[2].kind == TW_SPEC_ADDR);
    CHECK(tw_spec_parse_list("", list, 4, err, sizeof err) == 0);
    CHECK(tw_spec_parse_list("alloc:size=1;alloc:size=2;alloc:size=3", list, 2, err, sizeof err) == -1);
    CHECK(tw_spec_parse_list("alloc:size=1;bogus", list, 4, err, sizeof err) == -1);

    // Property: format() output parses back to an identical spec.
    uint64_t st = t_seed(0x7370656373706563ull);
    static const char *names[] = {"f", "make_node", "_ZN3Foo3barEv", "-[Obj_method:]x", "a.b$c"};
    for (int i = 0; i < 20000; i++) {
        tw_spec a, b;
        memset(&a, 0, sizeof a);
        a.kind = 1 + (int)(t_rand(&st) % 3);
        a.mode = 1 + (unsigned)(t_rand(&st) % 3);
        a.depth = 4;
        a.every = 1;
        a.size_max = UINT64_MAX;
        if (t_rand(&st) & 1) strcpy(a.label, names[t_rand(&st) % 5]);
        if (a.kind == TW_SPEC_ALLOC) {
            a.size_min = t_rand(&st) >> (t_rand(&st) & 63);
            a.size_max = (t_rand(&st) & 1) ? a.size_min : (t_rand(&st) & 1) ? UINT64_MAX : a.size_min + (t_rand(&st) & 0xffff);
            if (a.size_max < a.size_min) a.size_max = UINT64_MAX;
            if (t_rand(&st) & 1) strcpy(a.caller, names[t_rand(&st) % 5]);
            a.depth = 1 + (unsigned)(t_rand(&st) % 64);
            a.every = 1 + t_rand(&st) % 1000;
            a.skip = t_rand(&st) % 1000;
            a.limit = t_rand(&st) % 1000;
        } else if (a.kind == TW_SPEC_SYMBOL) {
            strcpy(a.name, names[t_rand(&st) % 5]);
            if (t_rand(&st) & 1) strcpy(a.image, names[t_rand(&st) % 5]);
            a.off = t_rand(&st) % 4096;
            a.len = t_rand(&st) % 4096;
        } else {
            a.base = t_rand(&st) >> 17;
            a.len = 1 + t_rand(&st) % 100000;
        }
        char text[512];
        int n = tw_spec_format(&a, text, sizeof text);
        CHECK(n > 0);
        int rc = tw_spec_parse(text, (size_t)n, &b, err, sizeof err);
        if (rc != 0) fprintf(stderr, "  '%s': %s\n", text, err);
        CHECK(rc == 0);
        if (memcmp(&a, &b, sizeof a) != 0) fprintf(stderr, "  round trip differs for '%s'\n", text);
        CHECK(memcmp(&a, &b, sizeof a) == 0);
    }
    char tiny[8];
    CHECK(parse("alloc:size=48", &s) == 0 && tw_spec_format(&s, tiny, sizeof tiny) == -1);
    return t_done("spec");
}

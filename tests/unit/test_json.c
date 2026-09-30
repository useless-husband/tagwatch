#include "../../cli/json.h"
#include "../../src/fmt.h"
#include "t.h"

static jval pool[256];

static jval *parse(const char *text) {
    static char buf[4096];
    snprintf(buf, sizeof buf, "%s", text);
    return json_parse(buf, pool, 256);
}

int main(void) {
    jval *o = parse("{\"ev\":\"access\",\"seq\":12,\"neg\":-7,\"addr\":\"0x7bdc000028\",\"freed\":true,\"none\":null,"
                    "\"bt\":[{\"pc\":\"0x1\",\"sym\":\"a\\\"b\",\"off\":4},{\"pc\":\"0x2\"}],\"big\":18446744073709551615}");
    CHECK(o && o->type == J_OBJ);
    CHECK_STR(json_str(o, "ev", ""), "access");
    CHECK(json_int(o, "seq", 0) == 12);
    CHECK(json_int(o, "neg", 0) == -7);
    CHECK(json_int(o, "freed", 0) == 1);
    CHECK(json_int(o, "missing", 99) == 99);
    CHECK(json_hex(o, "addr") == 0x7bdc000028ull);
    CHECK((uint64_t)json_int(o, "big", 0) == UINT64_MAX);
    CHECK(json_get(o, "none") && json_get(o, "none")->type == J_NULL);
    CHECK_STR(json_str(o, "seq", "dflt"), "dflt"); // wrong type falls back
    const jval *bt = json_get(o, "bt");
    CHECK(bt && bt->type == J_ARR && bt->child && bt->child->next && !bt->child->next->next);
    CHECK_STR(json_str(bt->child, "sym", ""), "a\"b");
    CHECK(json_int(bt->child, "off", 0) == 4);

    o = parse("{\"s\":\"tab\\there \\u00e9 \\u4e2d \\ud83d\\ude00 \\/ \\\\\"}");
    CHECK(o != NULL);
    if (o) CHECK_STR(json_str(o, "s", ""), "tab\there \xc3\xa9 \xe4\xb8\xad \xf0\x9f\x98\x80 / \\");
    o = parse("  [ 1 , 2.5e3 , [ ] , { } ]  ");
    CHECK(o && o->type == J_ARR && o->child->num == 1 && o->child->next->num == 2);

    static const char *bad[] = {"", "{", "{\"a\":}", "{\"a\" 1}", "{\"a\":1,}", "[1,]", "{\"a\":\"x}", "{\"a\":1} x", "nul",
                                "{\"a\":\"\\q\"}", "{\"a\":\"\\u12\"}", "{a:1}", "-", "\"a\nb\"", "{\"a\":1 \"b\":2}"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        if (parse(bad[i])) fprintf(stderr, "  accepted malformed input: %s\n", bad[i]);
        CHECK(parse(bad[i]) == NULL);
    }

    // Deep nesting and pool exhaustion are refused, not overrun.
    char deep[200];
    memset(deep, '[', 100);
    memset(deep + 100, ']', 99);
    deep[199] = 0;
    CHECK(parse(deep) == NULL);
    char many[4096] = "[";
    for (int i = 0; i < 400; i++) strcat(many, "1,");
    strcat(many, "1]");
    CHECK(parse(many) == NULL);

    // Round trip with the runtime's own string escaper: whatever the trace
    // writer emits, the reader gets back byte for byte.
    uint64_t st = t_seed(0x6a736f6e6a736f6eull);
    for (int i = 0; i < 20000; i++) {
        char raw[40], line[400];
        int n = (int)(t_rand(&st) % 39);
        for (int k = 0; k < n; k++) {
            unsigned c = (unsigned)(t_rand(&st) % 128);
            raw[k] = (char)(c ? c : 'x'); // any ASCII except NUL, including control characters
        }
        raw[n] = 0;
        tw_buf b;
        tw_buf_init(&b, line, sizeof line);
        tw_put_str(&b, "{\"k\":");
        tw_put_json_str(&b, raw);
        tw_put_str(&b, ",\"n\":");
        uint64_t v = t_rand(&st) >> (t_rand(&st) & 63);
        tw_put_dec(&b, v);
        tw_put_str(&b, "}");
        jval *r = json_parse(line, pool, 256);
        CHECK(r != NULL);
        if (r) {
            CHECK_STR(json_str(r, "k", "?"), raw);
            CHECK((uint64_t)json_int(r, "n", 0) == v);
        }
    }

    // Robustness: random mutations of a valid line never crash the parser.
    const char *seedline = "{\"ev\":\"access\",\"seq\":3,\"bt\":[{\"pc\":\"0x10\",\"sym\":\"f\",\"off\":8}],\"t\":true}";
    for (int i = 0; i < 100000; i++) {
        char line[128];
        snprintf(line, sizeof line, "%s", seedline);
        size_t len = strlen(line);
        int muts = 1 + (int)(t_rand(&st) % 3);
        for (int k = 0; k < muts; k++) line[t_rand(&st) % len] = (char)(1 + t_rand(&st) % 127);
        (void)json_parse(line, pool, 256);
        t_checks++;
    }
    return t_done("json");
}

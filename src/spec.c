#include "spec.h"

#include <string.h>

#include "fmt.h"

static int fail(char *err, size_t errlen, const char *msg, const char *s, size_t n) {
    tw_buf b;
    tw_buf_init(&b, err, errlen);
    tw_put_str(&b, msg);
    if (s) {
        tw_put_str(&b, ": '");
        tw_put_mem(&b, s, n);
        tw_put_char(&b, '\'');
    }
    return -1;
}

static int key_is(const char *k, size_t kn, const char *name) { return strlen(name) == kn && memcmp(k, name, kn) == 0; }

// Names and labels travel through an environment variable and come back out
// in JSON, so restrict them to characters that need no quoting in either.
static int copy_name(char *dst, size_t cap, const char *v, size_t vn) {
    if (vn == 0 || vn >= cap) return -1;
    for (size_t i = 0; i < vn; i++) {
        unsigned char c = (unsigned char)v[i];
        if (c <= ' ' || c == ',' || c == ';' || c == '=' || c == '"' || c == '\\' || c == 0x7f) return -1;
    }
    memcpy(dst, v, vn);
    dst[vn] = 0;
    return 0;
}

static int parse_size_range(const char *v, size_t vn, uint64_t *lo, uint64_t *hi) {
    size_t dots = vn;
    for (size_t i = 0; i + 1 < vn; i++)
        if (v[i] == '.' && v[i + 1] == '.') {
            dots = i;
            break;
        }
    if (dots == vn) {
        if (tw_parse_u64(v, vn, lo) != 0) return -1;
        *hi = *lo;
        return 0;
    }
    if (dots == 0) *lo = 0;
    else if (tw_parse_u64(v, dots, lo) != 0) return -1;
    if (dots + 2 == vn) *hi = UINT64_MAX;
    else if (tw_parse_u64(v + dots + 2, vn - dots - 2, hi) != 0) return -1;
    return *lo <= *hi ? 0 : -1;
}

int tw_spec_parse(const char *text, size_t n, tw_spec *s, char *err, size_t errlen) {
    memset(s, 0, sizeof *s);
    s->mode = TW_MODE_RW;
    s->size_max = UINT64_MAX;
    s->depth = 4;
    s->every = 1;
    size_t colon = 0;
    while (colon < n && text[colon] != ':') colon++;
    if (colon == n) return fail(err, errlen, "expected kind:key=value,...", text, n);
    if (key_is(text, colon, "alloc")) s->kind = TW_SPEC_ALLOC;
    else if (key_is(text, colon, "symbol")) s->kind = TW_SPEC_SYMBOL;
    else if (key_is(text, colon, "addr")) s->kind = TW_SPEC_ADDR;
    else return fail(err, errlen, "unknown watch kind (alloc, symbol, addr)", text, colon);

    int have_base = 0, have_len = 0, have_filter = 0;
    size_t i = colon + 1;
    while (i < n) {
        size_t e = i;
        while (e < n && text[e] != ',') e++;
        size_t eq = i;
        while (eq < e && text[eq] != '=') eq++;
        if (eq == e || eq == i) return fail(err, errlen, "expected key=value", text + i, e - i);
        const char *k = text + i, *v = text + eq + 1;
        size_t kn = eq - i, vn = e - eq - 1;
        uint64_t u = 0;
        int bad = 0;
        if (key_is(k, kn, "label")) {
            bad = copy_name(s->label, sizeof s->label, v, vn);
        } else if (key_is(k, kn, "rw")) {
            if (key_is(v, vn, "r")) s->mode = TW_MODE_READ;
            else if (key_is(v, vn, "w")) s->mode = TW_MODE_WRITE;
            else if (key_is(v, vn, "rw")) s->mode = TW_MODE_RW;
            else bad = 1;
        } else if (s->kind == TW_SPEC_ALLOC && key_is(k, kn, "size")) {
            bad = parse_size_range(v, vn, &s->size_min, &s->size_max);
            have_filter = 1;
        } else if (s->kind == TW_SPEC_ALLOC && key_is(k, kn, "caller")) {
            bad = copy_name(s->caller, sizeof s->caller, v, vn);
            have_filter = 1;
        } else if (s->kind == TW_SPEC_ALLOC && key_is(k, kn, "depth")) {
            bad = tw_parse_u64(v, vn, &u) != 0 || u == 0 || u > 64;
            s->depth = (unsigned)u;
        } else if (s->kind == TW_SPEC_ALLOC && key_is(k, kn, "every")) {
            bad = tw_parse_u64(v, vn, &s->every) != 0 || s->every == 0;
        } else if (s->kind == TW_SPEC_ALLOC && key_is(k, kn, "skip")) {
            bad = tw_parse_u64(v, vn, &s->skip) != 0;
        } else if (s->kind == TW_SPEC_ALLOC && key_is(k, kn, "limit")) {
            bad = tw_parse_u64(v, vn, &s->limit) != 0;
        } else if (s->kind == TW_SPEC_SYMBOL && key_is(k, kn, "name")) {
            bad = copy_name(s->name, sizeof s->name, v, vn);
        } else if (s->kind == TW_SPEC_SYMBOL && key_is(k, kn, "image")) {
            bad = copy_name(s->image, sizeof s->image, v, vn);
        } else if (s->kind != TW_SPEC_ADDR && key_is(k, kn, "off")) {
            bad = tw_parse_u64(v, vn, &s->off) != 0;
        } else if (s->kind == TW_SPEC_ADDR && key_is(k, kn, "base")) {
            bad = tw_parse_u64(v, vn, &s->base) != 0;
            have_base = 1;
        } else if (key_is(k, kn, "len")) {
            bad = tw_parse_u64(v, vn, &s->len) != 0 || s->len == 0;
            have_len = 1;
        } else {
            return fail(err, errlen, "unknown key for this watch kind", k, kn);
        }
        if (bad) return fail(err, errlen, "bad value", k, e - i);
        i = e + 1;
        if (e < n && i == n) return fail(err, errlen, "trailing comma", text, n);
    }
    if (s->kind == TW_SPEC_ALLOC && !have_filter)
        return fail(err, errlen, "alloc watch needs size= or caller= (watching every allocation is never useful)", NULL, 0);
    if (s->kind == TW_SPEC_SYMBOL && !s->name[0]) return fail(err, errlen, "symbol watch needs name=", NULL, 0);
    if (s->kind == TW_SPEC_ADDR && (!have_base || !have_len)) return fail(err, errlen, "addr watch needs base= and len=", NULL, 0);
    if (s->kind == TW_SPEC_ADDR && s->base + s->len < s->base) return fail(err, errlen, "addr range wraps", NULL, 0);
    return 0;
}

int tw_spec_format(const tw_spec *s, char *buf, size_t cap) {
    tw_buf b;
    tw_buf_init(&b, buf, cap);
    const char *rw = s->mode == TW_MODE_READ ? "r" : s->mode == TW_MODE_WRITE ? "w" : "rw";
    switch (s->kind) {
    case TW_SPEC_ALLOC:
        tw_put_str(&b, "alloc:size=");
        tw_put_dec(&b, s->size_min);
        if (s->size_max != s->size_min) {
            tw_put_str(&b, "..");
            if (s->size_max != UINT64_MAX) tw_put_dec(&b, s->size_max);
        }
        if (s->caller[0]) tw_put_fmt(&b, ",caller=%s", s->caller);
        tw_put_fmt(&b, ",depth=%u,every=%llu,skip=%llu,limit=%llu,off=%llu", s->depth, (unsigned long long)s->every,
                   (unsigned long long)s->skip, (unsigned long long)s->limit, (unsigned long long)s->off);
        if (s->len) tw_put_fmt(&b, ",len=%llu", (unsigned long long)s->len);
        break;
    case TW_SPEC_SYMBOL:
        tw_put_fmt(&b, "symbol:name=%s", s->name);
        if (s->image[0]) tw_put_fmt(&b, ",image=%s", s->image);
        tw_put_fmt(&b, ",off=%llu", (unsigned long long)s->off);
        if (s->len) tw_put_fmt(&b, ",len=%llu", (unsigned long long)s->len);
        break;
    case TW_SPEC_ADDR:
        tw_put_str(&b, "addr:base=");
        tw_put_hex(&b, s->base);
        tw_put_fmt(&b, ",len=%llu", (unsigned long long)s->len);
        break;
    default:
        return -1;
    }
    tw_put_fmt(&b, ",rw=%s", rw);
    if (s->label[0]) tw_put_fmt(&b, ",label=%s", s->label);
    return b.truncated ? -1 : (int)b.len;
}

int tw_spec_parse_list(const char *text, tw_spec *out, int max, char *err, size_t errlen) {
    int count = 0;
    size_t n = strlen(text), i = 0;
    while (i < n) {
        size_t e = i;
        while (e < n && text[e] != ';') e++;
        if (e > i) {
            if (count == max) return fail(err, errlen, "too many watch specs", NULL, 0);
            if (tw_spec_parse(text + i, e - i, &out[count], err, errlen) != 0) return -1;
            count++;
        }
        i = e + 1;
    }
    return count;
}

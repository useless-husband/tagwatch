#include "json.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    char *p;
    jval *pool;
    int used, cap;
    int depth;
} parser;

static void skip_ws(parser *ps) {
    while (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r') ps->p++;
}

static jval *node(parser *ps, jtype t) {
    if (ps->used == ps->cap) return NULL;
    jval *v = &ps->pool[ps->used++];
    memset(v, 0, sizeof *v);
    v->type = t;
    return v;
}

static int hex4(const char *s, unsigned *out) {
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        char c = s[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
        else return 0;
    }
    *out = v;
    return 1;
}

// Parses a string starting at the opening quote; unescapes in place and
// returns the start of the decoded text, leaving ps->p after the closing quote.
static char *parse_string(parser *ps) {
    if (*ps->p != '"') return NULL;
    char *start = ++ps->p, *w = start;
    for (;;) {
        unsigned char c = (unsigned char)*ps->p;
        if (c == 0 || c < 0x20) return NULL;
        if (c == '"') break;
        if (c != '\\') {
            *w++ = *ps->p++;
            continue;
        }
        ps->p++;
        switch (*ps->p) {
        case '"': *w++ = '"'; break;
        case '\\': *w++ = '\\'; break;
        case '/': *w++ = '/'; break;
        case 'b': *w++ = '\b'; break;
        case 'f': *w++ = '\f'; break;
        case 'n': *w++ = '\n'; break;
        case 'r': *w++ = '\r'; break;
        case 't': *w++ = '\t'; break;
        case 'u': {
            unsigned cp;
            if (!hex4(ps->p + 1, &cp)) return NULL;
            ps->p += 4;
            if (cp >= 0xd800 && cp < 0xdc00 && ps->p[1] == '\\' && ps->p[2] == 'u') { // surrogate pair
                unsigned lo;
                if (!hex4(ps->p + 3, &lo) || lo < 0xdc00 || lo > 0xdfff) return NULL;
                cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                ps->p += 6;
            }
            if (cp == 0) cp = 0xfffd; // keep strings NUL-free
            if (cp < 0x80) *w++ = (char)cp;
            else if (cp < 0x800) {
                *w++ = (char)(0xc0 | (cp >> 6));
                *w++ = (char)(0x80 | (cp & 0x3f));
            } else if (cp < 0x10000) {
                *w++ = (char)(0xe0 | (cp >> 12));
                *w++ = (char)(0x80 | ((cp >> 6) & 0x3f));
                *w++ = (char)(0x80 | (cp & 0x3f));
            } else {
                *w++ = (char)(0xf0 | (cp >> 18));
                *w++ = (char)(0x80 | ((cp >> 12) & 0x3f));
                *w++ = (char)(0x80 | ((cp >> 6) & 0x3f));
                *w++ = (char)(0x80 | (cp & 0x3f));
            }
            break;
        }
        default: return NULL;
        }
        ps->p++;
    }
    ps->p++; // closing quote
    *w = 0;  // safe: w <= position of the closing quote
    return start;
}

static jval *parse_value(parser *ps);

static jval *parse_container(parser *ps, int is_obj) {
    jval *v = node(ps, is_obj ? J_OBJ : J_ARR);
    if (!v || ++ps->depth > 32) return NULL;
    char close = is_obj ? '}' : ']';
    jval **tail = &v->child;
    ps->p++;
    skip_ws(ps);
    if (*ps->p == close) {
        ps->p++;
        ps->depth--;
        return v;
    }
    for (;;) {
        const char *key = NULL;
        skip_ws(ps);
        if (is_obj) {
            key = parse_string(ps);
            if (!key) return NULL;
            skip_ws(ps);
            if (*ps->p++ != ':') return NULL;
        }
        jval *c = parse_value(ps);
        if (!c) return NULL;
        c->key = key;
        *tail = c;
        tail = &c->next;
        skip_ws(ps);
        if (*ps->p == ',') {
            ps->p++;
            continue;
        }
        if (*ps->p == close) {
            ps->p++;
            ps->depth--;
            return v;
        }
        return NULL;
    }
}

static jval *parse_value(parser *ps) {
    skip_ws(ps);
    char c = *ps->p;
    if (c == '{') return parse_container(ps, 1);
    if (c == '[') return parse_container(ps, 0);
    if (c == '"') {
        jval *v = node(ps, J_STR);
        if (!v) return NULL;
        v->str = parse_string(ps);
        return v->str ? v : NULL;
    }
    if (!strncmp(ps->p, "true", 4) || !strncmp(ps->p, "false", 5)) {
        jval *v = node(ps, J_BOOL);
        if (!v) return NULL;
        v->num = c == 't';
        ps->p += c == 't' ? 4 : 5;
        return v;
    }
    if (!strncmp(ps->p, "null", 4)) {
        ps->p += 4;
        return node(ps, J_NULL);
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        jval *v = node(ps, J_NUM);
        if (!v) return NULL;
        char *e;
        v->num = c == '-' ? strtoll(ps->p, &e, 10) : (int64_t)strtoull(ps->p, &e, 10);
        if (e == ps->p || (c == '-' && e == ps->p + 1)) return NULL;
        // Skip a fraction or exponent; the trace only contains integers.
        while (*e == '.' || *e == 'e' || *e == 'E' || *e == '+' || *e == '-' || (*e >= '0' && *e <= '9')) e++;
        ps->p = e;
        return v;
    }
    return NULL;
}

jval *json_parse(char *text, jval *pool, int pool_size) {
    parser ps = {text, pool, 0, pool_size, 0};
    jval *root = parse_value(&ps);
    if (!root) return NULL;
    skip_ws(&ps);
    return *ps.p ? NULL : root;
}

const jval *json_get(const jval *obj, const char *key) {
    if (!obj || obj->type != J_OBJ) return NULL;
    for (const jval *c = obj->child; c; c = c->next)
        if (c->key && !strcmp(c->key, key)) return c;
    return NULL;
}

const char *json_str(const jval *obj, const char *key, const char *dflt) {
    const jval *v = json_get(obj, key);
    return v && v->type == J_STR ? v->str : dflt;
}

int64_t json_int(const jval *obj, const char *key, int64_t dflt) {
    const jval *v = json_get(obj, key);
    return v && (v->type == J_NUM || v->type == J_BOOL) ? v->num : dflt;
}

uint64_t json_hex(const jval *obj, const char *key) {
    const jval *v = json_get(obj, key);
    if (!v) return 0;
    if (v->type == J_NUM) return (uint64_t)v->num;
    return v->type == J_STR ? strtoull(v->str, NULL, 16) : 0;
}

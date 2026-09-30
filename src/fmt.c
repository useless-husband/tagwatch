#include "fmt.h"

#include <stdarg.h>

void tw_buf_init(tw_buf *b, char *storage, size_t cap) {
    b->buf = storage;
    b->cap = cap;
    b->len = 0;
    b->truncated = 0;
    if (cap) storage[0] = 0;
}

void tw_put_char(tw_buf *b, char c) {
    if (b->cap == 0 || b->len + 1 >= b->cap) {
        b->truncated = 1;
        return;
    }
    b->buf[b->len++] = c;
    b->buf[b->len] = 0;
}

void tw_put_mem(tw_buf *b, const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) tw_put_char(b, s[i]);
}

void tw_put_str(tw_buf *b, const char *s) {
    if (!s) s = "(null)";
    while (*s) tw_put_char(b, *s++);
}

void tw_put_dec(tw_buf *b, uint64_t v) {
    char tmp[24];
    int n = 0;
    do {
        tmp[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (n) tw_put_char(b, tmp[--n]);
}

void tw_put_sdec(tw_buf *b, int64_t v) {
    if (v < 0) {
        tw_put_char(b, '-');
        tw_put_dec(b, (uint64_t)0 - (uint64_t)v);
    } else {
        tw_put_dec(b, (uint64_t)v);
    }
}

static void put_hex_digits(tw_buf *b, uint64_t v) {
    char tmp[16];
    int n = 0;
    do {
        tmp[n++] = "0123456789abcdef"[v & 15];
        v >>= 4;
    } while (v);
    while (n) tw_put_char(b, tmp[--n]);
}

void tw_put_hex(tw_buf *b, uint64_t v) {
    tw_put_char(b, '0');
    tw_put_char(b, 'x');
    put_hex_digits(b, v);
}

void tw_put_json_str(tw_buf *b, const char *s) {
    tw_put_char(b, '"');
    if (!s) s = "";
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"': tw_put_str(b, "\\\""); break;
        case '\\': tw_put_str(b, "\\\\"); break;
        case '\n': tw_put_str(b, "\\n"); break;
        case '\r': tw_put_str(b, "\\r"); break;
        case '\t': tw_put_str(b, "\\t"); break;
        default:
            if (c < 0x20) {
                tw_put_str(b, "\\u00");
                tw_put_char(b, "0123456789abcdef"[c >> 4]);
                tw_put_char(b, "0123456789abcdef"[c & 15]);
            } else {
                tw_put_char(b, (char)c); // UTF-8 bytes pass through unchanged
            }
        }
    }
    tw_put_char(b, '"');
}

void tw_put_fmt(tw_buf *b, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    for (; *fmt; fmt++) {
        if (*fmt != '%') {
            tw_put_char(b, *fmt);
            continue;
        }
        fmt++;
        int lng = 0;
        while (*fmt == 'l' || *fmt == 'z') {
            lng++;
            fmt++;
        }
        switch (*fmt) {
        case 's': tw_put_str(b, va_arg(ap, const char *)); break;
        case 'c': tw_put_char(b, (char)va_arg(ap, int)); break;
        case 'd':
            if (lng) tw_put_sdec(b, va_arg(ap, long long));
            else tw_put_sdec(b, va_arg(ap, int));
            break;
        case 'u':
            if (lng) tw_put_dec(b, va_arg(ap, unsigned long long));
            else tw_put_dec(b, va_arg(ap, unsigned));
            break;
        case 'x':
            if (lng) put_hex_digits(b, va_arg(ap, unsigned long long));
            else put_hex_digits(b, va_arg(ap, unsigned));
            break;
        case 'p': tw_put_hex(b, (uint64_t)(uintptr_t)va_arg(ap, void *)); break;
        case '%': tw_put_char(b, '%'); break;
        case 0: va_end(ap); return;
        default:
            tw_put_char(b, '%');
            tw_put_char(b, *fmt);
        }
    }
    va_end(ap);
}

int tw_parse_u64(const char *s, size_t n, uint64_t *out) {
    if (n == 0) return -1;
    uint64_t v = 0;
    size_t i = 0;
    unsigned base = 10;
    if (n > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16;
        i = 2;
    }
    size_t digits = 0;
    for (; i < n; i++, digits++) {
        char c = s[i];
        unsigned d;
        if (c >= '0' && c <= '9') d = (unsigned)(c - '0');
        else if (base == 16 && c >= 'a' && c <= 'f') d = (unsigned)(c - 'a' + 10);
        else if (base == 16 && c >= 'A' && c <= 'F') d = (unsigned)(c - 'A' + 10);
        else break;
        if (v > (UINT64_MAX - d) / base) return -1;
        v = v * base + d;
    }
    if (digits == 0) return -1;
    if (i < n) {
        unsigned shift;
        if (base == 10 && (s[i] == 'k' || s[i] == 'K')) shift = 10;
        else if (base == 10 && (s[i] == 'm' || s[i] == 'M')) shift = 20;
        else return -1;
        if (i + 1 != n) return -1;
        if (v > (UINT64_MAX >> shift)) return -1;
        v <<= shift;
    }
    *out = v;
    return 0;
}

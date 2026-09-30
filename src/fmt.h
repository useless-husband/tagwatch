// fmt: bounded, allocation-free text formatting.
//
// The fault handler runs while a program thread is frozen in the middle of an
// arbitrary instruction, possibly holding the malloc or stdio lock. Anything
// the handler prints therefore goes through this module, which touches only
// the caller's buffer.
#ifndef TW_FMT_H
#define TW_FMT_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    char *buf;
    size_t cap; // total capacity including the terminating NUL
    size_t len; // bytes written so far (never exceeds cap - 1)
    int truncated;
} tw_buf;

void tw_buf_init(tw_buf *b, char *storage, size_t cap);
void tw_put_char(tw_buf *b, char c);
void tw_put_str(tw_buf *b, const char *s);
void tw_put_mem(tw_buf *b, const char *s, size_t n);
void tw_put_dec(tw_buf *b, uint64_t v);
void tw_put_sdec(tw_buf *b, int64_t v);
void tw_put_hex(tw_buf *b, uint64_t v); // "0x1f"
void tw_put_json_str(tw_buf *b, const char *s); // quoted and escaped
// printf subset: %s %d %u %x %p %c %% with optional l/ll/z length modifiers.
void tw_put_fmt(tw_buf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void tw_put_vfmt(tw_buf *b, const char *fmt, va_list ap);

// Parsing helpers shared by the spec parser and the CLI.
// Accepts decimal, 0x-hex, and the suffixes k/K, m/M (powers of 1024).
// Returns 0 on success, -1 on malformed input or overflow.
int tw_parse_u64(const char *s, size_t n, uint64_t *out);

#endif

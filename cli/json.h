// json: a small JSON reader for trace lines.
//
// One line of the trace is one JSON object. The parser builds a tree out of
// a caller-supplied node pool and unescapes strings in place, so reading a
// trace allocates nothing per line.
#ifndef TW_JSON_H
#define TW_JSON_H

#include <stdint.h>

typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } jtype;

typedef struct jval {
    jtype type;
    const char *key;   // member name when inside an object
    const char *str;   // J_STR
    int64_t num;       // J_NUM (integers; fractions are truncated), J_BOOL
    struct jval *child; // first element / member
    struct jval *next;  // next sibling
} jval;

// Parses the NUL-terminated text (modified in place). Returns the root, or
// NULL on malformed input or when the pool is exhausted.
jval *json_parse(char *text, jval *pool, int pool_size);

const jval *json_get(const jval *obj, const char *key);
const char *json_str(const jval *obj, const char *key, const char *dflt);
int64_t json_int(const jval *obj, const char *key, int64_t dflt);
// Trace addresses are hex strings ("0x1234").
uint64_t json_hex(const jval *obj, const char *key);

#endif

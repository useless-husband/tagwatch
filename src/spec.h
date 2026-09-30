// spec: the textual watch specifications shared by the CLI and the runtime.
//
//   alloc:size=48,caller=make_node,depth=4,every=1,skip=0,limit=0,rw=rw,label=x
//   alloc:size=32..128            (inclusive range; "64.." is open-ended)
//   alloc:caller=new_node,off=16,len=8   (one field of every such object)
//   symbol:name=g_table,len=64,off=0,image=libfoo.dylib
//   addr:base=0x100008000,len=16
//
// Several specs are joined with ';' in the TAGWATCH_WATCH environment variable.
#ifndef TW_SPEC_H
#define TW_SPEC_H

#include <stddef.h>
#include <stdint.h>

enum { TW_SPEC_ALLOC = 1, TW_SPEC_SYMBOL, TW_SPEC_ADDR };
enum { TW_MODE_READ = 1, TW_MODE_WRITE = 2, TW_MODE_RW = 3 };

#define TW_SPEC_NAME_MAX 128
#define TW_SPEC_LABEL_MAX 64

typedef struct {
    int kind;
    unsigned mode; // which accesses are reported (TW_MODE_*)
    char label[TW_SPEC_LABEL_MAX];
    // alloc
    uint64_t size_min, size_max; // inclusive
    char caller[TW_SPEC_NAME_MAX]; // "" = any call site
    unsigned depth;                // frames searched for `caller`
    uint64_t every, skip, limit;   // sampling: watch 1 in `every`, after `skip`, at most `limit` (0 = no limit)
    // symbol
    char name[TW_SPEC_NAME_MAX];
    char image[TW_SPEC_NAME_MAX]; // "" = main executable
    // alloc and symbol: watch [off, off+len) of the object; len 0 = to its end
    uint64_t off;
    uint64_t base, len; // addr: the range itself
} tw_spec;

// Parses one spec. Returns 0, or -1 with a message in err.
int tw_spec_parse(const char *text, size_t n, tw_spec *out, char *err, size_t errlen);

// Canonical text for a spec; parse(format(s)) == s. Returns the length or -1
// if the buffer is too small.
int tw_spec_format(const tw_spec *s, char *buf, size_t cap);

// Splits a ';'-separated list, parsing up to max specs. Returns the count or
// -1 with a message in err.
int tw_spec_parse_list(const char *text, tw_spec *out, int max, char *err, size_t errlen);

// Does an allocation of `size` bytes satisfy the size constraint?
static inline int tw_spec_size_match(const tw_spec *s, uint64_t size) {
    return size >= s->size_min && size <= s->size_max;
}

#endif

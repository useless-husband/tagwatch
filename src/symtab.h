// symtab: an in-process symboliser that reads the Mach-O images already
// mapped into the process.
//
// dladdr() would do the same job, but it takes dyld's lock. The fault handler
// runs while a program thread is frozen at an arbitrary instruction; if that
// thread is inside dyld the handler would deadlock. This module only follows
// pointers into read-only image memory and takes one private lock.
#ifndef TW_SYMTAB_H
#define TW_SYMTAB_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *name;    // without the leading underscore; NULL if unknown
    uint64_t addr;       // start of the symbol
    const char *image;   // basename of the image; NULL if pc is in no image
    uint64_t image_base; // load address of the image's Mach-O header
} tw_sym;

// Frame layout of the function containing a pc, from its compact unwind info.
enum {
    TW_UNW_UNKNOWN = 0, // no image or no unwind section
    TW_UNW_NONE,        // encoding 0: hand-written assembly without a frame
    TW_UNW_FRAME,       // standard x29/x30 frame record
    TW_UNW_FRAMELESS,   // leaf: return address is still in x30
    TW_UNW_DWARF,
};

// Registers for dyld image notifications and indexes the loaded images.
void tw_symtab_init(void);

// Symbolises pc. Returns 1 if pc lies in a known image (name may still be
// NULL for stripped code), 0 otherwise.
int tw_sym_lookup(uint64_t pc, tw_sym *out);

int tw_unwind_mode(uint64_t pc);

// Looks a symbol up by name. image is a basename, or NULL/"" for the main
// executable. On success stores the address and the distance to the next
// symbol in the same section (an upper bound for the object's size).
int tw_sym_find(const char *image, const char *name, uint64_t *addr, uint64_t *size);

// 1 if [addr, addr+len) lies inside the __TEXT segment of a loaded image.
int tw_addr_is_code(uint64_t addr);

// Number of indexed images (for tests and the start-of-trace record).
int tw_image_count(void);

// Image index -> basename/base, for emitting the image list in the trace.
int tw_image_info(int idx, const char **path, uint64_t *base, uint64_t *text_size);

#endif

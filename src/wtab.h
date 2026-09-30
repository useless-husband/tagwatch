// wtab: the watch table. Maps a 16-byte MTE granule to the watch that owns it.
//
// Layout: an open-addressing hash from 16 KB page number to a 1024-entry cell
// array, one cell per granule. A cell holds the owning watch slot, an "armed"
// bit, and the allocation tag the granule had before it was armed, so
// disarming can put the original tag back. Lookup is O(1); arming costs one
// cell per granule.
//
// The table does no locking and performs no MTE operations; both belong to
// the caller (watch.c). That keeps this file testable on any machine.
//
// A fork child walks the table without the lock, at whatever instant the
// fork happened (tw_wtab_foreach_armed). Every mutation is therefore ordered
// so that a snapshot taken between any two stores is still safe to walk:
// growth builds the new bucket block completely and publishes it with one
// pointer store, a granule is marked armed before its tag changes and the
// mark outlives the tag, and a page's live count drops to 0 before its cell
// array is released.
#ifndef TW_WTAB_H
#define TW_WTAB_H

#include <stddef.h>
#include <stdint.h>

#define TW_GRANULE 16u
#define TW_GRANULE_MASK 15ull
#define TW_PAGE_SHIFT 14
#define TW_PAGE_SIZE (1ull << TW_PAGE_SHIFT)
#define TW_CELLS_PER_PAGE (TW_PAGE_SIZE / TW_GRANULE)
#define TW_SLOT_MAX ((1u << 27) - 1)

// Memory provider. alloc returns zero-filled memory or NULL.
typedef struct {
    void *(*alloc)(size_t size);
    void (*release)(void *p, size_t size);
} tw_mem;

// The buckets: three parallel arrays in one allocation, so that a resize can
// swap them in with a single pointer store.
typedef struct {
    size_t cap;       // buckets, power of two
    uint64_t *keys;   // page number + 1; 0 marks an empty bucket
    uint32_t **cells; // parallel to keys
    uint32_t *live;   // parallel to keys: armed granules on that page
} tw_wtab_buckets;

typedef struct {
    tw_wtab_buckets *b;
    size_t used;       // occupied buckets
    uint64_t granules; // armed granules in total
    tw_mem mem;
} tw_wtab;

int tw_wtab_init(tw_wtab *t, const tw_mem *mem);
void tw_wtab_destroy(tw_wtab *t);

// Claims every granule of [base, base+len) for `slot` (1..TW_SLOT_MAX).
// base and len must be granule-aligned and len non-zero. Fails with -EEXIST,
// changing nothing, if any granule already belongs to a watch; -ENOMEM if the
// table cannot grow; -EINVAL for misaligned or wrapping ranges.
int tw_wtab_insert(tw_wtab *t, uint64_t base, uint64_t len, uint32_t slot);

// Releases the granules of [base, base+len) that belong to `slot`.
// Returns the number of granules released.
uint64_t tw_wtab_remove(tw_wtab *t, uint64_t base, uint64_t len, uint32_t slot);

// Slot owning the granule that contains addr, or 0. If orig_tag is non-NULL
// it receives the saved original allocation tag.
uint32_t tw_wtab_get(const tw_wtab *t, uint64_t addr, unsigned *orig_tag);

// Records the original tag of the granule containing addr (which must belong
// to a watch) and marks the granule as armed: from now on its real tag is
// the watch tag, and `tag` is what has to be put back.
void tw_wtab_set_orig_tag(tw_wtab *t, uint64_t addr, unsigned tag);

// Calls fn(addr, orig_tag, ctx) for every granule marked armed. Used to put
// all tags back without going through the watch records (fork child).
void tw_wtab_foreach_armed(const tw_wtab *t, void (*fn)(uint64_t addr, unsigned orig_tag, void *ctx), void *ctx);

// First armed granule intersecting [addr, addr+len): returns its slot and
// stores the granule address in *hit, or returns 0.
uint32_t tw_wtab_find(const tw_wtab *t, uint64_t addr, uint64_t len, uint64_t *hit);

// Bucket capacity (for tests).
size_t tw_wtab_capacity(const tw_wtab *t);

// The tag an armed granule gets: differs from the original tag (so every
// legitimate pointer faults) and is never 0 (so untagged pointers fault too).
static inline unsigned tw_watch_tag(unsigned orig_tag) {
    unsigned w = (orig_tag ^ 0x8u) & 0xfu;
    return w ? w : 0xcu;
}

#endif

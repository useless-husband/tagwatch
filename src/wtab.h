// wtab: the watch table. Maps a 16-byte MTE granule to the watch that owns it.
//
// Layout: an open-addressing hash from 16 KB page number to a 1024-entry cell
// array, one cell per granule. A cell holds the owning watch slot and the
// allocation tag the granule had before it was armed, so disarming can put
// the original tag back. Lookup is O(1); arming costs one cell per granule.
//
// The table does no locking and performs no MTE operations; both belong to
// the caller (watch.c). That keeps this file testable on any machine.
#ifndef TW_WTAB_H
#define TW_WTAB_H

#include <stddef.h>
#include <stdint.h>

#define TW_GRANULE 16u
#define TW_GRANULE_MASK 15ull
#define TW_PAGE_SHIFT 14
#define TW_PAGE_SIZE (1ull << TW_PAGE_SHIFT)
#define TW_CELLS_PER_PAGE (TW_PAGE_SIZE / TW_GRANULE)
#define TW_SLOT_MAX ((1u << 28) - 1)

// Memory provider. alloc returns zero-filled memory or NULL.
typedef struct {
    void *(*alloc)(size_t size);
    void (*release)(void *p, size_t size);
} tw_mem;

typedef struct {
    uint64_t *keys;   // page number + 1; 0 marks an empty bucket
    uint32_t **cells; // parallel to keys
    uint32_t *live;   // parallel to keys: armed granules on that page
    size_t cap;       // buckets, power of two
    size_t used;      // occupied buckets
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

// Records the original tag of the granule containing addr (must be armed).
void tw_wtab_set_orig_tag(tw_wtab *t, uint64_t addr, unsigned tag);

// First armed granule intersecting [addr, addr+len): returns its slot and
// stores the granule address in *hit, or returns 0.
uint32_t tw_wtab_find(const tw_wtab *t, uint64_t addr, uint64_t len, uint64_t *hit);

// The tag an armed granule gets: differs from the original tag (so every
// legitimate pointer faults) and is never 0 (so untagged pointers fault too).
static inline unsigned tw_watch_tag(unsigned orig_tag) {
    unsigned w = (orig_tag ^ 0x8u) & 0xfu;
    return w ? w : 0xcu;
}

#endif

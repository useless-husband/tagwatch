#include "wtab.h"

#include <errno.h>
#include <string.h>

#define CELL_BYTES (TW_CELLS_PER_PAGE * sizeof(uint32_t))
#define INITIAL_CAP 64

static size_t bucket_of(const tw_wtab *t, uint64_t pn) {
    return (size_t)((pn * 0x9e3779b97f4a7c15ull) >> 32) & (t->cap - 1);
}

// Index of the bucket holding pn, or (size_t)-1.
static size_t find_page(const tw_wtab *t, uint64_t pn) {
    if (!t->cap) return (size_t)-1;
    size_t i = bucket_of(t, pn);
    for (;;) {
        if (t->keys[i] == 0) return (size_t)-1;
        if (t->keys[i] == pn + 1) return i;
        i = (i + 1) & (t->cap - 1);
    }
}

static int alloc_arrays(tw_wtab *t, size_t cap, uint64_t **keys, uint32_t ***cells, uint32_t **live) {
    *keys = t->mem.alloc(cap * sizeof **keys);
    *cells = t->mem.alloc(cap * sizeof **cells);
    *live = t->mem.alloc(cap * sizeof **live);
    if (*keys && *cells && *live) return 0;
    if (*keys) t->mem.release(*keys, cap * sizeof **keys);
    if (*cells) t->mem.release(*cells, cap * sizeof **cells);
    if (*live) t->mem.release(*live, cap * sizeof **live);
    return -ENOMEM;
}

static int grow(tw_wtab *t) {
    size_t ncap = t->cap ? t->cap * 2 : INITIAL_CAP;
    uint64_t *okeys = t->keys, *nkeys;
    uint32_t **ocells = t->cells, **ncells;
    uint32_t *olive = t->live, *nlive;
    size_t ocap = t->cap;
    if (alloc_arrays(t, ncap, &nkeys, &ncells, &nlive) != 0) return -ENOMEM;
    t->keys = nkeys;
    t->cells = ncells;
    t->live = nlive;
    t->cap = ncap;
    for (size_t i = 0; i < ocap; i++) {
        if (!okeys[i]) continue;
        size_t j = bucket_of(t, okeys[i] - 1);
        while (t->keys[j]) j = (j + 1) & (ncap - 1);
        t->keys[j] = okeys[i];
        t->cells[j] = ocells[i];
        t->live[j] = olive[i];
    }
    if (ocap) {
        t->mem.release(okeys, ocap * sizeof *okeys);
        t->mem.release(ocells, ocap * sizeof *ocells);
        t->mem.release(olive, ocap * sizeof *olive);
    }
    return 0;
}

// Bucket for pn, creating the page if needed; (size_t)-1 on allocation failure.
static size_t ensure_page(tw_wtab *t, uint64_t pn) {
    size_t i = find_page(t, pn);
    if (i != (size_t)-1) return i;
    if ((t->used + 1) * 10 > t->cap * 7 && grow(t) != 0) return (size_t)-1;
    uint32_t *c = t->mem.alloc(CELL_BYTES);
    if (!c) return (size_t)-1;
    i = bucket_of(t, pn);
    while (t->keys[i]) i = (i + 1) & (t->cap - 1);
    t->keys[i] = pn + 1;
    t->cells[i] = c;
    t->live[i] = 0;
    t->used++;
    return i;
}

// Backward-shift deletion keeps probe sequences intact without tombstones.
static void drop_page(tw_wtab *t, size_t i) {
    t->mem.release(t->cells[i], CELL_BYTES);
    size_t mask = t->cap - 1;
    size_t j = i;
    for (;;) {
        j = (j + 1) & mask;
        if (!t->keys[j]) break;
        size_t home = bucket_of(t, t->keys[j] - 1);
        // Move j into the hole at i unless its home lies cyclically in (i, j].
        int stays = i <= j ? (home > i && home <= j) : (home > i || home <= j);
        if (stays) continue;
        t->keys[i] = t->keys[j];
        t->cells[i] = t->cells[j];
        t->live[i] = t->live[j];
        i = j;
    }
    t->keys[i] = 0;
    t->cells[i] = NULL;
    t->live[i] = 0;
    t->used--;
}

int tw_wtab_init(tw_wtab *t, const tw_mem *mem) {
    memset(t, 0, sizeof *t);
    t->mem = *mem;
    return grow(t);
}

void tw_wtab_destroy(tw_wtab *t) {
    for (size_t i = 0; i < t->cap; i++)
        if (t->keys[i]) t->mem.release(t->cells[i], CELL_BYTES);
    if (t->cap) {
        t->mem.release(t->keys, t->cap * sizeof *t->keys);
        t->mem.release(t->cells, t->cap * sizeof *t->cells);
        t->mem.release(t->live, t->cap * sizeof *t->live);
    }
    memset(t, 0, sizeof *t);
}

static int range_ok(uint64_t base, uint64_t len) {
    if (len == 0 || (base & TW_GRANULE_MASK) || (len & TW_GRANULE_MASK)) return 0;
    return base + len > base; // no wrap
}

uint32_t tw_wtab_get(const tw_wtab *t, uint64_t addr, unsigned *orig_tag) {
    size_t i = find_page(t, addr >> TW_PAGE_SHIFT);
    if (i == (size_t)-1) return 0;
    uint32_t c = t->cells[i][(addr & (TW_PAGE_SIZE - 1)) / TW_GRANULE];
    if (orig_tag) *orig_tag = c & 0xf;
    return c >> 4;
}

void tw_wtab_set_orig_tag(tw_wtab *t, uint64_t addr, unsigned tag) {
    size_t i = find_page(t, addr >> TW_PAGE_SHIFT);
    if (i == (size_t)-1) return;
    uint32_t *c = &t->cells[i][(addr & (TW_PAGE_SIZE - 1)) / TW_GRANULE];
    if (*c >> 4) *c = (*c & ~0xfu) | (tag & 0xf);
}

uint32_t tw_wtab_find(const tw_wtab *t, uint64_t addr, uint64_t len, uint64_t *hit) {
    if (len == 0) return 0;
    uint64_t a = addr & ~TW_GRANULE_MASK;
    uint64_t last = addr + len - 1;
    if (last < addr) last = UINT64_MAX;
    while (a <= last) {
        uint64_t page_end = (a | (TW_PAGE_SIZE - 1));
        size_t i = find_page(t, a >> TW_PAGE_SHIFT);
        if (i != (size_t)-1 && t->live[i]) {
            uint64_t stop = last < page_end ? last : page_end;
            for (uint64_t g = a; g <= stop; g += TW_GRANULE) {
                uint32_t c = t->cells[i][(g & (TW_PAGE_SIZE - 1)) / TW_GRANULE];
                if (c >> 4) {
                    if (hit) *hit = g;
                    return c >> 4;
                }
                if (g + TW_GRANULE < g) return 0;
            }
        }
        if (page_end == UINT64_MAX) break;
        a = page_end + 1;
    }
    return 0;
}

int tw_wtab_insert(tw_wtab *t, uint64_t base, uint64_t len, uint32_t slot) {
    if (!range_ok(base, len) || slot == 0 || slot > TW_SLOT_MAX) return -EINVAL;
    if (tw_wtab_find(t, base, len, NULL)) return -EEXIST;
    // Create every page first so the fill below cannot fail half-way.
    for (uint64_t pn = base >> TW_PAGE_SHIFT; pn <= (base + len - 1) >> TW_PAGE_SHIFT; pn++)
        if (ensure_page(t, pn) == (size_t)-1) return -ENOMEM;
    for (uint64_t a = base; a != base + len; a += TW_GRANULE) {
        size_t i = find_page(t, a >> TW_PAGE_SHIFT);
        t->cells[i][(a & (TW_PAGE_SIZE - 1)) / TW_GRANULE] = slot << 4;
        t->live[i]++;
    }
    t->granules += len / TW_GRANULE;
    return 0;
}

uint64_t tw_wtab_remove(tw_wtab *t, uint64_t base, uint64_t len, uint32_t slot) {
    if (!range_ok(base, len)) return 0;
    uint64_t released = 0;
    for (uint64_t a = base; a != base + len; a += TW_GRANULE) {
        size_t i = find_page(t, a >> TW_PAGE_SHIFT);
        if (i == (size_t)-1) continue;
        uint32_t *c = &t->cells[i][(a & (TW_PAGE_SIZE - 1)) / TW_GRANULE];
        if ((*c >> 4) != slot) continue;
        *c = 0;
        released++;
        if (--t->live[i] == 0) drop_page(t, i);
    }
    t->granules -= released;
    return released;
}

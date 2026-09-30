#include "wtab.h"

#include <errno.h>
#include <string.h>

#define CELL_BYTES (TW_CELLS_PER_PAGE * sizeof(uint32_t))
// Cell layout: slot (27 bits) | armed (1 bit) | original tag (4 bits).
#define CELL_SLOT(c) ((c) >> 5)
#define CELL_ARMED 0x10u
#define INITIAL_CAP 64

static size_t bucket_of(const tw_wtab_buckets *b, uint64_t pn) {
    return (size_t)((pn * 0x9e3779b97f4a7c15ull) >> 32) & (b->cap - 1);
}

// Index of the bucket holding pn, or (size_t)-1.
static size_t find_page(const tw_wtab *t, uint64_t pn) {
    const tw_wtab_buckets *b = t->b;
    if (!b) return (size_t)-1;
    size_t i = bucket_of(b, pn);
    for (;;) {
        if (b->keys[i] == 0) return (size_t)-1;
        if (b->keys[i] == pn + 1) return i;
        i = (i + 1) & (b->cap - 1);
    }
}

static size_t buckets_bytes(size_t cap) {
    return sizeof(tw_wtab_buckets) + cap * (sizeof(uint64_t) + sizeof(uint32_t *) + sizeof(uint32_t));
}

static tw_wtab_buckets *buckets_new(tw_wtab *t, size_t cap) {
    tw_wtab_buckets *b = t->mem.alloc(buckets_bytes(cap));
    if (!b) return NULL;
    b->cap = cap;
    b->keys = (uint64_t *)(b + 1);
    b->cells = (uint32_t **)(b->keys + cap);
    b->live = (uint32_t *)(b->cells + cap);
    return b;
}

// Builds a bigger bucket block and publishes it with one store, so a reader
// that sees the new pointer sees a complete table and one that saw the old
// pointer still has the old block intact until this function returns.
static int grow(tw_wtab *t) {
    tw_wtab_buckets *ob = t->b;
    size_t ncap = ob ? ob->cap * 2 : INITIAL_CAP;
    tw_wtab_buckets *nb = buckets_new(t, ncap);
    if (!nb) return -ENOMEM;
    if (ob) {
        for (size_t i = 0; i < ob->cap; i++) {
            if (!ob->keys[i]) continue;
            size_t j = bucket_of(nb, ob->keys[i] - 1);
            while (nb->keys[j]) j = (j + 1) & (ncap - 1);
            nb->keys[j] = ob->keys[i];
            nb->cells[j] = ob->cells[i];
            nb->live[j] = ob->live[i];
        }
    }
    __atomic_store_n(&t->b, nb, __ATOMIC_RELEASE);
    if (ob) t->mem.release(ob, buckets_bytes(ob->cap));
    return 0;
}

// Bucket for pn, creating the page if needed; (size_t)-1 on allocation failure.
static size_t ensure_page(tw_wtab *t, uint64_t pn) {
    size_t i = find_page(t, pn);
    if (i != (size_t)-1) return i;
    if ((t->used + 1) * 10 > t->b->cap * 7 && grow(t) != 0) return (size_t)-1;
    uint32_t *c = t->mem.alloc(CELL_BYTES);
    if (!c) return (size_t)-1;
    tw_wtab_buckets *b = t->b;
    i = bucket_of(b, pn);
    while (b->keys[i]) i = (i + 1) & (b->cap - 1);
    b->cells[i] = c;
    b->live[i] = 0;
    b->keys[i] = pn + 1; // last: the bucket becomes visible complete
    t->used++;
    return i;
}

// Backward-shift deletion keeps probe sequences intact without tombstones.
// The moves copy the live count last, so a bucket whose key was moved but
// whose cells pointer was not yet is still marked empty of armed granules.
static void drop_page(tw_wtab *t, size_t i) {
    tw_wtab_buckets *b = t->b;
    t->mem.release(b->cells[i], CELL_BYTES);
    size_t mask = b->cap - 1;
    size_t j = i;
    for (;;) {
        j = (j + 1) & mask;
        if (!b->keys[j]) break;
        size_t home = bucket_of(b, b->keys[j] - 1);
        // Move j into the hole at i unless its home lies cyclically in (i, j].
        int stays = i <= j ? (home > i && home <= j) : (home > i || home <= j);
        if (stays) continue;
        b->live[i] = 0;
        b->keys[i] = b->keys[j];
        b->cells[i] = b->cells[j];
        b->live[i] = b->live[j];
        i = j;
    }
    b->live[i] = 0;
    b->keys[i] = 0;
    b->cells[i] = NULL;
    t->used--;
}

int tw_wtab_init(tw_wtab *t, const tw_mem *mem) {
    memset(t, 0, sizeof *t);
    t->mem = *mem;
    return grow(t);
}

void tw_wtab_destroy(tw_wtab *t) {
    tw_wtab_buckets *b = t->b;
    if (b) {
        for (size_t i = 0; i < b->cap; i++)
            if (b->keys[i]) t->mem.release(b->cells[i], CELL_BYTES);
        t->mem.release(b, buckets_bytes(b->cap));
    }
    memset(t, 0, sizeof *t);
}

size_t tw_wtab_capacity(const tw_wtab *t) { return t->b ? t->b->cap : 0; }

static int range_ok(uint64_t base, uint64_t len) {
    if (len == 0 || (base & TW_GRANULE_MASK) || (len & TW_GRANULE_MASK)) return 0;
    return base + len > base; // no wrap
}

uint32_t tw_wtab_get(const tw_wtab *t, uint64_t addr, unsigned *orig_tag) {
    size_t i = find_page(t, addr >> TW_PAGE_SHIFT);
    if (i == (size_t)-1) return 0;
    uint32_t c = t->b->cells[i][(addr & (TW_PAGE_SIZE - 1)) / TW_GRANULE];
    if (orig_tag) *orig_tag = c & 0xf;
    return CELL_SLOT(c);
}

void tw_wtab_set_orig_tag(tw_wtab *t, uint64_t addr, unsigned tag) {
    size_t i = find_page(t, addr >> TW_PAGE_SHIFT);
    if (i == (size_t)-1) return;
    uint32_t *c = &t->b->cells[i][(addr & (TW_PAGE_SIZE - 1)) / TW_GRANULE];
    if (CELL_SLOT(*c)) *c = (*c & ~0x1fu) | CELL_ARMED | (tag & 0xf);
}

void tw_wtab_foreach_armed(const tw_wtab *t, void (*fn)(uint64_t addr, unsigned orig_tag, void *ctx), void *ctx) {
    const tw_wtab_buckets *b = t->b;
    if (!b) return;
    for (size_t i = 0; i < b->cap; i++) {
        if (!b->keys[i] || !b->live[i] || !b->cells[i]) continue;
        uint64_t page = (b->keys[i] - 1) << TW_PAGE_SHIFT;
        for (uint64_t g = 0; g < TW_CELLS_PER_PAGE; g++) {
            uint32_t c = b->cells[i][g];
            if (CELL_SLOT(c) && (c & CELL_ARMED)) fn(page + g * TW_GRANULE, c & 0xf, ctx);
        }
    }
}

uint32_t tw_wtab_find(const tw_wtab *t, uint64_t addr, uint64_t len, uint64_t *hit) {
    if (len == 0) return 0;
    uint64_t a = addr & ~TW_GRANULE_MASK;
    uint64_t last = addr + len - 1;
    if (last < addr) last = UINT64_MAX;
    while (a <= last) {
        uint64_t page_end = (a | (TW_PAGE_SIZE - 1));
        size_t i = find_page(t, a >> TW_PAGE_SHIFT);
        if (i != (size_t)-1 && t->b->live[i]) {
            uint64_t stop = last < page_end ? last : page_end;
            for (uint64_t g = a; g <= stop; g += TW_GRANULE) {
                uint32_t c = t->b->cells[i][(g & (TW_PAGE_SIZE - 1)) / TW_GRANULE];
                if (CELL_SLOT(c)) {
                    if (hit) *hit = g;
                    return CELL_SLOT(c);
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
        t->b->cells[i][(a & (TW_PAGE_SIZE - 1)) / TW_GRANULE] = slot << 5;
        t->b->live[i]++;
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
        uint32_t *c = &t->b->cells[i][(a & (TW_PAGE_SIZE - 1)) / TW_GRANULE];
        if (CELL_SLOT(*c) != slot) continue;
        *c = 0;
        released++;
        if (--t->b->live[i] == 0) drop_page(t, i);
    }
    t->granules -= released;
    return released;
}

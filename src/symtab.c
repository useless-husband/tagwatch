#include "symtab.h"

#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <os/lock.h>
#include <string.h>

#define MAX_IMAGES 4096
#define CACHE_SIZE 4096 // power of two

typedef struct {
    const struct mach_header_64 *mh;
    uint64_t slide;
    uint64_t text_lo, text_hi; // runtime address range of __TEXT
    const char *path;
    const char *base;
    const struct nlist_64 *syms;
    uint32_t nsyms;
    const char *strs;
    uint32_t strsize;
    const uint8_t *unwind; // __TEXT,__unwind_info
    uint64_t unwind_size;
    int is_main;
} image_t;

typedef struct {
    uint64_t pc; // 0 = empty
    const char *name;
    uint64_t addr;
    int image;
} cache_t;

static image_t images[MAX_IMAGES];
static int n_images;
static cache_t cache[CACHE_SIZE];
static os_unfair_lock lock = OS_UNFAIR_LOCK_INIT;
static int initialised;
static char main_path[1024] = "(main executable)";

static const char *basename_of(const char *path) {
    const char *b = path;
    for (const char *p = path; *p; p++)
        if (*p == '/' && p[1]) b = p + 1;
    return b;
}

static void index_image(const struct mach_header_64 *mh, intptr_t slide, image_t *im) {
    memset(im, 0, sizeof *im);
    im->mh = mh;
    (void)slide; // derived below: the Mach-O header is the first byte of __TEXT
    im->is_main = mh->filetype == MH_EXECUTE;
    im->path = im->is_main ? main_path : "(unnamed image)";
    const struct load_command *lc = (const struct load_command *)(mh + 1);
    const struct symtab_command *st = NULL;
    uint64_t linkedit_vmaddr = 0, linkedit_fileoff = 0;
    int have_linkedit = 0;
    for (uint32_t i = 0; i < mh->ncmds; i++, lc = (const struct load_command *)((const char *)lc + lc->cmdsize)) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            if (!strcmp(sg->segname, SEG_TEXT)) {
                im->slide = (uint64_t)(uintptr_t)mh - sg->vmaddr;
                im->text_lo = sg->vmaddr + im->slide;
                im->text_hi = im->text_lo + sg->vmsize;
                const struct section_64 *sec = (const struct section_64 *)(sg + 1);
                for (uint32_t s = 0; s < sg->nsects; s++)
                    if (!strncmp(sec[s].sectname, "__unwind_info", 16)) {
                        im->unwind = (const uint8_t *)(sec[s].addr + im->slide);
                        im->unwind_size = sec[s].size;
                    }
            } else if (!strcmp(sg->segname, SEG_LINKEDIT)) {
                linkedit_vmaddr = sg->vmaddr;
                linkedit_fileoff = sg->fileoff;
                have_linkedit = 1;
            }
        } else if (lc->cmd == LC_SYMTAB) {
            st = (const struct symtab_command *)lc;
        } else if (lc->cmd == LC_ID_DYLIB) {
            const struct dylib_command *dc = (const struct dylib_command *)lc;
            im->path = (const char *)dc + dc->dylib.name.offset;
        }
    }
    if (st && have_linkedit) {
        // File offsets in LC_SYMTAB are relative to the file; __LINKEDIT tells
        // where that part of the file is mapped. This holds for images in the
        // dyld shared cache too.
        uint64_t bias = linkedit_vmaddr + im->slide - linkedit_fileoff;
        im->syms = (const struct nlist_64 *)(bias + st->symoff);
        im->nsyms = st->nsyms;
        im->strs = (const char *)(bias + st->stroff);
        im->strsize = st->strsize;
    }
}

static void on_add(const struct mach_header *mh32, intptr_t slide) {
    if (mh32->magic != MH_MAGIC_64) return;
    image_t im;
    index_image((const struct mach_header_64 *)mh32, slide, &im);
    im.base = basename_of(im.path);
    os_unfair_lock_lock(&lock);
    if (n_images < MAX_IMAGES) images[n_images++] = im;
    os_unfair_lock_unlock(&lock);
}

static void on_remove(const struct mach_header *mh32, intptr_t slide) {
    (void)slide;
    os_unfair_lock_lock(&lock);
    for (int i = 0; i < n_images; i++)
        if ((const void *)images[i].mh == (const void *)mh32) {
            images[i] = images[--n_images];
            break;
        }
    memset(cache, 0, sizeof cache); // entries may point into the unmapped image
    os_unfair_lock_unlock(&lock);
}

void tw_symtab_init(void) {
    os_unfair_lock_lock(&lock);
    int was = initialised;
    initialised = 1;
    os_unfair_lock_unlock(&lock);
    if (was) return;
    uint32_t n = sizeof main_path;
    if (_NSGetExecutablePath(main_path, &n) != 0) strcpy(main_path, "(main executable)");
    // dyld itself (which holds `start`, the outermost frame of the main
    // thread) is not announced through the image callbacks.
    struct task_dyld_info di;
    mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&di, &cnt) == KERN_SUCCESS && di.all_image_info_addr) {
        const struct dyld_all_image_infos *all = (const struct dyld_all_image_infos *)(uintptr_t)di.all_image_info_addr;
        const struct mach_header *dyld = all->dyldImageLoadAddress;
        if (dyld && dyld->magic == MH_MAGIC_64) {
            image_t im;
            index_image((const struct mach_header_64 *)(const void *)dyld, 0, &im);
            im.path = "/usr/lib/dyld";
            im.base = "dyld";
            os_unfair_lock_lock(&lock);
            if (n_images < MAX_IMAGES) images[n_images++] = im;
            os_unfair_lock_unlock(&lock);
        }
    }
    // dyld calls on_add for every image already loaded, then for new ones.
    _dyld_register_func_for_add_image(on_add);
    _dyld_register_func_for_remove_image(on_remove);
}

// Caller holds the lock.
static int image_of(uint64_t pc) {
    for (int i = 0; i < n_images; i++)
        if (pc >= images[i].text_lo && pc < images[i].text_hi) return i;
    return -1;
}

static int usable_sym(const struct nlist_64 *n) {
    return !(n->n_type & N_STAB) && (n->n_type & N_TYPE) == N_SECT;
}

// Nearest symbol at or below pc. Linear in the image's symbol count; results
// are cached per pc, and fault sites repeat.
static const char *nearest(const image_t *im, uint64_t pc, uint64_t *addr) {
    uint64_t target = pc - im->slide, best = 0;
    const char *name = NULL;
    for (uint32_t i = 0; i < im->nsyms; i++) {
        const struct nlist_64 *n = &im->syms[i];
        if (!usable_sym(n) || n->n_value > target || n->n_value < best) continue;
        if (n->n_un.n_strx >= im->strsize) continue;
        const char *s = im->strs + n->n_un.n_strx;
        if (!s[0]) continue;
        // Prefer real names over assembler-local labels at the same address.
        if (n->n_value == best && name && !(name[0] == 'l' || name[0] == 'L')) continue;
        best = n->n_value;
        name = s;
    }
    if (!name) return NULL;
    *addr = best + im->slide;
    return name[0] == '_' ? name + 1 : name;
}

int tw_sym_lookup(uint64_t pc, tw_sym *out) {
    memset(out, 0, sizeof *out);
    os_unfair_lock_lock(&lock);
    cache_t *c = &cache[(pc >> 2) & (CACHE_SIZE - 1)];
    if (c->pc != pc) {
        int i = image_of(pc);
        if (i < 0) {
            os_unfair_lock_unlock(&lock);
            return 0;
        }
        c->pc = pc;
        c->image = i;
        c->addr = 0;
        c->name = nearest(&images[i], pc, &c->addr);
    }
    out->name = c->name;
    out->addr = c->addr;
    out->image = images[c->image].base;
    out->image_base = (uint64_t)(uintptr_t)images[c->image].mh;
    os_unfair_lock_unlock(&lock);
    return 1;
}

int tw_addr_is_code(uint64_t addr) {
    os_unfair_lock_lock(&lock);
    int i = image_of(addr);
    os_unfair_lock_unlock(&lock);
    return i >= 0;
}

int tw_image_count(void) {
    os_unfair_lock_lock(&lock);
    int n = n_images;
    os_unfair_lock_unlock(&lock);
    return n;
}

int tw_image_info(int idx, const char **path, uint64_t *base, uint64_t *text_size) {
    int ok = 0;
    os_unfair_lock_lock(&lock);
    if (idx >= 0 && idx < n_images) {
        *path = images[idx].path;
        *base = images[idx].text_lo;
        *text_size = images[idx].text_hi - images[idx].text_lo;
        ok = 1;
    }
    os_unfair_lock_unlock(&lock);
    return ok;
}

// End of section number `sect` (1-based, counted across all segments).
static uint64_t section_end(const struct mach_header_64 *mh, unsigned sect) {
    const struct load_command *lc = (const struct load_command *)(mh + 1);
    unsigned ordinal = 1;
    for (uint32_t i = 0; i < mh->ncmds; i++, lc = (const struct load_command *)((const char *)lc + lc->cmdsize)) {
        if (lc->cmd != LC_SEGMENT_64) continue;
        const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
        const struct section_64 *sec = (const struct section_64 *)(sg + 1);
        for (uint32_t s = 0; s < sg->nsects; s++, ordinal++)
            if (ordinal == sect) return sec[s].addr + sec[s].size;
    }
    return 0;
}

int tw_sym_find(const char *image, const char *name, uint64_t *addr, uint64_t *size) {
    int found = 0;
    os_unfair_lock_lock(&lock);
    for (int i = 0; i < n_images && !found; i++) {
        const image_t *im = &images[i];
        if (image && image[0] ? strcmp(im->base, image) != 0 : !im->is_main) continue;
        for (uint32_t k = 0; k < im->nsyms; k++) {
            const struct nlist_64 *n = &im->syms[k];
            if (!usable_sym(n) || n->n_un.n_strx >= im->strsize) continue;
            const char *s = im->strs + n->n_un.n_strx;
            if (s[0] != '_' || strcmp(s + 1, name) != 0) continue;
            uint64_t end = section_end(im->mh, n->n_sect);
            for (uint32_t j = 0; j < im->nsyms; j++) {
                const struct nlist_64 *m = &im->syms[j];
                if (usable_sym(m) && m->n_sect == n->n_sect && m->n_value > n->n_value && (end == 0 || m->n_value < end))
                    end = m->n_value;
            }
            *addr = n->n_value + im->slide;
            *size = end > n->n_value ? end - n->n_value : 0;
            found = 1;
            break;
        }
    }
    os_unfair_lock_unlock(&lock);
    return found;
}

// --- compact unwind -------------------------------------------------------

static uint32_t rd32(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}
static uint16_t rd16(const uint8_t *p) {
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}

// Compact unwind encoding of the function containing `off` (offset from the
// image base). Returns 0 and sets *found = 0 when there is no entry.
static uint32_t unwind_encoding(const uint8_t *u, uint64_t usize, uint32_t off, int *found) {
    *found = 0;
    if (usize < 28 || rd32(u) != 1) return 0;
    uint32_t common_off = rd32(u + 4), common_cnt = rd32(u + 8);
    uint32_t index_off = rd32(u + 20), index_cnt = rd32(u + 24);
    if (index_cnt < 2 || (uint64_t)index_off + (uint64_t)index_cnt * 12 > usize) return 0;
    if ((uint64_t)common_off + (uint64_t)common_cnt * 4 > usize) return 0;
    // First level: last entry whose functionOffset <= off. The final entry is
    // a sentinel marking the end of the covered range.
    uint32_t lo = 0, hi = index_cnt - 1;
    if (off < rd32(u + index_off) || off >= rd32(u + index_off + (uint64_t)(index_cnt - 1) * 12)) return 0;
    while (hi - lo > 1) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (rd32(u + index_off + (uint64_t)mid * 12) <= off) lo = mid;
        else hi = mid;
    }
    uint32_t first_fn = rd32(u + index_off + (uint64_t)lo * 12);
    uint32_t page_off = rd32(u + index_off + (uint64_t)lo * 12 + 4);
    if (page_off == 0 || (uint64_t)page_off + 12 > usize) return 0;
    const uint8_t *pg = u + page_off;
    uint32_t kind = rd32(pg);
    uint32_t ent_off = rd16(pg + 4), ent_cnt = rd16(pg + 6);
    if (ent_cnt == 0) return 0;
    if (kind == 2) { // regular page: {functionOffset, encoding} pairs
        if ((uint64_t)page_off + ent_off + (uint64_t)ent_cnt * 8 > usize) return 0;
        const uint8_t *e = pg + ent_off;
        uint32_t a = 0, b = ent_cnt;
        if (rd32(e) > off) return 0;
        while (b - a > 1) {
            uint32_t mid = a + (b - a) / 2;
            if (rd32(e + (uint64_t)mid * 8) <= off) a = mid;
            else b = mid;
        }
        *found = 1;
        return rd32(e + (uint64_t)a * 8 + 4);
    }
    if (kind == 3) { // compressed page: 24-bit offset delta, 8-bit encoding index
        uint32_t enc_off = rd16(pg + 8), enc_cnt = rd16(pg + 10);
        if ((uint64_t)page_off + ent_off + (uint64_t)ent_cnt * 4 > usize) return 0;
        if ((uint64_t)page_off + enc_off + (uint64_t)enc_cnt * 4 > usize) return 0;
        const uint8_t *e = pg + ent_off;
        if (off < first_fn) return 0;
        uint32_t rel = off - first_fn;
        uint32_t a = 0, b = ent_cnt;
        if ((rd32(e) & 0xffffff) > rel) return 0;
        while (b - a > 1) {
            uint32_t mid = a + (b - a) / 2;
            if ((rd32(e + (uint64_t)mid * 4) & 0xffffff) <= rel) a = mid;
            else b = mid;
        }
        uint32_t idx = rd32(e + (uint64_t)a * 4) >> 24;
        *found = 1;
        if (idx < common_cnt) return rd32(u + common_off + (uint64_t)idx * 4);
        idx -= common_cnt;
        if (idx >= enc_cnt) {
            *found = 0;
            return 0;
        }
        return rd32(pg + enc_off + (uint64_t)idx * 4);
    }
    return 0;
}

int tw_unwind_mode(uint64_t pc) {
    os_unfair_lock_lock(&lock);
    int i = image_of(pc);
    if (i < 0 || !images[i].unwind) {
        os_unfair_lock_unlock(&lock);
        return TW_UNW_UNKNOWN;
    }
    const image_t *im = &images[i];
    int found = 0;
    uint32_t enc = unwind_encoding(im->unwind, im->unwind_size, (uint32_t)(pc - (uint64_t)(uintptr_t)im->mh), &found);
    os_unfair_lock_unlock(&lock);
    if (!found) return TW_UNW_UNKNOWN;
    switch (enc & 0x0f000000u) { // UNWIND_ARM64_MODE_MASK
    case 0x02000000u: return TW_UNW_FRAMELESS;
    case 0x03000000u: return TW_UNW_DWARF;
    case 0x04000000u: return TW_UNW_FRAME;
    case 0: return TW_UNW_NONE;
    default: return TW_UNW_UNKNOWN;
    }
}

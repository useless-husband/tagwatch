// The symboliser is checked against dladdr(), the system's own answer, for
// code in this test binary and in the dyld shared cache.
#include "../../src/symtab.h"
#include "t.h"

#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>

int tw_test_global_a[10] = {1};
int tw_test_global_b = 2;
static volatile int sink;

__attribute__((noinline)) int tw_test_with_frame(int x);
__attribute__((noinline)) int tw_test_with_frame(int x) {
    char buf[64];
    snprintf(buf, sizeof buf, "%d", x); // a call forces a frame record
    return buf[0];
}

__attribute__((noinline)) int tw_test_leaf(int x);
__attribute__((noinline)) int tw_test_leaf(int x) { return x * 3 + sink; }

static void against_dladdr(const char *what, void *fn) {
    Dl_info di;
    tw_sym s;
    uint64_t pc = (uint64_t)(uintptr_t)fn;
    pc &= 0x00007fffffffffffull;
    CHECK(dladdr((void *)(uintptr_t)pc, &di) != 0);
    int ok = tw_sym_lookup(pc + 4, &s);
    CHECK(ok);
    if (!ok || !s.name || !di.dli_sname) {
        fprintf(stderr, "  %s: tagwatch=%s dladdr=%s\n", what, ok && s.name ? s.name : "(none)", di.dli_sname ? di.dli_sname : "(none)");
        CHECK(0);
        return;
    }
    CHECK_STR(s.name, di.dli_sname);
    CHECK(s.addr == (uint64_t)(uintptr_t)di.dli_saddr);
    const char *b = strrchr(di.dli_fname, '/');
    CHECK_STR(s.image, b ? b + 1 : di.dli_fname);
    CHECK(s.image_base == (uint64_t)(uintptr_t)di.dli_fbase);
}

int main(void) {
    tw_symtab_init();
    tw_symtab_init(); // idempotent
    CHECK(tw_image_count() > 5);

    against_dladdr("tw_test_with_frame", (void *)tw_test_with_frame);
    against_dladdr("tw_test_leaf", (void *)tw_test_leaf);
    against_dladdr("main", (void *)main);
    against_dladdr("memcpy", dlsym(RTLD_DEFAULT, "memcpy"));
    against_dladdr("strlen", dlsym(RTLD_DEFAULT, "strlen"));
    against_dladdr("printf", dlsym(RTLD_DEFAULT, "printf"));
    against_dladdr("malloc", dlsym(RTLD_DEFAULT, "malloc"));
    against_dladdr("qsort", dlsym(RTLD_DEFAULT, "qsort"));
    against_dladdr("pthread_create", dlsym(RTLD_DEFAULT, "pthread_create"));
    against_dladdr("read", dlsym(RTLD_DEFAULT, "read"));

    tw_sym s;
    CHECK(tw_sym_lookup(0x10, &s) == 0 && s.name == NULL && s.image == NULL);
    CHECK(tw_sym_lookup((uint64_t)(uintptr_t)&tw_test_global_b, &s) == 0); // data is not in __TEXT
    CHECK(tw_addr_is_code((uint64_t)(uintptr_t)main & 0x00007fffffffffffull));
    CHECK(!tw_addr_is_code((uint64_t)(uintptr_t)&s));

    // Data symbols by name, with the size bound taken from the next symbol.
    uint64_t addr = 0, size = 0;
    CHECK(tw_sym_find(NULL, "tw_test_global_a", &addr, &size));
    CHECK(addr == (uint64_t)(uintptr_t)tw_test_global_a);
    CHECK(size >= sizeof tw_test_global_a && size <= 4096);
    CHECK(tw_sym_find("", "tw_test_global_b", &addr, &size) && addr == (uint64_t)(uintptr_t)&tw_test_global_b);
    CHECK(size >= sizeof tw_test_global_b);
    CHECK(!tw_sym_find(NULL, "tw_no_such_symbol", &addr, &size));
    CHECK(!tw_sym_find("libnothere.dylib", "tw_test_global_a", &addr, &size));
    CHECK(tw_sym_find("libsystem_c.dylib", "printf", &addr, &size));
    CHECK(addr == ((uint64_t)(uintptr_t)dlsym(RTLD_DEFAULT, "printf") & 0x00007fffffffffffull));

    // Compact unwind: a function that calls others keeps a frame record; a
    // leaf does not, so its caller is only found through x30.
    CHECK_EQ(tw_unwind_mode((uint64_t)(uintptr_t)tw_test_with_frame + 8), TW_UNW_FRAME);
    int leaf = tw_unwind_mode((uint64_t)(uintptr_t)tw_test_leaf);
    CHECK(leaf == TW_UNW_FRAMELESS || leaf == TW_UNW_NONE);
    CHECK_EQ(tw_unwind_mode(0x10), TW_UNW_UNKNOWN);
    int mm = tw_unwind_mode((uint64_t)(uintptr_t)dlsym(RTLD_DEFAULT, "memmove") & 0x00007fffffffffffull);
    printf("     (memmove unwind mode %d, leaf %d)\n", mm, leaf);
    CHECK(mm != TW_UNW_FRAME); // hand-written leaf routine: no frame record

    // Every image reports a sane text range.
    for (int i = 0; i < tw_image_count(); i++) {
        const char *path;
        uint64_t base, size2;
        CHECK(tw_image_info(i, &path, &base, &size2));
        CHECK(path && path[0] && base && size2);
    }
    const char *p;
    uint64_t b2, z;
    CHECK(!tw_image_info(-1, &p, &b2, &z) && !tw_image_info(1 << 20, &p, &b2, &z));
    return t_done("symtab");
}

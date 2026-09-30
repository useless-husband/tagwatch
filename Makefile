# tagwatch build. Everything lands in build/.
#
#   make            library, CLI
#   make test       unit tests, then the MTE tests (skipped without MTE)
#   make unit       unit tests only (what CI runs)
#   make lint       warnings-as-errors build plus the clang static analyzer
#   make asan       unit tests under AddressSanitizer and UBSan
#   make bench      measurements used in the README (needs MTE)
CC      ?= clang
ARCH    := -arch arm64
WARN    := -Wall -Wextra -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wconversion -Wno-sign-conversion -Werror
OPT     ?= -O2 -g
CFLAGS  := $(OPT) -std=c11 $(ARCH) $(WARN) -Iinclude -fvisibility=hidden $(EXTRA_CFLAGS)
B       ?= build
ENT     := entitlements/mte.entitlements

# Logic that needs no MTE: unit-tested on any arm64 Mac.
PURE    := fmt insn wtab spec symtab
RUNTIME := $(PURE) vm watch bt trace tramp exc arena interpose adopt supervise runtime mte
CLI     := main report json
UNIT    := fmt insn wtab spec symtab json report

.SECONDARY:
.PHONY: all unit mte-test test lint asan bench clean
all: $(B)/libtagwatch.dylib $(B)/tagwatch

$(B)/obj $(B)/cli $(B)/unit $(B)/mte $(B)/examples $(B)/bench:
	mkdir -p $@

$(B)/obj/%.o: src/%.c $(wildcard src/*.h) include/tagwatch.h | $(B)/obj
	$(CC) $(CFLAGS) -c -o $@ $<

# MTE instructions live in one file; the rest builds for any arm64 CPU.
$(B)/obj/mte.o: src/mte.c $(wildcard src/*.h) include/tagwatch.h | $(B)/obj
	$(CC) $(CFLAGS) -march=armv8.5-a+memtag -c -o $@ $<

$(B)/cli/%.o: cli/%.c $(wildcard cli/*.h src/*.h) include/tagwatch.h | $(B)/cli
	$(CC) $(CFLAGS) -c -o $@ $<

$(B)/libtagwatch.dylib: $(RUNTIME:%=$(B)/obj/%.o)
	$(CC) $(ARCH) -dynamiclib -install_name @rpath/libtagwatch.dylib -o $@ $^

$(B)/tagwatch: $(CLI:%=$(B)/cli/%.o) $(B)/obj/fmt.o $(B)/obj/spec.o $(B)/obj/supervise.o
	$(CC) $(ARCH) -o $@ $^ -lc++abi

# ---- unit tests ---------------------------------------------------------------
# The decoder's test vectors are assembled by the real assembler.
$(B)/unit/insn_vectors.s: tests/unit/insn_vectors.def | $(B)/unit
	( echo '.section __TEXT,__const'; echo '.globl _tw_vec_code'; echo '.p2align 2'; echo '_tw_vec_code:'; \
	  sed -n 's/^V("\([^"]*\)".*/    \1/p' $< ) > $@

$(B)/unit/insn_vectors.o: $(B)/unit/insn_vectors.s
	$(CC) $(ARCH) -march=armv8.5-a+memtag -c -o $@ $<

UNIT_OBJS := $(PURE:%=$(B)/obj/%.o) $(B)/cli/json.o $(B)/cli/report.o
$(B)/unit/test_insn: $(B)/unit/insn_vectors.o
$(B)/unit/test_%: tests/unit/test_%.c tests/unit/t.h $(UNIT_OBJS) | $(B)/unit
	$(CC) $(CFLAGS) -Wno-conversion -o $@ $< $(filter %.o,$^) -lc++abi

unit: $(UNIT:%=$(B)/unit/test_%)
	@for t in $(UNIT); do $(B)/unit/test_$$t || exit 1; done

# ---- MTE tests (run on an M5 or later; skip elsewhere) -------------------------
MTE_TESTS := $(patsubst tests/mte/%.c,%,$(wildcard tests/mte/t_*.c))

# Library-mode tests link the dylib and carry the hardened-process
# entitlements, which is what enables MTE for a binary started directly.
$(B)/mte/t_%: tests/mte/t_%.c tests/mte/mt.h $(B)/libtagwatch.dylib $(ENT) | $(B)/mte
	$(CC) $(OPT) -std=c11 $(ARCH) -Wall -Wextra -Werror -Iinclude -o $@ $< -L$(B) -ltagwatch -Wl,-rpath,@executable_path/..
	codesign -s - --entitlements $(ENT) -f $@ 2>/dev/null

# Plain, unsigned-for-MTE targets for `tagwatch run`.
$(B)/mte/target_%: tests/mte/target_%.c | $(B)/mte
	$(CC) $(OPT) -std=c11 $(ARCH) -Wall -Wextra -o $@ $<

$(B)/mte/target_cxx: tests/mte/target_cxx.cpp | $(B)/mte
	$(CXX) $(OPT) -std=c++17 $(ARCH) -Wall -Wextra -o $@ $<

MTE_TARGETS := $(patsubst tests/mte/%.c,$(B)/mte/%,$(wildcard tests/mte/target_*.c)) \
               $(patsubst tests/mte/%.cpp,$(B)/mte/%,$(wildcard tests/mte/target_*.cpp))

mte-test: all $(MTE_TESTS:%=$(B)/mte/%) $(MTE_TARGETS)
	@sh tests/run_mte.sh $(B) $(MTE_TESTS)

test: unit mte-test

# ---- quality gates ---------------------------------------------------------------
lint:
	$(MAKE) B=$(B)/lint OPT="-O1 -g" all unit
	$(CC) --analyze -Xanalyzer -analyzer-output=text $(ARCH) -std=c11 -Iinclude \
	    src/fmt.c src/insn.c src/wtab.c src/spec.c src/symtab.c src/watch.c src/bt.c src/trace.c src/tramp.c src/exc.c \
	    src/arena.c src/adopt.c src/supervise.c src/runtime.c src/vm.c cli/json.c cli/report.c cli/main.c

asan:
	$(MAKE) B=$(B)/asan OPT="-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined" unit

clean:
	rm -rf $(B)

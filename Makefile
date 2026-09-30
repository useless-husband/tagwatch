# tagwatch build. Everything lands in build/.
CC      ?= clang
ARCH    := -arch arm64
WARN    := -Wall -Wextra -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wconversion -Wno-sign-conversion -Werror
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 $(ARCH) $(WARN) -Iinclude -fvisibility=hidden
B       := build

# Logic that does not need MTE. Unit-tested on any arm64 Mac (and in CI).
PURE    := fmt insn wtab spec symtab
UNIT    := $(PURE)

RUNTIME := $(PURE) vm watch bt trace tramp exc arena interpose adopt supervise runtime mte

.SECONDARY:
.PHONY: all unit test clean
all: $(B)/libtagwatch.dylib

# MTE instructions live in one file; the rest builds for any arm64 CPU.
$(B)/obj/mte.o: src/mte.c $(wildcard src/*.h) include/tagwatch.h | $(B)/obj
	$(CC) $(CFLAGS) -march=armv8.5-a+memtag -c -o $@ $<

$(B)/libtagwatch.dylib: $(RUNTIME:%=$(B)/obj/%.o)
	$(CC) $(ARCH) -dynamiclib -install_name @rpath/libtagwatch.dylib -o $@ $^

$(B)/obj/%.o: src/%.c $(wildcard src/*.h) include/tagwatch.h | $(B)/obj
	$(CC) $(CFLAGS) -c -o $@ $<

$(B)/obj $(B)/unit:
	mkdir -p $@

# The decoder's test vectors are assembled by the real assembler.
$(B)/unit/insn_vectors.s: tests/unit/insn_vectors.def | $(B)/unit
	( echo '.section __TEXT,__const'; echo '.globl _tw_vec_code'; echo '.p2align 2'; echo '_tw_vec_code:'; \
	  sed -n 's/^V("\([^"]*\)".*/    \1/p' $< ) > $@

$(B)/unit/insn_vectors.o: $(B)/unit/insn_vectors.s
	$(CC) $(ARCH) -march=armv8.5-a+memtag -c -o $@ $<

$(B)/unit/test_insn: $(B)/unit/insn_vectors.o
$(B)/unit/test_%: tests/unit/test_%.c tests/unit/t.h $(PURE:%=$(B)/obj/%.o) | $(B)/unit
	$(CC) $(CFLAGS) -Wno-conversion -o $@ $< $(filter %.o,$^)

unit: $(UNIT:%=$(B)/unit/test_%)
	@for t in $(UNIT); do $(B)/unit/test_$$t || exit 1; done

test: unit

clean:
	rm -rf $(B)

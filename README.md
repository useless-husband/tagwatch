# tagwatch

**Unlimited data watchpoints for Apple Silicon Macs with MTE, at 16-byte granularity.**

A hardware watchpoint answers "who touches this memory?", but the CPU has four of them. Protecting a page with
`mprotect` has no such limit, but it traps on everything in the 16 KB page. tagwatch uses the ARM Memory Tagging
Extension (M5 and later) instead: it gives the watched memory a tag that no pointer in the program carries, so exactly
the accesses to that memory fault. Each access is logged (address, width, read or write, thread, backtrace), allowed
to proceed, and the memory stays watched. You can watch one field, or every object of a type at once.

[繁體中文說明](README.zh-TW.md) · [Design notes](docs/DESIGN.md) · [Benchmark method and raw output](docs/BENCHMARKS.md) ·
[導讀（給初學者）](docs/導讀.zh-TW.md)

```
$ tagwatch run -w -a caller=customer_new,off=16,len=8,label=credit_limit -- ./ledger
```

reads as: run `./ledger`, and for every heap object allocated by `customer_new`, report each **w**rite to bytes 16–23.

## A worked example

[`examples/ledger.c`](examples/ledger.c) keeps 500 customer records. Each has a 16-byte nickname followed by a credit
limit. One function copies nicknames without checking the length, so a long nickname overwrites the credit limit *of
the same heap object*. Nothing crashes; an audit at the end finds five wrong limits:

```
$ build/examples/ledger
ledger: 500 customers, 6713 charges declined
ledger: AUDIT FAILED: 5 customers have a credit limit other than 5000 (first: #96, limit 13881)
```

This is the kind of bug the usual tools miss. AddressSanitizer and MTE's own checking police the *boundaries* of an
allocation, and this write never crosses one. A debugger watchpoint needs an address, and it is not known in advance
which five of the 500 objects will be hit. With tagwatch, watch that field in all of them and ask who writes it
(`-q`: summary only, `-w`: writes only):

```
$ build/tagwatch run -q -w -a caller=customer_new,off=16,len=8,label=credit_limit -- build/examples/ledger
ledger: 500 customers, 6713 charges declined
ledger: AUDIT FAILED: 5 customers have a credit limit other than 5000 (first: #96, limit 13881)

== tagwatch summary ==
program    /path/to/tagwatch/build/examples/ledger (pid 25002)
accesses   519 reported: 0 read, 519 write, 0 read-modify-write
watches    500 armed, 500 still armed at exit
threads    1
traps      34307 taken (33788 not reported: filtered or granule neighbours; 0 via the slow return path; 0 LL/SC emulated); 6 execution slots

Watched objects
  500 objects, 8 bytes each "credit_limit", allocated by customer_new+0x18 (ledger)
        0 reads, 519 writes
        busiest: #194 (5) #291 (5) #388 (5) #485 (5) #97 (4) #1 (1)

Access sites, busiest first
       500  write 16 bytes  500 watches ("credit_limit", ...)  offset +0
              customer_new+0x24 (ledger)
              import_customers+0x7c (ledger)
              main+0x20 (ledger)
              start+0x1a20 (dyld)
        19  write 1 byte  5 watches ("credit_limit", ...)  offsets +0..+3
              _platform_memmove+0x1c0 (libsystem_platform.dylib)
              set_nick+0x2c (ledger)
              import_customers+0xa4 (ledger)
              main+0x20 (ledger)
              start+0x1a20 (dyld)
```

Two places write the field. One is the constructor, once per object. The other is a byte-wise `memmove` called from
`set_nick`, hitting 5 objects: the bug, with its call chain. The "traps … not reported" line is the price of 16-byte
granularity: the neighbouring `balance` field shares a granule with `credit_limit`, so accesses to it trap too and
are filtered out by address.

## Requirements and limits, up front

| | |
| --- | --- |
| Hardware | A Mac whose CPU has MTE: **M5 or later**. `sysctl hw.optional.arm.FEAT_MTE` must print 1. |
| OS | Developed and tested on **macOS 27.0 (26A428)** only. Not tested on macOS 26. |
| Privileges | None. No root, no SIP changes, no developer-mode setting. |
| Private interface | `tagwatch run` enables MTE in the child with `posix_spawnattr_set_use_sec_transition_shims_np`, a private SPI in libsystem (the same call LLDB's `process launch --memory-tagging` makes). Apple can change or remove it. |
| Debugger-style recovery | On macOS a tag-check fault kills the process unless it is being traced. The target therefore calls `ptrace(PT_TRACE_ME)` and tagwatch acts as its tracing parent. A process has one tracer, so LLDB cannot attach to it as well, and it stops briefly on every signal (see Limitations). |
| Granularity | MTE tags cover 16-byte granules. tagwatch reports byte-precisely (it filters by address), but every access to a granule that contains a watched byte pays for a trap. |
| Cost | About **5 µs per trapped access** on the M5 (7–8 µs with full logging), against 0.1 ns untrapped. Watching hot memory is slow; see Measurements. |
| Cannot be traced | Binaries with the hardened runtime and system binaries protected by SIP (they ignore `DYLD_INSERT_LIBRARIES`; tagwatch says so and the program runs unwatched), arm64e binaries (the runtime is built for arm64; untested), and processes that are already running (there is no attach). |

`tagwatch check` tests all of this on your machine, including an end-to-end watch:

```
$ build/tagwatch check
CPU has MTE (hw.optional.arm.FEAT_MTE)      yes
spawn SPI to enable MTE in a child          yes
libtagwatch.dylib                           ./build/libtagwatch.dylib
end-to-end self test (watch, trap, resume)  passed
tagwatch can be used on this machine.
```

## Build

```sh
make            # build/tagwatch, build/libtagwatch.dylib, build/examples/ledger
make test       # unit tests everywhere; MTE tests on MTE hardware, skipped with a reason elsewhere
```

Needs only the Xcode Command Line Tools (Apple clang 17 was used). No dependencies.

## Using the command line

```
tagwatch run [options] -- program [args...]

  -a, --watch-alloc SPEC        heap objects by size and/or allocating function
  -s, --watch-symbol NAME[:LEN] a global variable
  -x, --watch-addr ADDR:LEN     an address range (with --no-aslr)
  -w, --writes-only             report writes only
  -t, --trace FILE              keep the JSON-lines trace
  -l, --log FILE / -q           live log to a file / no live log
      --heatmap                 per-offset heat maps in the summary
      --depth N, --max-events N, --quarantine BYTES, --top N, --frames N, --no-summary, -v
```

`tagwatch --help` lists everything. Allocation specs combine keys with commas:

| Spec | Watches |
| --- | --- |
| `-a size=48` | every heap block of exactly 48 bytes |
| `-a size=1k..64k` | blocks in a size range (also sizes the system allocator does not tag) |
| `-a caller=make_node` | blocks allocated while `make_node` is among the 4 innermost callers (`depth=N` to change) |
| `-a caller=make_node,off=16,len=8` | bytes 16–23 of each such block |
| `-a size=64,every=100,limit=50` | one in 100 such blocks, at most 50 |
| `-s g_table:64`, `-s name=cache,image=libfoo.dylib` | a global, by symbol |

The live log (stderr by default) shows each access as it happens:

```
$ build/tagwatch run --depth 4 -s g_counter -- build/mte/target_list
tagwatch: watch #1 armed: 8 bytes at 0x100a70020 "g_counter"
tagwatch: #1 READ  8 bytes at 0x100a70020  watch #1 "g_counter" +0  thread 10410595
    bump+0x8 (target_list)
    main+0x88 (target_list)
    start+0x1a20 (dyld)
tagwatch: #2 WRITE 8 bytes at 0x100a70020  watch #1 "g_counter" +0  thread 10410595
    bump+0x10 (target_list)
    main+0x88 (target_list)
    start+0x1a20 (dyld)
```

The trace (`-t file.jsonl`) has one JSON object per line: `start`, `watch`, `access`, `free`, `unwatch`, `violation`,
`note`, `stats`.

```json
{"ev":"access","seq":1,"t_ns":234625,"kind":"read","size":8,"addr":"0x102d9c020","watch":1,"off":0,"tid":10410600,"bt":[{"pc":"0x102d948b0","sym":"bump","off":8,"img":"target_list","imgoff":2224},{"pc":"0x102d945d0","sym":"main","off":136,"img":"target_list","imgoff":1488}]}
```

`tagwatch report [--heatmap] file.jsonl` prints the summary again from a saved trace. A heat map shows which parts of
an object are touched, summed over all objects of the same kind:

```
Heat map of 4 objects "make_node" (40 bytes each, 8 bytes per row)
    offset       reads    writes
    +0               7         8  ########################################
    +8               5         7  ################################
    +16              0        12  ################################
    ...          (2 untouched rows)
```

The exit status of `tagwatch run` is the program's own (128 + signal number if it was killed).

## Using the library

Link `libtagwatch.dylib` and sign your program with the two MTE entitlements (so it runs with MTE when started
directly), or run it under `tagwatch run`, which needs no entitlements.

```c
#include "tagwatch.h"

int main(void) {
    if (tagwatch_init() != 0) { /* no MTE here: every call below is a no-op */ }

    struct config *cfg = load_config();                   // an ordinary malloc'ed object
    tagwatch_watch(&cfg->timeout, sizeof cfg->timeout, "timeout");   // who reads or writes this field?

    char *big = tagwatch_alloc_watched(1 << 20, "frame"); // any size, from tagwatch's own MTE arena

    static long table[64];
    tagwatch_adopt(table, sizeof table);                  // make a global taggable, then:
    tagwatch_watch_mode(&table[3], 8, "table[3]", TAGWATCH_WRITE);
    ...
}
```

```sh
cc -Iinclude app.c -Lbuild -ltagwatch -Wl,-rpath,@executable_path/build -o app
codesign -s - --entitlements entitlements/mte.entitlements -f app
./app
```

Call `tagwatch_init()` first thing in `main`: unless the process was started by `tagwatch run`, it **forks**, and the
original process stays behind as the tracing parent (see "How it works"). [`include/tagwatch.h`](include/tagwatch.h)
documents the whole API: `tagwatch_watch`, `tagwatch_unwatch`, `tagwatch_alloc`, `tagwatch_adopt`,
`tagwatch_peek`/`poke` (touch watched memory without a report), `tagwatch_pause`/`resume`, a per-event callback, and
statistics.

## How it works

```
 program thread                          exception thread (inside the process)       tagwatch run (parent)
 ──────────────                          ─────────────────────────────────────       ─────────────────────
 str x1, [x0]      ; x0 -> watched
   └─ tag-check fault ───Mach exception──▶ look the address up in the watch table
      (thread frozen)                      decode the instruction: address, width, R/W
                                           walk the frame pointers, symbolise, log
                                           find/create the slot for this pc:
                                             msr TCO, #1      ; checks off, this thread only
                                             str x1, [x0]     ; the same instruction
                                             msr TCO, #0
                                             b   pc+4
   ◀──────reply: resume at the slot────────┘
 (runs the slot, continues after the str)                                             waits; passes signals on
```

1. **Arming.** For each 16-byte granule of the watched range, tagwatch reads the current allocation tag (`LDG`),
   remembers it, and stores a different, non-zero tag (`STG`). Every pointer the program holds now mismatches.
2. **Fault.** The access raises a synchronous tag-check fault. The task's `EXC_BAD_ACCESS` port belongs to a thread
   inside the process; the message carries the faulting thread's registers and the reply sets them.
3. **Log.** The handler decodes the instruction for the exact address, width and direction, walks the frame-pointer
   chain (using compact-unwind data to get leaf functions such as `memmove` right), symbolises from the Mach-O
   images in memory, and writes the log line and the JSON record.
4. **Proceed without disarming.** The handler points the thread at a small piece of generated code, one per faulting
   instruction address, which runs a copy of the instruction between `MSR TCO, #1` and `MSR TCO, #0` (TCO suppresses
   tag checks for the executing thread) and branches back. The granule's tag is never touched.
5. **Supervisor.** macOS kills a process on a tag-check fault unless it is traced, so the target calls
   `ptrace(PT_TRACE_ME)`. Its parent (`tagwatch run`, or a forked copy of your program in library mode) does nothing
   but wait and pass signals through.

Why this shape, and what was tried and rejected, is in [docs/DESIGN.md](docs/DESIGN.md).

### What is guaranteed with several threads

Because a watched granule keeps its watch tag while one thread is being let through, other threads touching it at
the same moment still fault. Every tag-checked access by any thread is trapped exactly once and takes effect exactly
once. `t_threads` checks this with exact counts (8 threads, 36 000 accesses, all reported, all values correct), and
`t_signal` checks it with a timer signal landing on a thread that is handling traps.

Not covered, by the nature of MTE or of the mechanism:

- accesses addressed as `[sp, #imm]` (MTE never checks them, so a watched stack variable is only seen through pointers);
- accesses made by the kernel in system calls tagwatch does not wrap (next section);
- accesses by a thread that called `tagwatch_pause()`;
- events are numbered in the order they were handled; two threads racing on the same granule may take effect in the
  opposite order.

## The hard cases

Each row is covered by a test that runs on MTE hardware (`make test`).

| Case | What happens | Test |
| --- | --- | --- |
| Several threads on one granule | All accesses trapped, exact counts. | `t_threads`, `t_far` |
| Arm/disarm while threads access | Faults already in flight when a watch is removed are retried, not reported as errors. | `t_threads` |
| `read`/`write`/`pread`/`pwrite`/`recv`/`send`/`fread`/`fwrite` on a watched buffer | A kernel access to an armed granule is fatal (next row), so the call is run against a bounce buffer, the data copied with tag checks off, and the access reported as made "by the kernel" with the caller's backtrace. | `t_syscall` |
| Any other system call on a watched buffer (`readv`, `getcwd`, `ioctl`, …) | **Not handled:** the kernel takes a fatal tag fault and the process is killed (exit status 137). | `cli.sh` ("unshimmed system call") |
| Large allocations (the system allocator only tags blocks up to about 4 KB) | Matching allocations are served from tagwatch's own MTE-backed arena, any size. | `t_alloc` (up to 70 MB) |
| Globals | The pages are replaced in place by MTE-backed copies ("adoption"), with other threads suspended. Done automatically for `-s`. | `t_adopt`, `cli.sh` |
| Stack memory | Another thread's stack can be adopted and watched; only accesses through pointers are seen. A thread cannot adopt its own stack. | `t_adopt` |
| Code and read-only file-backed pages | Cannot be adopted; `tagwatch_watch` returns `TAGWATCH_ENOTTAGGED`. | `t_adopt`, `t_basic` |
| `free` of a watched object | The watch stays armed in a quarantine (1 MB by default), so later accesses are reported as **use after free**; then it is removed and the memory reused. A double free is reported. | `t_alloc` |
| `realloc` | Contents are moved with tag checks off; the new block is watched if it matches a spec. | `t_alloc` |
| `fork` | Watches do not follow the child: its granules get their original tags back before it runs, and it runs unwatched. The parent is unaffected. | `t_fork`, `cli.sh` |
| `exec` | The new program runs unwatched and without the inserted library; exit status still propagates. | `cli.sh` |
| Signals | Forwarded by the supervisor. Handlers are wrapped so that one interrupting an execution slot runs with tag checks on. Blocking calls in the `wait`/`read`/`write` families are retried when the trace stop interrupts them. | `t_signal`, `cli.sh` |
| Code in system libraries (`memcpy`, `strlen`, zlib, …) | Traced like any other code; backtraces go through leaf functions correctly. | `t_insn` |
| Code more than 128 MB from any free address space (deep in the dyld shared cache) | The slot cannot branch back, so it ends in a breakpoint: two exceptions per access instead of one. | `t_far`, `t_insn` (zlib) |
| `LDXR`/`STXR` loops | Cannot be re-executed (the fault clears the exclusive monitor), so the pair is emulated as a compare-and-swap. | `t_insn` |
| A genuine MTE violation in the program (the target now runs with MTE on) | Reported with a backtrace as "not a watchpoint"; the program then dies as it would have. | `cli.sh` |

## Measurements

Apple M5 (10 cores, 16 GB), macOS 27.0, Apple clang 17, 1 October 2026. The machine was shared with other jobs (load
average 3–7 during the run), so treat the figures as ±15%. Each is the median of 5 runs. Reproduce with `make bench`;
method and raw output are in [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

**Per trapped access**

| Mechanism | µs per access |
| --- | --- |
| tagwatch, event delivered to a callback, nothing written | 4.7 |
| tagwatch, JSON record with a 16-frame symbolised backtrace written to a file | 6.6 |
| tagwatch, JSON record and live log line | 7.6 |
| tagwatch, slow return path (code far from free address space, 2 exceptions) | 8.9 |
| retag + single-step + retag (the obvious design; rejected, also racy) | 15.5 |
| `mprotect` page watch (fault, single-step, two `mprotect` calls) | 16.3 |
| an untrapped access, for scale | 0.0001 |

**Overhead on a workload.** `bench/kv.c`: a hash table of 100 000 heap nodes (48 bytes each), one million lookups and
updates on random keys; time for the operations phase.

| Configuration | Time (ms) | Traps | Slowdown |
| --- | --- | --- | --- |
| native, MTE off | 10.0 | – | 1.0× |
| MTE on, tagwatch not loaded (`--no-runtime`) | 10.0 | – | 1.0× |
| tagwatch loaded, nothing matched | 9.9 | 0 | 1.0× |
| 1 node watched | 10.7 | 23 | 1.1× |
| 10 nodes watched (1 in 10 000) | 14.2 | 428 | 1.4× |
| 100 nodes (1 in 1 000) | 41.3 | 4 068 | 4.1× |
| 1 000 nodes (1 in 100) | 309 | 40 116 | 31× |
| 10 000 nodes (1 in 10) | 2 954 | 405 522 | 295× |
| all 100 000 nodes | 28 156 | 4 049 194 | 2 800× |

Cost is proportional to the number of trapped accesses, about 7 µs each here, and nothing else: a few objects in a
large program cost nothing measurable, every object in a hot loop costs three orders of magnitude. (The operations
phase does not allocate, so this table does not measure the allocation interposers, which add a branch per
`malloc` when no allocation spec is active.)

**The same task with page protection.** `bench/pagewatch.c` runs the same workload and watches the same nodes by
protecting their pages. Both tools report the same number of true accesses, which is a useful cross-check:

| Watched | Tool | Time (ms) | Traps | Accesses to watched nodes | False traps |
| --- | --- | --- | --- | --- | --- |
| 1 node | tagwatch | 9.8 | 23 | 20 (+3 during table construction) | 0 |
| 1 node | mprotect | 32.0 | 1 300 | 20 | 98.5% |
| 100 nodes | tagwatch | 43.0 | 4 068 | 3 768 (+300 during construction) | 0 |
| 100 nodes | mprotect | 20 383 | 1 267 454 | 3 768 | 99.7% |

A 16 KB page holds about 340 of these nodes, so a page watch takes roughly 340 traps for each one that matters. With
100 watched nodes spread over 100 pages it is 470 times slower than tagwatch on this workload.

**Hardware watchpoints.** `sysctl hw.optional.watchpoint` reports **4** debug registers on the M5; that is the limit
LLDB watchpoints live under, against 100 000 simultaneous watches in the table above. I could not time LLDB itself:
Developer Mode is off on the development machine and I have no administrator rights there, so LLDB cannot launch a
process. As a substitute `bench/hwwatch.c` programs the same debug registers from inside the process; a delivered hit
cost 17–33 µs, but only a fraction of the hits were delivered in that configuration (36 of 5 000 in the recorded run),
so it is not a usable baseline and I draw no conclusion from it beyond the register count.

## Limitations

- **Platform.** M5 or later, macOS 27.0 tested. Relies on a private spawn SPI, on undocumented `VM_FLAGS_MTE`
  mappings and on the kernel's treatment of traced processes; any of these can change.
- **Being traced has side effects.** The target stops on every signal until the supervisor passes it on, so signal
  delivery is slower, and blocking system calls can fail with `EINTR` although no handler ran. tagwatch retries the
  `wait`, `read` and `write` families in that case; other calls (`select`, `poll`, `nanosleep`, `accept`, …) are
  not covered and a program that does not handle `EINTR` there can misbehave.
- **Unwrapped system calls on watched memory kill the process** (see the table above).
- **No attach, no hardened-runtime or SIP-protected targets, no arm64e.**
- **`fork` and `exec` end the watch** for the child / new image.
- **Stack variables** are only seen through pointers; **code and read-only file-backed data** cannot be watched.
- **Granularity is 16 bytes** for trapping. Neighbours in the same granule cost a trap each (filtered from the
  report).
- **Watched allocations live in tagwatch's arena**, not the system heap: their addresses, neighbours and reuse
  pattern differ from an unwatched run, which can hide or move a layout-dependent bug.
- **The handler is in the process.** A program that corrupts memory wildly can corrupt tagwatch's state too. A
  program that installs its own Mach exception ports for `EXC_BAD_ACCESS` (some crash reporters do) replaces the
  handler.
- **LL/SC emulation** uses compare-and-swap and therefore cannot see an A→B→A change between `LDXR` and `STXR`.
- **Self-modifying or JIT-generated code** that changes an instruction while another thread runs its slot is not
  handled; the slot is rewritten on the next fault at that address.
- **Backtraces** rely on frame pointers (standard on Apple platforms) and show mangled-name-plus-offset, not
  file and line. The summary demangles C++ names. Tail calls hide frames, as in any debugger.
- **Overhead** is about 5–9 µs per trapped access. Watching memory that is touched millions of times per second makes
  the program thousands of times slower.
- **Library mode forks** in `tagwatch_init()`, and handlers installed before that call are not wrapped.

## Tests

```sh
make unit       # logic that needs no MTE; this is what CI runs on macos-latest
make sanitize   # the same under UBSan (CI adds AddressSanitizer)
make lint       # -Werror build and the clang static analyzer
make mte-test   # everything that needs MTE; prints SKIP with the reason on other hardware
```

The unit tests cover the instruction decoder (against encodings produced by the real assembler, plus two million
random words), the watch table (against a reference model, with injected allocation failures), the spec grammar and
JSON reader (round-trip properties), the symboliser (against `dladdr`), and the report. Randomised tests use fixed
seeds and print the seed on failure.

GitHub-hosted runners are M1/M2 machines without MTE, so CI builds the MTE tests and reports them as skipped.
**The MTE tests were run locally on an Apple M5 (macOS 27.0).** Output of `make test` there:

```
ok   fmt            20024 checks
ok   insn           2379659 checks
ok   wtab           686182 checks
ok   spec           60069 checks
     (memmove unwind mode 1, leaf 3)
ok   symtab         233 checks
ok   json           160033 checks
ok   report         55 checks
     (sp-relative store to a watched stack slot: not reported, as MTE never checks [sp, #imm] accesses)
ok   adopt      33 checks
     (58 watches armed in total, 5 still live in quarantine)
ok   alloc      75 checks
ok   basic      62 checks
ok   far        8 checks
ok   fork       16 checks
     (libz crc32 over the watched window: 2 traps; 2 traps so far took the slow return path)
ok   insn       245 checks
     (544 timer signals delivered during 20000 traps; all 20544 accesses reported)
ok   signal     25 checks
ok   syscall    103 checks
     (9794 accesses caught during 3000 arm/disarm cycles with 4 threads running)
ok   threads    3041 checks
ok   cli        53 checks
MTE tests passed
```

## Related work

The technique is not new. Using MTE tag mismatches as cheap, fine-grained access traps has been done on Linux and
Android; what this project adds is a working tool on macOS, where the pieces (enabling MTE without entitlements,
surviving a tag fault, tagging memory the allocator does not tag) are different and mostly undocumented. To my
knowledge, no such tool existed for macOS as of September 2026.

- **Noh et al., "ARM MTE Performance in Practice"** ([arXiv:2601.11786](https://arxiv.org/abs/2601.11786)) includes
  *MTE-tracer*, a user-space memory tracer on a Pixel 8. As the paper describes it, the tool tags the data of
  interest, takes the fault in a signal handler, and runs a generated "log, step, resume" snippet that untags the
  data, re-executes the instruction and retags. tagwatch shares the idea of generated code per fault site. It differs
  in leaving the tag in place and suppressing the check with `PSTATE.TCO` (which is what makes it safe with threads),
  in being a watchpoint tool rather than a benchmark subject, and in the platform. Their kernel-assisted variant has
  no counterpart here.
- **HMTRace** ([arXiv:2404.19139](https://arxiv.org/abs/2404.19139)) uses MTE to detect data races in C programs on
  Armv8.5 Linux: a different question (who races) answered with the same hardware mechanism.
- **NanoTag** ([github.com/ice-rlab/nanotag](https://github.com/ice-rlab/nanotag), IEEE S&P 2026) gets byte-granular
  overflow detection out of 16-byte MTE on Android with "tripwire" allocations and a software check in the fault
  handler. tagwatch's address filtering is a much simpler cousin of that idea and detects nothing by itself.
- **LLDB `process launch --memory-tagging`** ([llvm-project PR 162944](https://github.com/llvm/llvm-project/pull/162944))
  is where the spawn SPI used by `tagwatch run` is publicly visible. LLDB uses it to run a program with MTE checking;
  its watchpoints remain the four hardware ones.
- **Apple-MTE-Research** ([github.com/kaffeindecaf/Apple-MTE-Research](https://github.com/kaffeindecaf/Apple-MTE-Research))
  and **8kSec's "MIE deep dive"** ([8ksec.io/mie-deep-dive-enabling-apps](https://8ksec.io/mie-deep-dive-enabling-apps/))
  document how Apple's Memory Integrity Enforcement is enabled and what a tag fault looks like. Neither is a tracing tool.
- Page-protection watchpoints and hardware watchpoints are the classic alternatives; both are measured above.

## Scope

tagwatch is a debugging aid for programs you build and run yourself. It has no way to attach to a running process,
does not work on hardened or system binaries, and does nothing to weaken MTE as a protection: a traced program has
*more* checking than usual, and real violations are reported and remain fatal.

## Repository layout

```
include/tagwatch.h   public C API
src/                 the runtime (libtagwatch.dylib); see docs/DESIGN.md for a file-by-file tour
cli/                 tagwatch run / report / check
tests/unit/          tests that need no MTE (CI)
tests/mte/           tests that need MTE: library-mode tests, CLI targets and cli.sh
examples/            ledger.c, the worked example
bench/               measurements and the comparison baselines
experiments/         the small programs behind the design decisions, with recorded results
```

## License

MIT. See [LICENSE](LICENSE).

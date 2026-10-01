# tagwatch: design notes

This document explains how tagwatch is put together, which problems were hard, how they were settled, and what was
tried and thrown away. Claims about the platform are either measured by a program in `experiments/` or `tests/`, or
marked as not verified.

## 1. The problem and the constraints

Goal: report every access to chosen memory, at finer granularity and in larger numbers than the four hardware
watchpoints allow, on a Mac, without privileges.

MTE gives each 16-byte granule of memory a 4-bit *allocation tag* and each pointer a 4-bit *logical tag* in bits
56–59. A load or store faults when the two differ. A process may change the allocation tags of its own memory from
user mode (`STG`), so "make this granule mismatch every existing pointer" is one instruction. That is the whole
trick; everything else is making it survivable and useful.

What macOS adds to the problem (all observed on an M5 with macOS 27.0):

| Fact | Evidence |
| --- | --- |
| A process gets MTE only if it is signed with `hardened-process` + `hardened-process.checked-allocations`, or is spawned with `posix_spawnattr_set_use_sec_transition_shims_np`. | tested with each subset of the entitlement keys; `tagwatch check` |
| Only MTE mappings hold tags: `malloc` blocks of up to 32 KB (32 769 bytes and more come back untagged) and memory mapped with `VM_FLAGS_MTE`. `STG` elsewhere raises a bus error; `LDG` elsewhere returns 0. | `experiments/vm_behaviour.c` (malloc-tags, ldg-plain) |
| A tag-check fault is delivered as `EXC_BAD_ACCESS` with code `0x106`, and then the process is killed whatever the handler replies. Signal handlers never run. | feasibility probe; `experiments/external_handler.c` |
| If the process is ptrace-traced, the fault is an ordinary recoverable exception. | same |
| Soft mode is no use: checking switches off after the first fault. | feasibility probe |
| When the *kernel* touches a mismatched granule on behalf of a system call, the process is killed and nothing is delivered. | `experiments/vm_behaviour.c`, `tests/mte/cli.sh` |
| `PSTATE.TCO` (tag check override) can be set from user mode with `MSR TCO`, but not through `thread_set_state`. | `experiments/let_access_proceed.c` |
| `fork()` copies the tag storage of every MTE mapping, touched or not: about 8 ms per GB (0.9 ms for a fork with no MTE mapping, 10.6 ms with an untouched 1 GB one, 497 ms with 64 GB). | `experiments/vm_behaviour.c` (fork-cost) |

I have not verified *why* tracing changes the outcome; it is an observed kernel policy and could change.

## 2. Architecture

```
┌─ tagwatch run (parent) ──────────────┐      ┌─ target process ────────────────────────────────────┐
│ posix_spawn with the MTE shim SPI    │      │ libtagwatch.dylib (inserted with DYLD_INSERT_…)     │
│ and DYLD_INSERT_LIBRARIES            │      │                                                     │
│                                      │      │  program threads ── fault ──▶ exception thread      │
│ supervise.c: waitpid loop            │◀────▶│    interposers:                 exc.c: classify     │
│   pass signals on (PT_CONTINUE)      │ptrace│    malloc family → arena.c      insn.c: decode      │
│   swallow the exec SIGTRAP           │      │    read/write family (bounce)   bt.c/symtab.c       │
│                                      │      │    sigaction (wrap handlers)    trace.c: log, JSON  │
│ report.c: summary from the trace  ◀──┼──────┼─── trace file (JSON lines)      tramp.c: slots      │
└──────────────────────────────────────┘      └─────────────────────────────────────────────────────┘
```

File by file (`src/`):

| File | Role |
| --- | --- |
| `mte.c` | The only file with MTE instructions: `LDG`, `STG`, `MSR TCO`, and the guarded variants that survive a fault. |
| `wtab.c` | Watch table: granule → owning watch and original tag. Pure data structure. |
| `watch.c` | Watch records; arming and disarming under one lock. |
| `exc.c` | The exception thread: receive, classify, log, choose how to resume. LL/SC emulation. |
| `tramp.c` | Execution slots (generated code) and their placement. |
| `insn.c` | AArch64 load/store decoder: address, width, direction. |
| `bt.c`, `symtab.c` | Frame-pointer backtraces; symbols and compact-unwind data read from the mapped images. |
| `trace.c`, `fmt.c` | Live log and JSON lines, formatted without `malloc` or stdio. |
| `arena.c` | MTE-backed allocator for watched objects, registered as a malloc zone; use-after-free quarantine. |
| `adopt.c` | Replaces ordinary pages by MTE pages in place (globals, stacks). |
| `interpose.c` | dyld interposers: allocation, system calls on watched buffers, EINTR retry, signal-handler wrapping. |
| `supervise.c` | The tracing parent's loop (also used by the CLI). |
| `runtime.c` | Initialisation, configuration, public API. |
| `spec.c` | Grammar of watch specifications (shared with the CLI). |
| `vm.c` | Page allocation straight from the kernel for the runtime's own data. |

## 3. Decision: where the fault handler lives

Two candidates: a thread inside the target, or the parent process.

An external handler is possible without privileges: `posix_spawnattr_setexceptionports_np` gives the child an
exception port owned by the parent, and the exception message carries the child's thread state.
`experiments/external_handler.c` does exactly that: with the child traced, 5000 of 5000 faults were handled in the
parent, at 7.9 µs each for the bare round trip. (Untraced, the first fault reached the parent and the child was killed
regardless.) An external handler would also be immune to a target that scribbles over its own memory.

It was still rejected, because the parent cannot do the rest of the job from outside:

- Tags can only be written by `STG` executed *in* the process. There is no "set tag in another task" call.
- Matching allocations means being inside `malloc`.
- The cheap way to let an access through (section 4) needs generated code in the target's address space.
- A backtrace from outside costs a `mach_vm_read` per frame; from inside it is a pointer walk.
- The same-process round trip is cheaper: 4.7 µs with the full handler, against 7.9 µs for an empty external one.

So an in-process agent is needed in any case, and once it is there it is the natural place for the handler. The
parent is kept as small as possible: it exists because *somebody* has to be the ptrace tracer, and a traced process
stops on every signal until its tracer says continue.

In library mode there is no `tagwatch run` parent, so `tagwatch_init()` forks: the original process becomes the
supervisor (it keeps the pid the shell knows and exits with the program's status), and the program continues in the
child. This is why the call must come before any other thread exists.

## 4. Decision: how to let the access proceed

The faulting instruction cannot succeed as it stands. Five ways out were considered.

**A. Restore the tag, single-step, tag again.** The obvious design, and the one the feasibility probe used. Two
exceptions per access plus two debug-state system calls: 14.8 µs measured (`bench/naive_step.c`). Worse, while the
original tag is in place any other thread can access the granule unseen. Closing that hole means suspending every
other thread around every access. Rejected.

**B. Set `PSTATE.TCO` for the faulting thread through its saved state and single-step.** No retagging, so no race.
It does not work: the kernel does not copy the TCO bit from `thread_set_state` or from the exception reply, and the
instruction faults again forever (`experiments/let_access_proceed.c tco-state`).

**C. Change the tag in the base register instead.** Give the pointer the watch tag, re-run the instruction, and the
check passes. But the register now holds a pointer that differs from every other copy of it: pointer comparisons
change meaning and the program's behaviour with it. Rejected without an experiment.

**D. Emulate the instruction in the handler.** One exception, no generated code, but it needs a complete and exact
interpreter for every load/store form including SIMD. A decoder mistake would silently corrupt the target. Used only
where unavoidable (section 9).

**E. Execute the instruction out of line with TCO set.** Chosen. For each faulting address the handler writes a
16-byte slot into MAP_JIT memory:

```
msr  TCO, #1
<copy of the faulting instruction>
msr  TCO, #0
b    <faulting address + 4>
```

and resumes the thread at the slot. `MSR TCO` is a user-mode instruction, the override applies only to the thread
executing it, and the granule's tag is not touched. One exception per access: 4.7 µs.

Why copying the instruction is sound: only loads and stores with a register base take tag-check faults (literal loads
and `[sp, #imm]` accesses are never checked), and those behave identically at any address. Nothing else in the slot
reads or writes a general register. The slot does not depend on the decoder: an instruction it does not recognise
(SME loads and stores in streaming mode, for instance; the M5 has SME) is re-executed the same way, and only the report
is poorer: the fault address, one byte, and the direction from the syndrome register. `t_insn` runs an SME `LD1B`
into the ZA array from a watched window to check this. A slot is written once and never changed afterwards (unless the code at that
address changes, which is detected by comparing the instruction word on each fault), so any number of threads can be
inside the same slot.

**The branch back.** `B` reaches ±128 MB, and AArch64 has no way to jump further without putting the target in a
register. x16/x17 are scratch only at call boundaries; in the middle of a function they can hold live values, so
they cannot be borrowed. Slots are therefore allocated near the code they serve: on the first fault in a
neighbourhood, `tramp.c` walks the VM map for unmapped space within ±120 MB and maps a pool there. This works for the
program and its libraries. It works for libsystem too, which sits near the start of the dyld shared cache, because the
address space just below the cache is free: in `t_insn`, the traps in `memcpy`, `memset` and `strlen` all take near
slots, and only zlib's `crc32` takes the far path. Code deep inside the multi-gigabyte shared cache has nothing free within reach. For that, a *far slot* ends in
`BRK` instead of `B`; the handler sees the breakpoint and sets pc itself. Two exceptions, 9.5 µs, same guarantee.
`t_insn` hits this path naturally (zlib's `crc32`), and `t_far` forces it for every access.

**Signals and TCO.** `experiments/vm_behaviour.c` shows that a signal handler inherits `PSTATE.TCO`. If a signal
arrived while a thread was inside a slot, the whole handler would run unchecked. The `sigaction`/`signal` interposers
therefore wrap every handler in a small function that clears TCO first. When the handler returns, either `sigreturn`
restores the bit and the slot continues, or the bit stays clear, the instruction faults inside the slot, and the
exception thread (which recognises a pc inside a slot) restarts it. Both are correct; `t_signal` checks the outcome
(exact counts with several hundred timer signals landing during 20 000 traps) without telling the two apart.

## 5. The guarantee with several threads, and the race that was found

Arming and disarming hold one lock while they change the table and the tags together. The handler consults the table
under the same lock. During an access nothing is changed at all. So:

> Every tag-checked access to an armed granule, by any thread, is reported once (subject to the read/write and
> byte-range filters) and takes effect exactly once.

(It may fault more than once before that: a fault that finds the watch lock busy, or that raced with the removal of
its watch, is simply retried; see below.)

`t_threads` checks the counts exactly: 8 threads × 1500 iterations × 3 accesses = 36 000 events, shared counter and
private slots all at their expected values.

One real race turned up in testing. A fault can be in flight, queued for the handler, while another thread removes
the watch. The handler then finds no watch. The first version compared the pointer's tag with the granule's current
tag to tell "the watch just went away, retry" from "a genuine MTE violation", but read the tag *after* releasing the
lock. If the watch was re-armed in between, a healthy access was classified as a violation and the process died,
in 15–40% of the runs of the churn test. The tag is now read under the lock, together with the table lookup.
The retry is bounded (16 times at one pc), so that a fault whose reported address is not the mismatching granule
cannot loop forever. The bound only counts while the set of watches is unchanged, because under churn any number of
retries is legitimate.

A second problem was a deadlock, found in the final review. Arming probes each new page with a guarded `LDG`/`STG`
that faults on purpose when the page is unmapped or not an MTE mapping, and that fault is resumed by the exception
thread. The probe runs under the watch lock. If the exception thread was meanwhile handling another thread's trap, it
waited for that same lock, the prober waited for the exception thread, and the process hung for good (no signal could
end it, since every thread was either frozen in an exception or blocked). A multi-threaded program that called
`tagwatch_watch` on a stack or global address, or `tagwatch_adopt`, while other threads trapped could hit it. The
exception thread now never waits for the watch lock: it spins briefly and, if the lock is still taken, lets the
faulting thread retry, which frees it to serve the prober first. On its own that can starve the handler when one
thread arms in a tight loop, so a handler that gave up leaves a timestamp, and program threads hold back for up to
100 µs before their next acquisition. The third part of `t_threads` (4 threads × 20 000 trapped loads while the main
thread keeps failing to arm untaggable and unmapped memory) hung every time before the fix; it now finishes in about
a second with exact counts.

What the guarantee does not include: `[sp, #imm]` accesses (never tag-checked), kernel accesses in unwrapped system
calls, threads that called `tagwatch_pause()`, and the *order* of events relative to the order in which racing
accesses took effect.

## 6. Tags, the table, byte-precise reports

Arming a granule saves its tag and stores `original XOR 8` (or 12 if that would be 0). The watch tag always differs
from the original, so legitimate pointers fault, and is never 0, so untagged pointers fault too.

The table (`wtab.c`) is a hash from 16 KB page number to an array with one 32-bit cell per granule: owning watch slot
and saved tag. Lookup is one probe and one index. A page's array is released when its last watch goes. Watches may
not overlap.

Requests are not granule-aligned, so the armed range is the request rounded outwards. The handler compares the exact
access range (from the decoder) with the requested byte range and drops accesses that only touch the rounding; they
are counted as "filtered". That is how `off=16,len=8` reports writes to one field while the neighbour in the same
granule is accessed thousands of times.

For accesses that straddle a watched and an unwatched granule, the decoder's effective address and width are used to
find the watch even if the address the CPU reports lies in the unwatched part.

## 7. Memory that has no tags

**Heap objects matched by a spec** are not left in the system heap. The system allocator only tags small blocks,
retags on its own schedule, and would see tagwatch's retagging as corruption. `arena.c` maps MTE regions of 256 MB on
demand (populated lazily by the kernel; a larger block gets a region of its own), hands out granule-aligned blocks of
any size with a 32-byte header, and is registered as a malloc zone, so `free`, `realloc` and `malloc_size` on an arena
pointer end up there even from code the interposers cannot see. Ownership is a range check over the regions. The
first version reserved 64 GB up front, which looked free until `fork` was measured: the kernel copies the tag storage
of an MTE mapping whether or not it was touched (section 1), so every `fork` of a traced program took half a second.
With 256 MB regions a fork costs about 3 ms (`t_fork` prints the figure and fails above 100 ms).

**A block of the system heap watched through the API** is armed in place; the `free`/`realloc` interposers disarm it
before the allocator sees it again. The allocator does not recognise a block whose first granule is retagged
(`malloc_size` returns 0), so that granule is disarmed first and the rest of the block is searched afterwards.

**Globals and other ordinary pages** are *adopted*: every other thread is suspended, the page's bytes are copied
aside, the page is replaced with `mach_vm_map(FIXED | OVERWRITE | MTE)` at the same address, the bytes are copied
back, threads resume. Fresh MTE pages carry tag 0, which is what untagged pointers to globals expect. Code pages are
refused (replacing them would break code signing), as is the calling thread's own stack (the copy-back runs on it).
A thread blocked in a system call that writes to the page during those microseconds would lose its write; adoption
at start-up, which is what `-s` does, has no other threads to worry about.

**Stacks** can be adopted from another thread, but compilers address most locals as `[sp, #imm]`, which MTE does not
check. A stack watch therefore sees accesses through pointers only. `t_adopt` demonstrates both halves.

## 8. Allocation, free, reuse

The malloc-family interposers check the spec list: size range first (two compares), then, if the spec names a
function, the innermost `depth` return addresses are symbolised (cached) and compared. `every`, `skip` and `limit`
sample. A match is served from the arena and armed; `off`/`len` narrow the armed range to one field.

On `free`, a watched arena block is marked freed and stays armed in a FIFO quarantine (1 MB by default). Accesses
are reported with a use-after-free flag. When it leaves the quarantine, all watches inside the block are removed and
the block is recycled. A second `free` of a quarantined block is reported and ignored.

## 9. System calls, signals, fork, exec

**System calls.** There is no fault to recover from when the kernel hits a mismatched granule: the process is
killed. The interposers for `read`, `pread`, `recv`, `write`, `pwrite`, `send`, `fread` and `fwrite` check the
buffer against the table (one atomic load when nothing is armed), run the call against a private buffer, copy with
TCO set, and report the access as made by the kernel. Everything else (`readv`, `ioctl`, `getcwd`, `stat` into a
watched struct, …) is not covered and is fatal; `cli.sh` has a test that demonstrates it. Covering every system call
needs a table of which arguments point to memory, which I left out.

**Signals.** A traced process stops on each signal; `supervise.c` continues it with the same signal. A kqueue tells
the `SIGTRAP` that tracing adds after `exec` apart from one the program raised. A side effect cannot be avoided: the
stop aborts blocking system calls in every thread with `EINTR`, even for a signal that is ignored. The interposers
for the `wait`, `read` and `write` families retry when `EINTR` comes back and no signal handler ran on the thread
in between (a per-thread counter kept by the handler wrapper), which restores POSIX behaviour for those calls.

**fork.** The child has no exception thread and is not traced, so the `atfork` child handler puts every original tag
back and detaches from the exception port before any program code runs. The forking thread holds the watch lock across
`fork()`, because the kernel copies the address space one VM entry at a time while other threads keep arming: without
the lock the child's copy of the table and its copy of the tags could come from different instants. The table marks
which granules are actually armed, so the child restores exactly those. `os_unfair_lock` records its owner, so locks
are re-initialised in the child rather than unlocked. `t_fork` forks 300 times while other threads arm and disarm
continuously and checks that no child ever finds a watch tag.

**exec.** The runtime removes itself from `DYLD_INSERT_LIBRARIES` and drops its `TAGWATCH_*` variables right after
start-up, so programs launched by the target run clean. The exec'ed image itself also runs without MTE watches. The
trace and log descriptors are close-on-exec, so it does not inherit them either (`cli.sh` checks this).

**Programs that cannot be traced.** `tagwatch run` reads the program's Mach-O header first. The runtime is built for
arm64 only, and dyld aborts a process when an inserted library has the wrong architecture, so a program with no
arm64 code (arm64e-only or x86_64-only) is refused with that reason. A universal binary with both arm64 and arm64e
slices would run as arm64e; `posix_spawnattr_setarchpref_np` asks for the arm64 slice instead. Binaries with the
hardened runtime, and SIP-protected system binaries, ignore `DYLD_INSERT_LIBRARIES`: they run with MTE on but
unwatched, and the summary says that the runtime never started. Each case has a test in `cli.sh`.

**LDXR/STXR.** Taking an exception clears the CPU's exclusive monitor, so a store-exclusive that traps can never
succeed and its retry loop would spin forever. The handler emulates the pair the way QEMU does: the load records the
value it returned, the store becomes a compare-and-swap against it and sets the status register. An A→B→A change
between the two is not seen. macOS compilers emit LSE atomics (`CASAL`, `LDADDAL`, …), which are single instructions
and go through a slot like any other; this path is for hand-written assembly.

## 10. What the handler may and may not do

The handler runs while a program thread is frozen at an arbitrary instruction, perhaps inside `malloc` or dyld.
It therefore does not allocate, does not use stdio, and does not call `dladdr`:

- formatting goes into stack buffers (`fmt.c`) and out with one `write(2)` per record;
- symbols come from `LC_SYMTAB` of the images already mapped (`symtab.c`), cached per address;
- the thread's stack bounds and id come from one `mach_vm_region`/`thread_info` call, cached per thread port;
- all its own memory comes from `mach_vm_allocate`.

The handler thread runs with TCO set permanently (it must never trap on the memory it inspects) and blocks all
signals.

**Backtraces.** Frame-pointer walk, bounded by the thread's stack region. The subtle part is frame 0. A leaf
function has no frame record, so its caller is only in x30, and for the typical question ("who called the `memcpy`
that wrote here?") the caller is the answer. Whether the function at pc keeps a frame is read from its compact unwind
encoding (`__unwind_info`); hand-written routines such as `_platform_memmove` have no entry and are treated as
leaves. `test_symtab` checks the symboliser against `dladdr` and the unwind reader on a framed and a frameless
function.

## 11. Testing

- **Unit tests** (any arm64 Mac, CI): decoder against encodings assembled at build time and against two million
  random words; watch table against a reference model with injected allocation failures; spec and JSON round trips;
  symboliser against `dladdr`; report output.
- **MTE tests** (M5): library-mode programs that perform exact instructions on watched memory and check both the
  report and the effect; `cli.sh` runs unmodified programs under `tagwatch run`.
- Bugs the tests found, each now covered: the lock held across `fork`; the classification race of section 5; `LDG`
  on an unmapped address; watches left armed inside a freed block; `EINTR` from trace stops; two leak-on-error paths
  and a NULL string table (static analyzer).
- Found in review, each with a regression test: event `watch` ids that were trace serials rather than the id the
  caller holds; `realloc` of a block watched in place losing its contents; inconsistent tags in fork children and the
  half-second fork (section 7); the deadlock of section 5; arm64e programs aborted by dyld with a misleading message;
  the `tagwatch run` log descriptor leaking into exec'ed programs.

## 12. Left out

- **Attach.** Needs `task_for_pid`, which needs privileges; also deliberately out of scope.
- **Store-only checking.** The M5 reports `FEAT_MTE_STORE_ONLY`; with it, write watchpoints would not pay for
  reads. I found no user-mode way to turn it on.
- **Wrapping all system calls**, **following `fork`**, **file and line in backtraces** (the trace carries image
  offsets for `atos`).
- **A fallback for processes that cannot map JIT memory** (hardened runtime without `allow-jit`): `tagwatch_init`
  fails there.

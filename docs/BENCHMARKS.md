# Benchmarks: method and raw output

Everything quoted in the README comes from `make bench` (`bench/run.sh`). This file says what each line measures and
reproduces the raw output of the run the README uses.

## Conditions

- Apple M5, 10 cores, 16 GB; macOS 27.0 (26A428); Apple clang 17.0.0; `-O2`.
- The machine was **shared** with other jobs during the run (load average about 3 at the start, see the raw output),
  so absolute numbers carry noise of ±15% or more. Ratios between mechanisms are far larger than that.
- The run below is of the code as committed (after the review fixes of 1 October 2026). An earlier run, before those
  fixes, is in the git history of this file; the figures moved by less than the noise except the trace-writing line
  (6.6 → 7.8 µs).
- Every figure is the median of 5 runs of the corresponding program.
- Times are wall-clock, taken inside the measured program around the loop of interest with `CLOCK_MONOTONIC`.

## What is measured

**Per-trap cost.** `bench/trapcost.c` links the library, watches a 64-byte arena object and runs a loop with one store
and one load per iteration (20 000 iterations = 40 000 traps), after a warm-up that creates the execution slots. It
reports elapsed time divided by traps taken, in three output modes: a callback that only counts; the JSON-lines trace
(each record has a symbolised backtrace, written with one `write(2)`; "16-frame" in the label is the depth limit, and
the loop is three calls deep, so records carry three frames); trace plus live log. With
`TAGWATCH_FORCE_FAR=1` every slot returns through a breakpoint, which is the path taken for code that has no free
address space within ±128 MB.

`bench/naive_step.c` is the design tagwatch rejected, implemented directly: on the fault put the original tag back,
set the single-step bit, on the step exception put the watch tag back. Same loop.

`bench/pagewatch.c` and `bench/hwwatch.c` report their own time per trap (see below).

**Workload overhead.** `bench/kv.c` (code in `bench/kv.h`) builds a chained hash table of 100 000 nodes, each a 48-byte
`malloc` block, then performs 1 000 000 operations on uniformly random keys: half read a node's value, half update two
of its fields. Only the operations phase is timed. It is run natively, under `tagwatch run --no-runtime` (MTE on,
nothing inserted), with the runtime inserted but an allocation spec that matches nothing, and with
`-a size=48,every=K` for K from 100 000 down to 1, i.e. from one watched node to all of them. "Traps" is the runtime's
own counter from the trace's final `stats` record and includes the accesses made while the table is built (three per
watched node).

**Page protection on the same task.** `bench/pagewatch.c` links the same `kv.h`, builds the same table, and watches
nodes 0, K, 2K, … by setting their pages to `PROT_NONE`. Its handler is an in-process Mach exception thread, like
tagwatch's: on a fault inside an armed page it counts the trap, checks whether the address lies in a watched node (a
true hit), unprotects the page, single-steps the instruction, and protects the page again. "False traps" are traps
whose address is not in a watched node. For the comparison, tagwatch's true hits are the `access` records whose
backtrace contains `kv_run` (the operations phase), because the page watch can only be armed after the table exists.
Both tools reporting the same number of true hits (20 and 3 768) is a check that they watched the same thing.

**Hardware watchpoints.** `hw.optional.watchpoint` is the number of debug watchpoint registers the kernel exposes.
`bench/hwwatch.c` sets one watchpoint on an 8-byte variable through `thread_set_state(ARM_DEBUG_STATE64)` and handles
the resulting exceptions in-process (disable, single-step, re-enable), which is what a debugger does minus the
debugger. In this configuration most hits are not delivered at all (the watchpoint stops firing for stretches; I did not
find out why), so the program reports time per *delivered* hit and the count. It is included for
completeness, not as a baseline. LLDB itself was not measured: it cannot launch processes on the development machine
(Developer Mode is disabled and enabling it needs an administrator).

## Raw output

```
## machine
Apple M5
ProductName:		macOS ProductVersion:		27.0 BuildVersion:		26A428
load average: { 3.22 3.19 3.16 }
runs per figure: 5 (median reported)

## per-trap cost (microseconds per trapped access)
tagwatch, near slot, callback only                         4.70
tagwatch, near slot, JSON trace + 16-frame backtrace       7.78
tagwatch, near slot, JSON trace + live log                 8.52
tagwatch, far slot (2 exceptions), callback only           9.47
naive retag + single-step (rejected design)                14.82
mprotect page watch (fault + single-step + 2 mprotect)     16.47
hardware watchpoint registers, driven in-process           25.00
unwatched access, for scale                                0.12 ns

## overhead on the kv workload (100000 nodes of 48 bytes, 1000000 operations); ops phase in ms
configuration                                      ops_ms      traps
native (no MTE)                                     11.29          -
MTE on, runtime not loaded                           9.81          -
runtime loaded, nothing matched                      9.87          0
1 node in 100000 watched (1 objects)                10.20         23
1 node in 10000 watched (10 objects)                14.01        428
1 node in 1000 watched (100 objects)                39.84       4068
1 node in 100 watched (1000 objects)               295.02      40116
1 node in 10 watched (10000 objects)              2652.80     405522
1 node in 1 watched (100000 objects)             25866.40    4049194

## the same task with page protection: watch 1 node in K of the kv workload
K          tool           ops_ms        traps    true hits    false %      pages
100000     tagwatch        10.15           23           20       0.00          -
           (tagwatch also reported 3 accesses while the table was being built)
100000     mprotect        31.40         1200           20      98.33          1
1000       tagwatch        42.34         4068         3768       0.00          -
           (tagwatch also reported 300 accesses while the table was being built)
1000       mprotect     20511.70      1267312         3768      99.70        100

## hardware watchpoints
debug registers available for watchpoints (hw.optional.watchpoint): 4
hwwatch hits=5000 traps=11 us_per_hit=17.27 value=4999
```

## Reading the numbers

- A trap is one Mach exception round trip to a thread in the same process plus the handler's work. The kernel part
  dominates: the callback-only figure (4.7 µs) is what the mechanism costs with no logging at all; formatting,
  symbolising (cached per address) and one `write` add about 3 µs; the live log another 0.7 µs.
- The slow return path costs one more exception (9.5 µs). The naive design needs that second exception too, plus two
  debug-state system calls per access, and lands at 14.8 µs.
- In the workload table, time grows linearly with traps: (25 866 − 10) ms / 4 049 194 traps ≈ 6.4 µs per trap, a
  little below the micro-benchmark with tracing on (7.8 µs). The two are different programs measured minutes apart
  on a shared machine; I have not investigated the difference further.
- With MTE on and nothing watched, the workload runs at native speed within noise: 9.8 and 9.9 ms against 11.3 ms for
  the native run, which happened to be the slowest of the three. The README takes their mean, 10.3 ms, as the
  baseline for the slowdown column.
- The page watch takes 16 µs per trap and, more importantly, about 340 traps for each access that was asked for
  (1 267 312 / 3 768 ≈ 336).
- `hwwatch` delivered 11 of its 5 000 hits in the run shown; the per-trap table reports the median over five runs
  (25 µs). This is why it is not used as a baseline.

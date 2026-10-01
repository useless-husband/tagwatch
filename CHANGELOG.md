# Changelog

## 0.1.0 — 2026-10-01

First version.

- `libtagwatch.dylib`: data watchpoints on MTE tag-check faults. Watches are armed by retagging 16-byte granules; each
  trapped instruction is re-executed out of line with `PSTATE.TCO` set, so the granule keeps its watch tag and no
  concurrent access is missed.
- `tagwatch run`: launches an unmodified program with MTE enabled and watches heap objects by size or allocating
  function (optionally one field of each), globals by symbol, or an address range.
- Output: live log, JSON-lines trace, and a summary with per-site backtraces and heat maps (`tagwatch report`).
- `tagwatch check`: reports whether the machine can run it, including an end-to-end self test.
- Handled: multi-threaded programs, signals and handlers, fork (watches are dropped in the child), exec, free and
  realloc of watched objects (with a use-after-free quarantine), `read`/`write`-family system calls on watched buffers,
  globals and other threads' stacks (page adoption), LDXR/STXR sequences (emulated), code far from any free address
  space (two-exception return path).
- Known limits are listed in the README.

Fixed during the pre-release review, each with a regression test:

- A deadlock: arming untaggable or unmapped memory (or adopting pages) while other threads trapped could hang the
  process for good. The exception thread no longer waits for the watch lock (`t_threads`).
- Event `watch` ids, `realloc` of in-place watches, consistency of tags in `fork` children, and a `fork` that took half a
  second because the arena reserved 64 GB of MTE address space up front (`t_basic`, `t_alloc`, `t_fork`).
- `tagwatch run` refuses programs with no arm64 code instead of letting dyld abort them, and runs the arm64 slice of
  an arm64 + arm64e universal binary; the log descriptor is no longer inherited by exec'ed programs (`cli.sh`).
- `tests/run_mte.sh` kills a hung test (and its traced child) after a time limit instead of hanging `make test`.

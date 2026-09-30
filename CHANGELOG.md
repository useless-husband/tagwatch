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

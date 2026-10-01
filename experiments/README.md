# Experiments

Small, self-contained programs that settled the design questions in [docs/DESIGN.md](../docs/DESIGN.md). They are
not part of the build. Each needs an MTE machine; the first two must be signed with the MTE entitlements:

```sh
cc -O1 -march=armv8.5-a+memtag -o let_access_proceed let_access_proceed.c
codesign -s - --entitlements ../entitlements/mte.entitlements -f let_access_proceed
for mode in retag-step tco-state tramp; do ./let_access_proceed $mode 2000; done

cc -O1 -march=armv8.5-a+memtag -o vm_behaviour vm_behaviour.c
codesign -s - --entitlements ../entitlements/mte.entitlements -f vm_behaviour
./vm_behaviour

cc -O2 -march=armv8.5-a+memtag -o external_handler external_handler.c    # no entitlements needed
./external_handler
```

Results on an Apple M5, macOS 27.0 (26A428), 30 September 2026 unless dated otherwise:

| Program | Question | Observation |
| --- | --- | --- |
| `let_access_proceed retag-step` | Does the obvious loop work? | Yes: 2000/2000 accesses, about 19 µs per trap (two exceptions each). |
| `let_access_proceed tco-state` | Can `PSTATE.TCO` be set through `thread_set_state`? | No. The kernel drops the bit; the instruction faults again forever (the run ends by timeout). |
| `let_access_proceed tramp` | Does out-of-line execution under `MSR TCO` work? | Yes: about 7.6 µs per trap, one exception each, tags never change. |
| `vm_behaviour` reserve | Can a large MTE mapping be reserved up front? | Yes, 64 GB with `VM_FLAGS_MTE`, populated lazily. (But see fork-cost.) |
| `vm_behaviour` ldg-plain | What does `LDG` return outside MTE mappings? | Tag 0, no fault. (`STG` there raises a catchable bus error.) |
| `vm_behaviour` global-adopt | Can a `__DATA` page be replaced by an MTE page in place? | Yes, with `VM_FLAGS_FIXED \| VM_FLAGS_OVERWRITE \| VM_FLAGS_MTE`; tags then work at the original address. |
| `vm_behaviour` remap | Does `mach_vm_remap` of an MTE region share tags? | Yes: both mappings see the same tags. |
| `vm_behaviour` tco-signal | Is `PSTATE.TCO` inherited by a signal handler? | Yes, and it is still set after `sigreturn`. Hence the handler wrapper in `src/interpose.c`. |
| `vm_behaviour` syscall-read/-write | What happens when the kernel touches a mismatched granule? | The process is killed (SIGKILL); nothing can be recovered. Hence the system-call shims. |
| `vm_behaviour` malloc-tags | Which `malloc` sizes are tagged (MTE on)? | Up to 32 768 bytes; 32 769 bytes and more come back untagged (1 October 2026; the same for an unsigned build run as `tagwatch run --no-runtime -- ./vm_behaviour`). |
| `vm_behaviour` fork-cost | Does an untouched MTE mapping make `fork()` slower? | Yes: the tag storage is copied. Mean of 5 forks with an untouched MTE mapping of 0 / 1 / 4 / 16 / 64 GB: 0.86 / 10.56 / 32.80 / 122.15 / 497.30 ms (1 October 2026), about 8 ms per GB. Hence the arena maps 256 MB regions on demand instead of reserving 64 GB. |
| `external_handler` | Can another process handle the faults? | Only if the child is ptrace-traced: then 5000/5000 faults are handled in the parent at about 7.9 µs each. Untraced, the first fault is delivered and the child is killed anyway. |

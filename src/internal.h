// Internal interfaces of the tagwatch runtime (everything in libtagwatch that
// is not the public API in include/tagwatch.h).
#ifndef TW_INTERNAL_H
#define TW_INTERNAL_H

#include <mach/mach.h>
#include <os/lock.h>
#include <stddef.h>
#include <stdint.h>

#include "../include/tagwatch.h"
#include "fmt.h"
#include "spec.h"
#include "wtab.h"

#define TW_ADDR_MASK 0x00ffffffffffffffull // strips the top byte (tag)
#define TW_VA_MASK 0x00007fffffffffffull   // strips tag and pointer-authentication bits
#define TW_LABEL_MAX 48
#define TW_ALLOC_BT 8

// ---- mte.c: the only file that contains MTE instructions ------------------
int tw_mte_process_enabled(void);
unsigned tw_mte_get_tag(uint64_t addr);
void tw_mte_set_tag(uint64_t addr, unsigned tag);
// Like tw_mte_set_tag, but returns -1 instead of crashing when the page is
// not an MTE mapping. Needs the exception thread (exc.c) to be running.
int tw_mte_try_set_tag(uint64_t addr, unsigned tag);
// If pc is one of the guarded instructions above, returns where to resume.
uint64_t tw_mte_recover_pc(uint64_t pc);
// PSTATE.TCO: when set, the calling thread's accesses are not tag-checked.
uint64_t tw_tco_save_and_set(void);
void tw_tco_restore(uint64_t saved);
void tw_tco_force(int on);
int tw_tco_is_set(void);

// ---- vm.c: memory that never goes through malloc ---------------------------
void *tw_vm_alloc(size_t size); // zero-filled, page-granular
void tw_vm_free(void *p, size_t size);
void *tw_vm_alloc_mte(size_t size);
extern const tw_mem tw_vm_mem;

// ---- watch.c: watch records, arming and disarming ---------------------------
enum {
    TW_ORIGIN_API = 0,
    TW_ORIGIN_ALLOC,  // matched by an alloc: spec
    TW_ORIGIN_SYMBOL,
    TW_ORIGIN_ADDR,
};
enum {
    TW_WF_ACTIVE = 1 << 0,
    TW_WF_FREED = 1 << 1, // object was freed and sits in quarantine, still armed
};

typedef struct {
    uint64_t base, len;         // what was asked for
    uint64_t gbase, glen;       // granule-aligned range that is armed
    uint64_t serial;            // id printed in the trace; never reused
    uint64_t reads, writes;
    uint32_t flags;
    uint8_t mode, origin;
    char label[TW_LABEL_MAX];
} tw_watch;

int tw_watch_module_init(void);
// Arms [addr, addr+len). Returns a public id (> 0) or a negated error.
tagwatch_id tw_watch_add(uint64_t addr, uint64_t len, const char *label, unsigned mode, unsigned origin,
                         const uint64_t *bt, unsigned nbt);
int tw_watch_remove_id(tagwatch_id id, const char *reason);
int tw_watch_remove_addr(uint64_t addr, const char *reason);
// Marks the watch covering addr as freed (it stays armed). Returns 1 if found.
int tw_watch_mark_freed(uint64_t addr);
// Finds the watch hit by an access to [ea, ea+size) or, failing that, by the
// fault address. Copies the record and bumps its counters. On a miss,
// *tag_now (if not NULL) receives the current tag of the faulting granule.
int tw_watch_hit(uint64_t ea, uint64_t size, uint64_t far, unsigned access, tw_watch *out, uint64_t *slack,
                 unsigned *tag_now);
// 1 if any granule of [addr, addr+len) is armed (cheap when nothing is).
int tw_watch_overlaps(uint64_t addr, uint64_t len);
// Restores the original tag of every armed granule (fork child).
void tw_watch_disarm_all(void);
void tw_watch_counts(uint64_t *live, uint64_t *total, uint64_t *granules);
extern _Atomic uint64_t tw_armed_granules;
extern _Atomic uint64_t tw_watch_generation; // bumped whenever a watch is armed or disarmed

// ---- tramp.c: out-of-line execution slots ------------------------------------
int tw_tramp_init(void);
// Entry point of the slot that re-executes `insn` (the word at pc) with tag
// checks suppressed and then returns to pc + 4. *far is set when the slot
// returns through a breakpoint because no slot could be placed within
// branch range of pc. Returns 0 if no slot could be made.
uint64_t tw_tramp_get(uint64_t pc, uint32_t insn, int *far);
// If addr is inside a slot, returns 1 and the slot's entry, the original pc
// and the word index (0..3) within the slot.
int tw_tramp_owner(uint64_t addr, uint64_t *entry, uint64_t *orig_pc, unsigned *word);
uint64_t tw_tramp_count(void);

// ---- bt.c ----------------------------------------------------------------------
// Walks the frame-pointer chain of a stopped thread. Reads stay inside
// [stack_lo, stack_hi). Returns the number of frames (frames[0] = pc).
unsigned tw_backtrace(uint64_t pc, uint64_t lr, uint64_t fp, uint64_t stack_lo, uint64_t stack_hi, uint64_t *frames,
                      unsigned max);
// Backtrace of the calling thread starting at a frame record of its own
// (pass __builtin_frame_address(0)): frames[0] is the return address of the
// function that owns that frame, i.e. its caller.
unsigned tw_backtrace_fp(const void *frame, uint64_t *frames, unsigned max);

// ---- trace.c: log and JSON-lines output ---------------------------------------
void tw_out_init(void);
int tw_out_set(int log_fd, const char *trace_path);
void tw_out_after_fork(void);
void tw_emit_start(const char *engine);
void tw_emit_watch(const tw_watch *w, const uint64_t *bt, unsigned nbt);
void tw_emit_unwatch(uint64_t serial, const char *reason, uint64_t reads, uint64_t writes);
void tw_emit_freed(uint64_t serial);
void tw_emit_access(const tagwatch_event *ev);
void tw_emit_violation(uint64_t addr, uint64_t pc, uint64_t tid, unsigned access, unsigned size, const uint64_t *frames,
                       unsigned nframes);
void tw_emit_note(const char *kind, const char *msg);
void tw_emit_stats(void);
void tw_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
uint64_t tw_now_ns(void);

// ---- exc.c: the exception thread ------------------------------------------------
int tw_exc_start(void);
void tw_exc_after_fork_child(void);
thread_t tw_exc_thread_port(void);

// ---- arena.c: MTE-backed allocations of any size --------------------------------
int tw_arena_init(void);
void *tw_arena_alloc(size_t size, size_t align);
void tw_arena_free(void *p);
size_t tw_arena_size(const void *p); // 0 if p is not an arena block
int tw_arena_owns(const void *p);
void tw_arena_set_quarantine(uint64_t bytes);

// ---- interpose.c / runtime.c -----------------------------------------------------
typedef struct {
    int state; // TW_STATE_*
    int supervised;
    int verbose;
    unsigned bt_depth;
    uint64_t max_events;
    tw_spec specs[16];
    int nspecs;
    _Atomic uint64_t spec_seen[16], spec_taken[16];
    int have_alloc_specs;
    tagwatch_callback cb;
    void *cb_ctx;
    // counters
    _Atomic uint64_t n_events, n_traps, n_filtered, n_far, n_emulated, n_syscalls, n_violations;
} tw_runtime;

enum { TW_STATE_NEW = 0, TW_STATE_ON, TW_STATE_UNAVAILABLE, TW_STATE_FORKED };

extern tw_runtime tw_rt;

static inline int tw_on(void) { return tw_rt.state == TW_STATE_ON; }

// Called by the allocation interposers: should an allocation of `size` bytes
// made from the current call stack be watched? Returns the spec index or -1.
int tw_alloc_match(size_t size, const void *frame);
void *tw_alloc_watched(size_t size, size_t align, int spec_idx, const void *frame);
// Reports a system call that is about to read (kernel reads user memory) or
// write a watched buffer.
void tw_report_syscall(const char *name, uint64_t addr, uint64_t len, unsigned access, const void *frame);

// adopt.c
int tw_adopt(uint64_t addr, uint64_t len);

#endif

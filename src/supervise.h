// supervise: the debugger-parent half of fault recovery.
//
// On macOS a hard-mode MTE tag-check fault is fatal unless the process is
// being traced. The target therefore calls ptrace(PT_TRACE_ME), which makes
// its parent the tracer. A traced process stops on every signal and waits for
// its tracer; this loop is that tracer. It does nothing but pass signals
// through and report how the child ended.
#ifndef TW_SUPERVISE_H
#define TW_SUPERVISE_H

#include <sys/types.h>

// Runs until `child` terminates. Returns its exit status in shell convention
// (exit code, or 128 + signal number); *termsig is set to the fatal signal,
// or 0 for a normal exit.
int tw_supervise(pid_t child, int *termsig);

#endif

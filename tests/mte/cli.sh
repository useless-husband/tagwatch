#!/bin/sh
# End-to-end tests of `tagwatch run` on unmodified, unentitled programs.
B=$1
T="$B/tagwatch"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/tagwatch-cli.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
fail=0
checks=0

ok() { # ok "description" command...
    desc=$1
    shift
    checks=$((checks + 1))
    if ! "$@"; then
        echo "FAIL cli: $desc"
        fail=$((fail + 1))
    fi
}
count() { grep -c -- "$1" "$2" 2>/dev/null || true; }
eq() { [ "$1" = "$2" ] || { echo "     got '$1', expected '$2'"; return 1; }; }
has() { grep -q -- "$1" "$2"; }
hasnt() { ! grep -q -- "$1" "$2"; }

# --- by allocation site and by symbol ----------------------------------------
"$T" run -q -t "$TMP/a.jsonl" -a caller=make_node -s g_counter -- "$B/mte/target_list" >"$TMP/a.out" 2>"$TMP/a.err"
ok "exit status 0" eq $? 0
ok "program output intact" has "sum=6 counter=3 big=25 table=7" "$TMP/a.out"
ok "five watches (4 nodes + global)" eq "$(count '"ev":"watch"' "$TMP/a.jsonl")" 5
ok "four node frees recorded" eq "$(count '"ev":"free"' "$TMP/a.jsonl")" 4
ok "g_counter: 3 increments = 3 reads + 3 writes in bump, 1 read in main" eq "$(grep '"watch":1,' "$TMP/a.jsonl" | grep -c '"sym":"bump"')" 6
ok "accesses from the second thread are attributed to worker" has '"sym":"worker"' "$TMP/a.jsonl"
ok "allocation site recorded" has '"origin":"alloc","label":"make_node","bt":\[{"pc":"0x[0-9a-f]*","sym":"make_node"' "$TMP/a.jsonl"
ok "summary printed" has "== tagwatch summary ==" "$TMP/a.err"
ok "summary groups the nodes" has '4 objects, 40 bytes each "make_node", allocated by make_node' "$TMP/a.err"
ok "no violations" eq "$(count '"ev":"violation"' "$TMP/a.jsonl")" 0

# --- by size, including a block far larger than the system allocator tags ----
"$T" run -q --no-summary -t "$TMP/b.jsonl" -a size=100000 -- "$B/mte/target_list" >"$TMP/b.out" 2>"$TMP/b.err"
ok "large allocation: exit 0" eq $? 0
ok "large allocation: one watch" eq "$(count '"ev":"watch"' "$TMP/b.jsonl")" 1
ok "large allocation: memset and the read loop were traced" [ "$(count '"ev":"access"' "$TMP/b.jsonl")" -gt 25 ]
ok "large allocation: program result unchanged" has "big=25" "$TMP/b.out"
ok "--no-summary prints none" hasnt "tagwatch summary" "$TMP/b.err"

# --- writes only, sampling, limits ---------------------------------------------
"$T" run -q -w --no-summary -t "$TMP/c.jsonl" -a size=40,skip=1,limit=2 -- "$B/mte/target_list" >/dev/null 2>&1
ok "skip/limit: two of the four nodes" eq "$(count '"ev":"watch"' "$TMP/c.jsonl")" 2
ok "--writes-only: no reads reported" eq "$(count '"kind":"read"' "$TMP/c.jsonl")" 0
ok "--writes-only: writes reported" [ "$(count '"kind":"write"' "$TMP/c.jsonl")" -gt 0 ]
"$T" run -q --no-summary --max-events 5 -t "$TMP/d.jsonl" -a size=40 -- "$B/mte/target_list" >/dev/null 2>&1
ok "--max-events caps the log" eq "$(count '"ev":"access"' "$TMP/d.jsonl")" 5

# --- a static symbol with offset and length, and an absolute address ---------------
"$T" run -q --no-summary -t "$TMP/e.jsonl" -s name=g_static_table,off=16,len=8 -- "$B/mte/target_list" >/dev/null 2>&1
ok "static symbol + offset: the write and the read of element 2" eq "$(count '"ev":"access"' "$TMP/e.jsonl")" 2
addr=$("$T" run -q --no-summary --no-aslr -- "$B/mte/target_list" addr 2>/dev/null | sed -n 's/^g_counter@//p')
"$T" run -q --no-summary --no-aslr -t "$TMP/f.jsonl" -x "$addr:8" -- "$B/mte/target_list" >/dev/null 2>&1
ok "--watch-addr with --no-aslr hits the same global" eq "$(count '"ev":"access"' "$TMP/f.jsonl")" 7
"$T" run -q -s no_such_symbol -- "$B/mte/target_list" >/dev/null 2>"$TMP/g.err"
ok "unknown symbol is reported, program still runs" has "cannot watch symbol 'no_such_symbol'" "$TMP/g.err"

# --- live log and report subcommand -----------------------------------------------------
"$T" run --no-summary -l "$TMP/h.log" -t "$TMP/h.jsonl" -s g_counter -- "$B/mte/target_list" >/dev/null 2>"$TMP/h.err"
ok "live log goes to the file" has 'WRITE 8 bytes at 0x[0-9a-f]*  watch #1 "g_counter" +0' "$TMP/h.log"
ok "live log has symbolised frames" has "    bump+0x[0-9a-f]* (target_list)" "$TMP/h.log"
"$T" report --heatmap "$TMP/h.jsonl" >"$TMP/h.rep"
ok "report: totals" has "accesses   7 reported: 4 read, 3 write" "$TMP/h.rep"
ok "report: heat map" has "Heat map of watch #1 \"g_counter\"" "$TMP/h.rep"

# --- C++ ------------------------------------------------------------------------------------
"$T" run -q -t "$TMP/i.jsonl" -a size=48 -- "$B/mte/target_cxx" >"$TMP/i.out" 2>"$TMP/i.err"
ok "C++: exit 0 and output" has "total=150" "$TMP/i.out"
ok "C++: three objects from operator new" eq "$(count '"ev":"watch"' "$TMP/i.jsonl")" 3
ok "C++: names demangled in the summary" has "Account::deposit(long)+0x" "$TMP/i.err"

# --- exit status, fatal signals ------------------------------------------------------------------
"$T" run -q --no-summary -a size=4000 -- "$B/mte/target_misc" exit3 >/dev/null 2>&1
ok "exit status is passed through" eq $? 3
"$T" run -q --no-summary -a size=4000 -- "$B/mte/target_misc" abort >/dev/null 2>"$TMP/j.err"
ok "abort(): status 134" eq $? 134
ok "abort(): termination reported" has "terminated by signal 6" "$TMP/j.err"

# --- exec: the new image runs untraced, and the runtime does not follow it -------------------------
"$T" run -q --no-summary -t "$TMP/k.jsonl" -a size=4000 -- "$B/mte/target_misc" exec >"$TMP/k.out" 2>&1
ok "exec: status 0" eq $? 0
ok "exec: new image ran without the inserted library" has "hello from the exec'ed image (DYLD_INSERT_LIBRARIES=unset)" "$TMP/k.out"
ok "exec: only the first image was traced" eq "$(count '"ev":"start"' "$TMP/k.jsonl")" 1
"$T" run --no-summary -l "$TMP/k2.log" -a size=4000 -- "$B/mte/target_misc" exec >"$TMP/k2.out" 2>&1
ok "exec: the new image inherits neither the trace nor the log descriptor" has "descriptors inherited beyond stdio: 0" "$TMP/k2.out"

# --- fork and child processes -------------------------------------------------------------------------
"$T" run -q --no-summary -t "$TMP/l.jsonl" -a size=4000 -- "$B/mte/target_misc" fork >"$TMP/l.out" 2>&1
ok "fork: child survives and parent reaps it" has "child exited with status 7" "$TMP/l.out"
ok "fork: note in the trace" has '"kind":"fork"' "$TMP/l.jsonl"
ok "fork: parent keeps tracing afterwards" has '"off":2,' "$TMP/l.jsonl"
"$T" run -q --no-summary -a size=4000 -- "$B/mte/target_misc" system >"$TMP/m.out" 2>&1
ok "system(): a shell started by the target works" has "system() returned 0" "$TMP/m.out"

# --- signals sent to tagwatch are forwarded --------------------------------------------------------------
"$T" run -q --no-summary -t "$TMP/n.jsonl" -a size=4000 -- "$B/mte/target_misc" sigwait >"$TMP/n.out" 2>&1 &
tpid=$!
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    grep -q ready "$TMP/n.out" 2>/dev/null && break
    sleep 0.25
done
kill -TERM $tpid
wait $tpid
ok "forwarded SIGTERM reaches the handler; exit 0" eq $? 0
ok "handler ran" has "got signal 15" "$TMP/n.out"
ok "access after the handler traced" has '"off":3,' "$TMP/n.jsonl"

# --- the documented fatal cases ---------------------------------------------------------------------------
"$T" run -q --no-summary -t "$TMP/o.jsonl" -a size=4000 -- "$B/mte/target_misc" readv >"$TMP/o.out" 2>"$TMP/o.err"
ok "unshimmed system call on a watched buffer: killed (status 137)" eq $? 137
ok "unshimmed system call: died inside readv" hasnt "readv returned" "$TMP/o.out"
"$T" run -q -t "$TMP/p.jsonl" -a size=4000 -- "$B/mte/target_misc" uaf >"$TMP/p.out" 2>"$TMP/p.err"
ok "genuine MTE violation: killed by a signal" [ $? -gt 128 ]
ok "genuine MTE violation: recorded with a backtrace" has '"ev":"violation".*"sym":"main"' "$TMP/p.jsonl"
ok "genuine MTE violation: shown in the summary" has "Violation 1: read at 0x" "$TMP/p.err"

# --- programs that cannot be traced ---------------------------------------------------------------------------
"$T" run -q -a size=48 -- /bin/ls / >"$TMP/q.out" 2>"$TMP/q.err"
ok "SIP-protected binary: still runs" eq $? 0
ok "SIP-protected binary: tagwatch says nothing was watched" has "the runtime never started" "$TMP/q.err"
# Built here rather than committed: one 48-byte object, one write and one read.
printf '%s\n' '#include <stdio.h>' '#include <stdlib.h>' \
    'int main(void) { volatile char *p = malloc(48); p[3] = 1; printf("value %d\n", p[3]); free((void *)p); return 0; }' \
    >"$TMP/one.c"
${CC:-cc} -arch arm64 -o "$TMP/hardened" "$TMP/one.c" && codesign -s - -o runtime -f "$TMP/hardened" 2>/dev/null
"$T" run -q -a size=48 -- "$TMP/hardened" >"$TMP/hr.out" 2>"$TMP/hr.err"
ok "hardened-runtime binary: still runs" eq "$?:$(cat "$TMP/hr.out")" "0:value 1"
ok "hardened-runtime binary: tagwatch says nothing was watched" has "the runtime never started" "$TMP/hr.err"
${CC:-cc} -arch arm64e -o "$TMP/only_e" "$TMP/one.c"
"$T" run -q -a size=48 -- "$TMP/only_e" >/dev/null 2>"$TMP/e.err"
ok "arm64e-only binary: refused up front (exit 2)" eq $? 2
ok "arm64e-only binary: the reason is given" has "contains no arm64 code (only arm64e)" "$TMP/e.err"
${CC:-cc} -arch arm64 -arch arm64e -o "$TMP/fat" "$TMP/one.c"
"$T" run -q --no-summary -t "$TMP/fat.jsonl" -a size=48 -- "$TMP/fat" >/dev/null 2>&1
ok "arm64 + arm64e binary: the arm64 slice runs, traced" eq "$?:$(count '"ev":"access"' "$TMP/fat.jsonl")" "0:2"

# --- usage errors -------------------------------------------------------------------------------------------------
"$T" run -a bogus=1 -- "$B/mte/target_list" >/dev/null 2>"$TMP/r.err"
ok "bad spec: exit 2" eq $? 2
ok "bad spec: message" has "bad watch 'alloc:bogus=1'" "$TMP/r.err"
"$T" run -a size=1 -- /nonexistent/program >/dev/null 2>"$TMP/s.err"
ok "missing program: exit 2" eq $? 2
"$T" run >/dev/null 2>&1
ok "no program: exit 2" eq $? 2

if [ $fail = 0 ]; then
    printf 'ok   %-10s %d checks\n' cli $checks
else
    echo "cli: $fail of $checks checks FAILED (artifacts were in $TMP)"
fi
exit $fail

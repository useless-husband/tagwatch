#!/bin/sh
# Runs every measurement quoted in the README and prints the raw lines.
# Each figure is the median of $RUNS runs. Needs an MTE machine.
B=${1:-build}
RUNS=${RUNS:-5}
T="$B/tagwatch"
"$T" check --quiet || { echo "bench: skipped, MTE is not usable here"; "$T" check; exit 0; }

median() { sort -n | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}'; }
field() { sed -n "s/.* $1=\([^ ]*\).*/\1/p"; }
rep() { # rep FIELD command... -> median of FIELD over $RUNS runs
    f=$1
    shift
    i=0
    while [ $i -lt "$RUNS" ]; do
        "$@" 2>/dev/null | field "$f"
        i=$((i + 1))
    done | median
}

echo "## machine"
sysctl -n machdep.cpu.brand_string
sw_vers | tr '\n' ' '; echo
echo "load average: $(sysctl -n vm.loadavg)"
echo "runs per figure: $RUNS (median reported)"

echo
echo "## per-trap cost (microseconds per trapped access)"
printf '%-58s %s\n' "tagwatch, near slot, callback only"            "$(rep us_per_trap "$B/bench/trapcost" count 20000)"
printf '%-58s %s\n' "tagwatch, near slot, JSON trace + 16-frame backtrace"  "$(rep us_per_trap "$B/bench/trapcost" trace 20000)"
printf '%-58s %s\n' "tagwatch, near slot, JSON trace + live log"    "$(rep us_per_trap "$B/bench/trapcost" log 20000)"
printf '%-58s %s\n' "tagwatch, far slot (2 exceptions), callback only" "$(TAGWATCH_FORCE_FAR=1 rep us_per_trap "$B/bench/trapcost" count 20000)"
printf '%-58s %s\n' "naive retag + single-step (rejected design)"   "$(rep us_per_trap "$B/bench/naive_step" 20000)"
printf '%-58s %s\n' "mprotect page watch (fault + single-step + 2 mprotect)" "$(rep us_per_trap "$B/bench/pagewatch" 100000 100000 1000)"
printf '%-58s %s\n' "hardware watchpoint registers, driven in-process"  "$(rep us_per_hit "$B/bench/hwwatch" 5000)"
printf '%-58s %s ns\n' "unwatched access, for scale"                "$(rep unwatched_ns_per_access "$B/bench/trapcost" count 20000)"

N=100000
M=1000000
echo
echo "## overhead on the kv workload ($N nodes of 48 bytes, $M operations); ops phase in ms"
printf '%-46s %10s %10s\n' "configuration" "ops_ms" "traps"
printf '%-46s %10s %10s\n' "native (no MTE)" "$(rep ops_ms "$B/bench/kv" $N $M)" "-"
printf '%-46s %10s %10s\n' "MTE on, runtime not loaded" "$(rep ops_ms "$T" run --no-runtime -- "$B/bench/kv" $N $M)" "-"
printf '%-46s %10s %10s\n' "runtime loaded, nothing matched" "$(rep ops_ms "$T" run -q --no-summary -a size=999999 -- "$B/bench/kv" $N $M)" "0"
for every in 100000 10000 1000 100 10 1; do
    trace=$(mktemp "${TMPDIR:-/tmp}/tagwatch-bench.XXXXXX")
    ms=$("$T" run -q --no-summary -t "$trace" -a size=48,every=$every -- "$B/bench/kv" $N $M 2>/dev/null | field ops_ms)
    traps=$(sed -n 's/.*"ev":"stats".*"traps":\([0-9]*\).*/\1/p' "$trace")
    rm -f "$trace"
    printf '%-46s %10s %10s\n' "1 node in $every watched ($((N / every)) objects)" "$ms" "$traps"
done

echo
echo "## the same task with page protection: watch 1 node in K of the kv workload"
printf '%-10s %-10s %10s %12s %12s %10s %10s\n' "K" "tool" "ops_ms" "traps" "true hits" "false %" "pages"
for every in 100000 1000; do
    trace=$(mktemp "${TMPDIR:-/tmp}/tagwatch-bench.XXXXXX")
    ms=$("$T" run -q --no-summary -t "$trace" -a size=48,every=$every -- "$B/bench/kv" $N $M 2>/dev/null | field ops_ms)
    traps=$(sed -n 's/.*"ev":"stats".*"traps":\([0-9]*\).*/\1/p' "$trace")
    # Count the ops phase only (accesses made from kv_run), as pagewatch does:
    # it can only protect the pages once the table has been built.
    events=$(grep '"ev":"access"' "$trace" | grep -c '"sym":"kv_run"')
    build=$(grep '"ev":"access"' "$trace" | grep -vc '"sym":"kv_run"')
    rm -f "$trace"
    printf '%-10s %-10s %10s %12s %12s %10s %10s\n' "$every" "tagwatch" "$ms" "$traps" "$events" "0.00" "-"
    echo "           (tagwatch also reported $build accesses while the table was being built)"
    line=$("$B/bench/pagewatch" $N $M $every)
    printf '%-10s %-10s %10s %12s %12s %10s %10s\n' "$every" "mprotect" "$(echo "$line" | field ops_ms)" "$(echo "$line" | field traps)" \
        "$(echo "$line" | field hits)" "$(echo "$line" | field false_pct)" "$(echo "$line" | field pages)"
done

echo
echo "## hardware watchpoints"
echo "debug registers available for watchpoints (hw.optional.watchpoint): $(sysctl -n hw.optional.watchpoint)"
"$B/bench/hwwatch" 5000 | tail -1

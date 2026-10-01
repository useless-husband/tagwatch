#!/bin/sh
# Runs the MTE-dependent tests. On hardware without MTE (every GitHub-hosted
# runner as of 2026: they are M1/M2) the whole group is skipped with a reason
# rather than failed.
B=$1
shift
if ! "$B/tagwatch" check --quiet; then
    echo "SKIP MTE tests: this machine cannot run them. Reason:"
    "$B/tagwatch" check | sed 's/^/     /'
    exit 0
fi

# limit SECONDS command...: runs the command in a process group of its own and
# SIGKILLs the whole group if it is still running after SECONDS. A traced
# process that hangs ignores every other signal, and killing its tracer is
# what makes the kernel kill it. (perl ships with macOS; timeout(1) does not.)
limit() {
    perl -e '
        my $secs = shift;
        my $pid = fork;
        die "fork: $!" unless defined $pid;
        if ($pid == 0) { setpgrp(0, 0); exec @ARGV or exit 127; }
        my $timed_out = 0;
        local $SIG{ALRM} = sub { $timed_out = 1; kill "KILL", -$pid; kill "KILL", $pid; };
        alarm $secs;
        my $r;
        do { $r = waitpid($pid, 0) } while ($r == -1 && $!{EINTR});
        my $st = $?;
        alarm 0;
        if ($timed_out) { print STDERR "TIMEOUT after ${secs}s: @ARGV\n"; exit 124; }
        exit(($st & 127) ? 128 + ($st & 127) : $st >> 8);
    ' "$@"
}

fail=0
for t in "$@"; do
    limit 180 "$B/mte/$t" || { echo "FAILED: $t"; fail=1; }
done
if [ -f tests/mte/cli.sh ]; then
    limit 300 sh tests/mte/cli.sh "$B" || fail=1
fi
[ $fail = 0 ] && echo "MTE tests passed" || echo "MTE tests FAILED"
exit $fail

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
fail=0
for t in "$@"; do
    "$B/mte/$t" || { echo "FAILED: $t"; fail=1; }
done
if [ -f tests/mte/cli.sh ]; then
    sh tests/mte/cli.sh "$B" || fail=1
fi
[ $fail = 0 ] && echo "MTE tests passed" || echo "MTE tests FAILED"
exit $fail

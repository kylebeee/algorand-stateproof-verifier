#!/bin/bash
# Runs the differential tests (after ./setup.sh). Extra args go to `go test`, e.g.
#   ./run.sh -run TestSynthetic            DIFFTEST_SYNTH=500 ./run.sh
#   ./run.sh -run '^$' -fuzz FuzzStateProofBytes -fuzztime 30m
set -euo pipefail
cd "$(dirname "$0")"
# Build the Rust library for the same macOS version Go links for (avoids ld warnings).
[ "$(uname -s)" = Darwin ] && export MACOSX_DEPLOYMENT_TARGET="$(sw_vers -productVersion | cut -d. -f1).0"
(cd rustffi && cargo build --release -q)
exec go test -overlay overlay.json -count=1 -timeout 0 "$@" .

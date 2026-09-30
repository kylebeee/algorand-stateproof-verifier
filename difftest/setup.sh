#!/bin/bash
# Prepares the differential tests: the go-algorand reference (v5.0.2-stable, what MainNet runs)
# with its libsodium, the Rust FFI library, and the Go modules. (run.sh writes the overlay file.)
set -euo pipefail
cd "$(dirname "$0")"
# Build the Rust library for the same macOS version Go links for (avoids ld warnings).
[ "$(uname -s)" = Darwin ] && export MACOSX_DEPLOYMENT_TARGET="$(sw_vers -productVersion | cut -d. -f1).0"
REF=v5.0.2-stable
if [ ! -d .deps/go-algorand ]; then
  git clone -q --depth 1 --branch "$REF" https://github.com/algorand/go-algorand .deps/go-algorand
fi
(cd .deps/go-algorand && [ -f "crypto/libs/$(uname -s | tr A-Z a-z)/$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')/lib/libsodium.a" ] || make libsodium >/dev/null)
(cd rustffi && cargo build --release -q)
go mod tidy

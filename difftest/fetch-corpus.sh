#!/bin/bash
# Samples real state proofs and blocks for the differential tests into corpus/ (~100 MB).
# Needs an archival algod; the default is Nodely, with ALGOD_TOKEN from the environment.
set -euo pipefail
cd "$(dirname "$0")"
go run -overlay overlay.json ./cmd/fetchcorpus -network mainnet -samples "${SAMPLES:-150}" -blocks "${BLOCKS:-150}"
go run -overlay overlay.json ./cmd/fetchcorpus -network testnet -samples "${TESTNET_SAMPLES:-40}" -blocks "${TESTNET_BLOCKS:-40}"

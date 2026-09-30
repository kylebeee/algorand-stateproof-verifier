# Differential tests against go-algorand

These tests check that the Rust verifier gives exactly the same verdict as go-algorand, the
implementation Algorand's nodes run. Every input goes through both verifiers in one process
(go-algorand in Go, the Rust crates through a small C ABI in `rustffi/`), and any difference in
verdict fails the run and is saved under `findings/`.

**Reference:** go-algorand `v5.0.2-stable` (commit `fe1308bd`), the version Nodely's MainNet
nodes report. `setup.sh` clones it into `.deps/` and builds its libsodium. Through `go test
-overlay` files (`overlay/`, wired up by `run.sh`) the tests reach two unexported functions
(`verifyWeights` and the coin generator) and build Merkle signature keys from fixed seeds, so
synthetic proofs are identical in every process; the clone itself is not modified.

```bash
./setup.sh                 # reference clone, Rust library, Go modules
./fetch-corpus.sh          # optional: ~190 real state proofs and ~190 blocks (needs ALGOD_TOKEN)
./run.sh -v                # every comparison; prints a summary table
./run.sh -run '^$' -fuzz FuzzStateProofBytes -fuzztime 1h   # coverage-guided fuzzing
```

Knobs (environment): `DIFFTEST_SYNTH` (synthetic proofs, default 60), `DIFFTEST_DRAWS`
(draws per mutation, default 3), `DIFFTEST_MAX_REAL_MUTATED` (default 40),
`DIFFTEST_STRICT=1` (also fail on non-canonical-encoding differences).

## What is compared

| Test | Inputs | Compared |
|---|---|---|
| `TestRealProofsVerify` | the repo fixture and the fetched corpus: MainNet from its first state proof, and TestNet, sampled across history | state proof verdict, message hash (from fields and from msgpack) |
| `TestRealProofsMutated` | every structured mutation of those proofs (≈90 kinds: weights, positions, reveals, Falcon signatures and keys, MSS paths and depths, both vector commitment proofs, salt, hash types, the 640-reveal limit, and the verifier's inputs: voters, ln(proven weight), round, message hash, strength target) | state proof verdict |
| `TestSyntheticProofs` | proofs built by go-algorand's own prover over shapes the chain never produced (1 to 4,000 participants; equal, skewed, huge and unit weights; proven weight from 1% to 99%; strength targets 16 to 512; key lifetimes 1 to 256), and all their mutations | state proof verdict |
| `TestRealBlocks` | the fetched blocks | light header leaf (both eras: seed and block hash), state proof transaction extraction from raw blocks |
| `TestSha256VectorCommitment` | SHA-256 vector commitments of 1 to 600 leaves; honest and damaged single-leaf proofs | root recomputation (the light node's transaction and header paths) |
| `TestWeights`, `TestCoins`, `TestSumhash512`, `TestFalcon`, `TestMessageHash`, `TestLightHeaderAndTxnLeaf`, `TestLnIntApproximation` | edge grids and random inputs | each component on its own |
| `Fuzz*` | coverage-guided: raw proof bytes, chains of structured mutations, messages, Falcon signatures, weights | as above |

## How differences are classified

- **SOUNDNESS**: Rust accepts what go-algorand rejects. A light client could be fooled.
- **LIVENESS**: Rust rejects a canonical input go-algorand accepts. A light client could stall.
- **NON-CANONICAL**: they differ only on bytes that are not go-algorand's own encoding of what
  they decode to (the Rust decoder is deliberately stricter). Chain data is always canonical.
  Reported, and fatal only with `DIFFTEST_STRICT=1`.
- **MASKED**: a component-level difference the test proves cannot change a verdict (below).
- **UPSTREAM**: a difference inside go-algorand itself (below).

## Known differences

1. **`ln_int_approximation` (fixed).** It computed `ceil(ln(x)·2^16)` with the platform's
   `f64::ln`, which differs from Go's `math.Log` in the last bit for about 1 in 8,000 inputs
   near rounding boundaries (1,132 of 9.26 million worst-case inputs against amd64 Go). It now
   evaluates Go's algorithm exactly as Go's amd64 assembly does, and matches amd64 go-algorand
   on all 19.9 million inputs tested. It is used only by host tooling to derive anchors from
   block headers (a wrong value makes the first state proof fail to verify, never pass); the
   no_std verifier and the zkVM program never compute it.
2. **Upstream: go-algorand disagrees with itself across CPU architectures.** Go's `math.Log`
   is assembly on amd64 and pure Go with fused multiply-adds on arm64, so
   `stateproof.LnIntApproximation` returns different values on amd64 and arm64 for 60 of the
   9.26 million worst-case inputs (between 2.2·10^13 and 9.7·10^14; MainNet's proven weight is
   about 7·10^14). go-algorand computes it during consensus (state proof message generation
   and `ValidateStateProof`), so in principle amd64 and arm64 nodes could disagree about a state
   proof. The chance that a real proven weight hits one of these values is negligible, but it is
   a determinism bug worth reporting upstream (`findings/upstream.txt` lists the inputs).
3. **Masked: Falcon `ConvertToCT` with trailing bytes.** go-algorand's C converter ignores bytes
   after a complete compressed signature; the Rust decoder rejects them. Falcon verification of
   the same bytes fails on both sides, so a state proof containing such a signature is rejected
   by both (the test checks this every time it sees the difference).
4. **Masked: vector commitment depth.** go-algorand's `VerifyVectorCommitment` walks however
   many siblings it is given and uses `TreeDepth` only to position the leaf, so a proof with
   the wrong depth still verifies for some indices (e.g. 0); Rust's `sha256_vc_root` requires
   `depth == siblings.len()`. The light node never takes a depth separately (it uses the path
   length, and 8 for headers), and in that form both agree on every case tested.
5. **Out of domain: light headers of blocks before state proofs.** For blocks older than the
   network's first voters round (consensus < v34), go-algorand's `ToLightBlockHeader` uses the
   seed, while `algorand-lc-host` treats protocols it does not list as seed-era (v34–v38) as
   block-hash era, so that future protocols need no update. No state proof ever commits to those
   blocks' light headers. The test compares every block from the first voters round on strictly
   (both eras), and records older ones separately.
6. **Documented, not a verifier difference: the acceptable-weight rule.** When a node includes a
   state proof in a block it also requires, depending on how soon after the interval the proof
   lands, more signed weight than the cryptographic minimum
   (`calculateAcceptableStateProofWeight`). That is a block-inclusion rule; a light client
   cannot apply it (it knows neither the total online weight nor the confirmation round) and
   does not need to: soundness comes from `Verifier.Verify`, which is what is compared here.

## Results

See the summary table printed by `./run.sh -v` (also `findings/summary.json`). Latest full run:
in `RESULTS.md`.

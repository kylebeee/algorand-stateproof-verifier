# algorand-stateproof-verifier

A Rust verifier for Algorand [state proofs](https://developer.algorand.org/docs/get-details/stateproofs/),
a faithful port of go-algorand's verification. It checks the compact certificate
(Falcon-1024 signatures, Sumhash512 Merkle commitments, the Fiat–Shamir coins and the weight
threshold) and follows the chain of trust from one interval's voters to the next.

It runs anywhere: natively (phones, laptops, servers) or inside a zkVM such as SP1, which is how
the bridge proves Algorand to other chains.

| Crate | What |
|---|---|
| [`algorand-stateproof`](algorand-stateproof) | `no_std` verifier: state proofs, light block headers, transaction inclusion (Merkle) |
| [`algorand-lc-host`](algorand-lc-host) | Host tooling and the `algo-lc` CLI: fetch state proofs from algod/indexer, anchors (including the network's first voters), full-history walks, transaction inclusion proofs |

Checked on real MainNet data: every state proof from the very first one (September 2022) has been
verified, independently, by two tools built on these crates.

```bash
cargo test --release
cargo run --release -p algorand-lc-host --bin algo-lc -- latest
```

Used by:
- [algorand-zk-bridge](https://github.com/kylebeee/algorand-zk-bridge): proves Algorand to other chains through SP1.
- [algorand-light-node](https://github.com/kylebeee/algorand-light-node): a phone light node.

**Unaudited.**

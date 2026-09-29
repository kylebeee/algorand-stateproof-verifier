//! Prints the shape of the state proofs in a light-client input file.
//! `cargo run --release --example stats -- fixtures/mainnet/input.json`
use algorand_stateproof::decode::decode_state_proof;
use base64::Engine;
use std::collections::BTreeMap;

fn main() {
    let path = std::env::args().nth(1).expect("usage: stats <input.json>");
    let input: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    for p in input["stateProofs"].as_array().unwrap() {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(p["stateProof"].as_str().unwrap())
            .unwrap();
        let sp = decode_state_proof(&bytes).unwrap();
        let mut mss_depths = BTreeMap::new();
        let mut sig_lens = (usize::MAX, 0usize);
        for r in &sp.reveals {
            *mss_depths
                .entry(r.sig_slot.sig.proof.tree_depth)
                .or_insert(0) += 1;
            let l = r.sig_slot.sig.falcon_signature.len();
            sig_lens = (sig_lens.0.min(l), sig_lens.1.max(l));
        }
        println!(
            "interval ending {}: {} bytes, signedWeight {} ({:.2e} ALGO), {} positions / {} distinct reveals, sig tree depth {}, part tree depth {}, {} sig hints, {} part hints, MSS depths {:?}, falcon sig bytes {:?}, salt v{}",
            p["message"]["lastAttestedRound"], bytes.len(), sp.signed_weight, sp.signed_weight as f64 / 1e6,
            sp.positions_to_reveal.len(), sp.reveals.len(), sp.sig_proofs.tree_depth, sp.part_proofs.tree_depth,
            sp.sig_proofs.path.len(), sp.part_proofs.path.len(), mss_depths, sig_lens, sp.merkle_signature_salt_version
        );
    }
}

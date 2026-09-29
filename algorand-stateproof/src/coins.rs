//! `crypto/stateproof/coinGenerator.go`: the Fiat–Shamir coins that pick which signature
//! slots a state proof must reveal.
//!
//! The seed is `"spc" || version(0) || votersCommitment || lnProvenWeight(le64) ||
//! sigCommit || signedWeight(le64) || messageHash`, fed to SHAKE256. Each coin is the next
//! little-endian u64 of output, rejection-sampled below `floor(2^64 / sw) · sw` and reduced
//! modulo the signed weight `sw`.

use crate::hash_id;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// `VersionForCoinGenerator`.
const COIN_GENERATOR_VERSION: u8 = 0;

pub struct CoinGenerator {
    reader: <Shake256 as ExtendableOutput>::Reader,
    signed_weight: u64,
    threshold: u128,
}

impl CoinGenerator {
    /// `signed_weight` must be non-zero (enforced earlier by the weight check).
    pub fn new(
        voters_commitment: &[u8],
        ln_proven_weight: u64,
        sig_commit: &[u8],
        signed_weight: u64,
        message_hash: &[u8; 32],
    ) -> Self {
        assert!(signed_weight != 0);
        let mut xof = Shake256::default();
        xof.update(hash_id::STATE_PROOF_COIN);
        xof.update(&[COIN_GENERATOR_VERSION]);
        xof.update(voters_commitment);
        xof.update(&ln_proven_weight.to_le_bytes());
        xof.update(sig_commit);
        xof.update(&signed_weight.to_le_bytes());
        xof.update(message_hash);
        let sw = signed_weight as u128;
        Self {
            reader: xof.finalize_xof(),
            signed_weight,
            threshold: ((1u128 << 64) / sw) * sw,
        }
    }

    /// `getNextCoin`: a uniform value in `[0, signed_weight)`.
    pub fn next_coin(&mut self) -> u64 {
        loop {
            let mut buf = [0u8; 8];
            self.reader.read(&mut buf);
            let r = u64::from_le_bytes(buf);
            if (r as u128) < self.threshold {
                return r % self.signed_weight;
            }
        }
    }
}

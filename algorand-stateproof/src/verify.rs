//! `crypto/stateproof/verifier.go` + `crypto/merklesignature`: verification of a state
//! proof against a trusted voters commitment.

use crate::coins::CoinGenerator;
use crate::error::{Error, Result};
use crate::falcon::{self, DetSignature};
use crate::hash_id;
use crate::merkle::{self, MAX_ENCODED_TREE_DEPTH};
use crate::sumhash::{Sumhash512, DIGEST_SIZE};
use crate::types::{MssSignature, Participant, StateProof, HASH_SUMHASH};
use crate::weights::verify_weights;
use alloc::vec::Vec;

/// `config.Consensus[...].StateProofStrengthTarget` (unchanged since consensus v34).
pub const STRENGTH_TARGET: u64 = 256;
/// `stateproof.MaxTreeDepth`.
pub const MAX_TREE_DEPTH: u8 = 20;
/// `merklesignature.CryptoPrimitivesID` (Sumhash + Falcon).
const CRYPTO_PRIMITIVES_ID: u16 = 0;

/// `Verifier.Verify(round, data, s)`.
///
/// * `voters_commitment` / `ln_proven_weight`: trusted values for this interval, taken
///   from the previous interval's [`StateProofMessage`](crate::StateProofMessage).
/// * `round`: the interval's `LastAttestedRound`.
/// * `message_hash`: [`StateProofMessage::hash`](crate::StateProofMessage::hash).
pub fn verify_state_proof(
    sh: &Sumhash512,
    voters_commitment: &[u8],
    ln_proven_weight: u64,
    strength_target: u64,
    round: u64,
    message_hash: &[u8; 32],
    sp: &StateProof,
) -> Result<()> {
    // verifyStateProofAlgorithms
    if sp.sig_proofs.hash_type != HASH_SUMHASH || sp.part_proofs.hash_type != HASH_SUMHASH {
        return Err(Error::InvalidHashType);
    }
    if sp.sig_commit.len() != DIGEST_SIZE {
        return Err(Error::InvalidSigCommitSize);
    }
    for reveal in &sp.reveals {
        let sig = &reveal.sig_slot.sig;
        if !sig.is_zero() && sig.proof.hash_type != HASH_SUMHASH {
            return Err(Error::InvalidHashType);
        }
    }

    // verifyStateProofTreesDepth
    if sp.sig_proofs.tree_depth > MAX_TREE_DEPTH || sp.part_proofs.tree_depth > MAX_TREE_DEPTH {
        return Err(Error::TreeDepthTooLarge);
    }

    let num_reveals = sp.positions_to_reveal.len() as u64;
    verify_weights(
        sp.signed_weight,
        ln_proven_weight,
        num_reveals,
        strength_target,
    )?;

    for reveal in &sp.reveals {
        if reveal.sig_slot.sig.salt_version() != sp.merkle_signature_salt_version {
            return Err(Error::SaltVersionMismatch);
        }
    }

    let mut sig_leaves = Vec::with_capacity(sp.reveals.len());
    let mut part_leaves = Vec::with_capacity(sp.reveals.len());
    for reveal in &sp.reveals {
        let sig = &reveal.sig_slot.sig;
        // An empty Falcon signature (including an all-zero slot) can never verify.
        if sig.falcon_signature.is_empty() {
            return Err(Error::EmptyFalconSignature);
        }
        // buildCommittableSignature
        if sig.proof.tree_depth > MAX_ENCODED_TREE_DEPTH {
            return Err(Error::MssProofTooDeep);
        }
        let decoded = track!(
            "falcon-decode",
            DetSignature::decode_compressed(&sig.falcon_signature)
        )?;
        sig_leaves.push((
            reveal.position,
            track!(
                "sig-leaf",
                sig_slot_leaf(sh, reveal.sig_slot.l, sig, &decoded)
            )?,
        ));
        part_leaves.push((
            reveal.position,
            track!("part-leaf", participant_leaf(sh, &reveal.participant)),
        ));

        // Participant.PK.VerifyBytes(round, messageHash, sig)
        verify_merkle_signature(sh, &reveal.participant, round, message_hash, sig, &decoded)?;
    }

    track!(
        "sig-tree",
        merkle::verify_vector_commitment(sh, &sp.sig_commit, sig_leaves, &sp.sig_proofs)
    )?;
    track!(
        "part-tree",
        merkle::verify_vector_commitment(sh, voters_commitment, part_leaves, &sp.part_proofs)
    )?;
    track!(
        "coins",
        check_coins(voters_commitment, ln_proven_weight, message_hash, sp)
    )
}

/// Replays the Fiat-Shamir coins and checks each lands in its revealed slot.
fn check_coins(
    voters_commitment: &[u8],
    ln_proven_weight: u64,
    message_hash: &[u8; 32],
    sp: &StateProof,
) -> Result<()> {
    let mut coins = CoinGenerator::new(
        voters_commitment,
        ln_proven_weight,
        &sp.sig_commit,
        sp.signed_weight,
        message_hash,
    );
    for &pos in &sp.positions_to_reveal {
        let reveal = sp.reveal(pos).ok_or(Error::NoRevealInPos(pos))?;
        let coin = coins.next_coin();
        let l = reveal.sig_slot.l;
        // Go's uint64 addition wraps; mirror it exactly.
        if !(l <= coin && coin < l.wrapping_add(reveal.participant.weight)) {
            return Err(Error::CoinNotInRange { pos, coin });
        }
    }
    Ok(())
}

/// `merklesignature.Verifier.VerifyBytes`: the ephemeral key for `round` is in the
/// participant's key tree at the claimed index, and the Falcon signature verifies.
fn verify_merkle_signature(
    sh: &Sumhash512,
    participant: &Participant,
    round: u64,
    message: &[u8],
    sig: &MssSignature,
    decoded: &DetSignature,
) -> Result<()> {
    if participant.key_lifetime == 0 {
        return Err(Error::KeyLifetimeZero);
    }
    let key_round = round - round % participant.key_lifetime;
    let key_leaf = track!(
        "mss-key-leaf",
        sh.hash(&[
            hash_id::KEYS_IN_MSS,
            &CRYPTO_PRIMITIVES_ID.to_le_bytes(),
            &key_round.to_le_bytes(),
            &sig.verifying_key,
        ])
    );
    track!(
        "mss-path",
        merkle::verify_vector_commitment(
            sh,
            &participant.commitment,
            alloc::vec![(sig.vector_commitment_index, key_leaf)],
            &sig.proof,
        )
    )?;
    if sig.falcon_signature.len() > falcon::COMPRESSED_SIG_MAX_SIZE {
        return Err(Error::FalconFormat);
    }
    track!("falcon-verify", decoded.verify(&sig.verifying_key, message))
}

/// Leaf of the signature commitment: `committableSignatureSlot.ToBeHashed()`.
///
/// `"sps" || L(le64) || scheme(le16) || falconCT(1538) || pubkey(1793) || index(le64) ||
/// proof(1 + 16·64)`.
fn sig_slot_leaf(
    sh: &Sumhash512,
    l: u64,
    sig: &MssSignature,
    decoded: &DetSignature,
) -> Result<[u8; DIGEST_SIZE]> {
    let proof = &sig.proof;
    let depth = proof.tree_depth as usize;
    // Honest MSS proofs carry exactly one 64-byte sibling per level. go-algorand's fixed
    // encoding treats short/missing elements loosely; requiring the exact shape only
    // rejects proofs no honest signer produces.
    if proof.path.len() != depth || proof.path.iter().any(|p| p.len() != DIGEST_SIZE) {
        return Err(Error::MssProofMalformed);
    }
    let mut h = sh.hasher();
    h.update(hash_id::STATE_PROOF_SIG);
    h.update(&l.to_le_bytes());
    h.update(&CRYPTO_PRIMITIVES_ID.to_le_bytes());
    h.update(&decoded.to_ct());
    h.update(&sig.verifying_key);
    h.update(&sig.vector_commitment_index.to_le_bytes());
    // SingleLeafProof.GetFixedLengthHashableRepresentation: depth byte, zero padding up
    // to 16 levels, then the path.
    h.update(&[proof.tree_depth]);
    let zero = [0u8; DIGEST_SIZE];
    for _ in depth..MAX_ENCODED_TREE_DEPTH as usize {
        h.update(&zero);
    }
    for p in &proof.path {
        h.update(p);
    }
    Ok(h.finalize())
}

/// Leaf of the voters commitment: `Participant.ToBeHashed()`.
fn participant_leaf(sh: &Sumhash512, p: &Participant) -> [u8; DIGEST_SIZE] {
    sh.hash(&[
        hash_id::STATE_PROOF_PART,
        &p.weight.to_le_bytes(),
        &p.key_lifetime.to_le_bytes(),
        &p.commitment,
    ])
}

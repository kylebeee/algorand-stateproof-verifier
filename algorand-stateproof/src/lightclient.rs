//! The light-client state transition that the zkVM proves.
//!
//! The trusted state is the voters commitment (and `ln(provenWeight)`) that will sign the
//! next interval. Verifying that interval's state proof yields its block headers commitment
//! and — from the signed message — the voters of the interval after it.
//!
//! ```text
//! state_k = (voters_k, lnPW_k, next_round_k)
//!   verify SP_k over msg_k with (voters_k, lnPW_k), msg_k.first == next_round_k
//! state_{k+1} = (msg_k.voters, msg_k.lnPW, msg_k.last + 1)
//! ```

use crate::block::StateProofTxn;
use crate::decode::decode_state_proof;
use crate::error::{Error, Result};
use crate::message::StateProofMessage;
use crate::sumhash::Sumhash512;
use crate::verify::{verify_state_proof, STRENGTH_TARGET};
use alloc::vec::Vec;

/// `StateProofInterval` (256 rounds since consensus v34). The on-chain verifier assumes
/// 256 light headers per commitment (a depth-8 vector commitment).
pub const STATE_PROOF_INTERVAL: u64 = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TrustedState {
    /// Sumhash512 commitment to the voters that sign the interval starting at `next_round`.
    #[cfg_attr(feature = "serde", serde(with = "bytes64"))]
    pub voters_commitment: [u8; 64],
    pub ln_proven_weight: u64,
    /// First round of the next interval to be proven.
    pub next_round: u64,
}

impl TrustedState {
    /// The state established by a (trusted) message: it authorizes the next interval.
    pub fn from_message(msg: &StateProofMessage) -> Result<Self> {
        Ok(Self {
            voters_commitment: msg
                .voters_commitment
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidMessage("voters commitment must be 64 bytes"))?,
            ln_proven_weight: msg.ln_proven_weight,
            next_round: msg
                .last_attested_round
                .checked_add(1)
                .ok_or(Error::InvalidMessage("round overflow"))?,
        })
    }
}

/// A block headers commitment attested by a verified state proof.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerifiedInterval {
    pub first_attested_round: u64,
    pub last_attested_round: u64,
    pub block_headers_commitment: [u8; 32],
}

/// What a verified certificate showed, beyond its interval: enough to evaluate claims stronger
/// than the protocol's (e.g. that at least 2/3 of the weight signed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CertificateStats {
    pub signed_weight: u64,
    pub num_reveals: u64,
    /// The trusted ln(provenWeight) the certificate was checked against.
    pub ln_proven_weight: u64,
}

/// Verifies one state proof on top of `state` and returns the successor state.
pub fn apply_state_proof(
    sh: &Sumhash512,
    state: &TrustedState,
    txn: &StateProofTxn,
) -> Result<(TrustedState, VerifiedInterval)> {
    apply_state_proof_with_stats(sh, state, txn).map(|(next, interval, _)| (next, interval))
}

/// [`apply_state_proof`], also returning the certificate's [`CertificateStats`].
pub fn apply_state_proof_with_stats(
    sh: &Sumhash512,
    state: &TrustedState,
    txn: &StateProofTxn,
) -> Result<(TrustedState, VerifiedInterval, CertificateStats)> {
    let msg = &txn.message;
    if msg.first_attested_round != state.next_round {
        return Err(Error::RoundMismatch {
            expected: state.next_round,
            got: msg.first_attested_round,
        });
    }
    if msg
        .last_attested_round
        .checked_sub(msg.first_attested_round)
        != Some(STATE_PROOF_INTERVAL - 1)
        || msg.last_attested_round % STATE_PROOF_INTERVAL != 0
    {
        return Err(Error::InvalidMessage(
            "interval is not 256 rounds ending on a multiple of 256",
        ));
    }
    let block_headers_commitment: [u8; 32] = msg
        .block_headers_commitment
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidMessage("block headers commitment must be 32 bytes"))?;
    let next = TrustedState::from_message(msg)?;

    let sp = track!("decode", decode_state_proof(&txn.state_proof))?;
    verify_state_proof(
        sh,
        &state.voters_commitment,
        state.ln_proven_weight,
        STRENGTH_TARGET,
        msg.last_attested_round,
        &track!("message-hash", msg.hash()),
        &sp,
    )?;

    Ok((
        next,
        VerifiedInterval {
            first_attested_round: msg.first_attested_round,
            last_attested_round: msg.last_attested_round,
            block_headers_commitment,
        },
        CertificateStats {
            signed_weight: sp.signed_weight,
            num_reveals: sp.positions_to_reveal.len() as u64,
            ln_proven_weight: state.ln_proven_weight,
        },
    ))
}

/// [`apply_state_proofs`], also returning each certificate's [`CertificateStats`].
pub fn apply_state_proofs_with_stats(
    sh: &Sumhash512,
    state: &TrustedState,
    txns: &[StateProofTxn],
) -> Result<(TrustedState, Vec<VerifiedInterval>, Vec<CertificateStats>)> {
    if txns.is_empty() {
        return Err(Error::NoStateProofs);
    }
    let mut state = state.clone();
    let mut intervals = Vec::with_capacity(txns.len());
    let mut stats = Vec::with_capacity(txns.len());
    for txn in txns {
        let (next, interval, s) = apply_state_proof_with_stats(sh, &state, txn)?;
        state = next;
        intervals.push(interval);
        stats.push(s);
    }
    Ok((state, intervals, stats))
}

/// Verifies a consecutive run of state proofs; returns the final state and every interval.
pub fn apply_state_proofs(
    sh: &Sumhash512,
    state: &TrustedState,
    txns: &[StateProofTxn],
) -> Result<(TrustedState, Vec<VerifiedInterval>)> {
    if txns.is_empty() {
        return Err(Error::NoStateProofs);
    }
    let mut state = state.clone();
    let mut intervals = Vec::with_capacity(txns.len());
    for txn in txns {
        let (next, interval) = apply_state_proof(sh, &state, txn)?;
        state = next;
        intervals.push(interval);
    }
    Ok((state, intervals))
}

#[cfg(feature = "serde")]
mod bytes64 {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        v.as_slice().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v = alloc::vec::Vec::<u8>::deserialize(d)?;
        v.try_into()
            .map_err(|_| D::Error::custom("expected 64 bytes"))
    }
}

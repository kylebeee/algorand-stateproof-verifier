//! End-to-end tests against real Algorand mainnet state proofs.
//!
//! `fixtures/mainnet/input.json` holds the trusted state established by the signed message
//! of interval [65474817, 65475072] and the three state proofs that follow it, exactly as
//! they appear in mainnet blocks 65475464, 65475720 and 65475976
//! (regenerate with `algo-lc anchor` + `algo-lc fetch`).

use algorand_stateproof::block::StateProofTxn;
use algorand_stateproof::decode::decode_state_proof;
use algorand_stateproof::lightclient::{apply_state_proof, apply_state_proofs, TrustedState};
use algorand_stateproof::message::StateProofMessage;
use algorand_stateproof::types::StateProof;
use algorand_stateproof::verify::{verify_state_proof, STRENGTH_TARGET};
use algorand_stateproof::{Error, Sumhash512};
use base64::Engine;
use std::sync::OnceLock;

struct Fixture {
    state: TrustedState,
    txns: Vec<StateProofTxn>,
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).unwrap()
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../fixtures/mainnet/input.json"
        );
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let ts = &v["trustedState"];
        let state = TrustedState {
            voters_commitment: unhex(ts["votersCommitment"].as_str().unwrap())
                .try_into()
                .unwrap(),
            ln_proven_weight: ts["lnProvenWeight"].as_u64().unwrap(),
            next_round: ts["nextRound"].as_u64().unwrap(),
        };
        let txns = v["stateProofs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                let m = &p["message"];
                StateProofTxn {
                    message: StateProofMessage {
                        block_headers_commitment: unhex(
                            m["blockHeadersCommitment"].as_str().unwrap(),
                        ),
                        voters_commitment: unhex(m["votersCommitment"].as_str().unwrap()),
                        ln_proven_weight: m["lnProvenWeight"].as_u64().unwrap(),
                        first_attested_round: m["firstAttestedRound"].as_u64().unwrap(),
                        last_attested_round: m["lastAttestedRound"].as_u64().unwrap(),
                    },
                    state_proof: base64::engine::general_purpose::STANDARD
                        .decode(p["stateProof"].as_str().unwrap())
                        .unwrap(),
                }
            })
            .collect();
        Fixture { state, txns }
    })
}

fn sumhash() -> &'static Sumhash512 {
    static S: OnceLock<Sumhash512> = OnceLock::new();
    S.get_or_init(Sumhash512::new)
}

/// Verifies a (possibly modified) decoded proof of the first interval.
fn verify_first(
    sp: &StateProof,
    msg: &StateProofMessage,
    state: &TrustedState,
) -> Result<(), Error> {
    verify_state_proof(
        sumhash(),
        &state.voters_commitment,
        state.ln_proven_weight,
        STRENGTH_TARGET,
        msg.last_attested_round,
        &msg.hash(),
        sp,
    )
}

fn first() -> (StateProof, StateProofMessage, TrustedState) {
    let f = fixture();
    (
        decode_state_proof(&f.txns[0].state_proof).unwrap(),
        f.txns[0].message.clone(),
        f.state.clone(),
    )
}

#[test]
fn mainnet_chain_verifies() {
    let f = fixture();
    let (end, intervals) = apply_state_proofs(sumhash(), &f.state, &f.txns).unwrap();
    assert_eq!(intervals.len(), 3);
    for (i, (interval, txn)) in intervals.iter().zip(&f.txns).enumerate() {
        assert_eq!(interval.first_attested_round, 65475073 + 256 * i as u64);
        assert_eq!(
            interval.last_attested_round,
            interval.first_attested_round + 255
        );
        assert_eq!(
            interval.block_headers_commitment.as_slice(),
            txn.message.block_headers_commitment.as_slice()
        );
    }
    let last = &f.txns[2].message;
    assert_eq!(end, TrustedState::from_message(last).unwrap());
    assert_eq!(end.next_round, 65475841);
}

#[test]
fn message_encoding_roundtrips_through_block_bytes() {
    // The message is re-encoded canonically before hashing; decoding our own encoding must
    // give back the same fields.
    for txn in &fixture().txns {
        let enc = txn.message.encode();
        let dec = StateProofMessage::decode(&mut algorand_stateproof::msgpack::Reader::new(&enc))
            .unwrap();
        assert_eq!(dec, txn.message);
    }
}

#[test]
fn intervals_cannot_be_skipped() {
    let f = fixture();
    // Interval 2 presented directly after the anchor.
    assert_eq!(
        apply_state_proof(sumhash(), &f.state, &f.txns[1]),
        Err(Error::RoundMismatch {
            expected: 65475073,
            got: 65475329
        })
    );
    // Even with the round check bypassed, the anchor's voters did not sign interval 2.
    let mut state = f.state.clone();
    state.next_round = f.txns[1].message.first_attested_round;
    assert!(apply_state_proof(sumhash(), &state, &f.txns[1]).is_err());
}

#[test]
fn wrong_trusted_voters_rejected() {
    let (sp, msg, mut state) = first();
    state.voters_commitment[0] ^= 1;
    assert_eq!(
        verify_first(&sp, &msg, &state),
        Err(Error::MerkleRootMismatch)
    );
}

#[test]
fn tampered_message_rejected() {
    // Claiming a different block headers commitment (the thing a bridge would care about).
    let (sp, mut msg, state) = first();
    msg.block_headers_commitment[31] ^= 1;
    assert_eq!(
        verify_first(&sp, &msg, &state),
        Err(Error::FalconBadSignature)
    );

    // Claiming different voters for the next interval (hijacking the chain).
    let (sp, mut msg, state) = first();
    msg.voters_commitment[5] ^= 0x80;
    assert_eq!(
        verify_first(&sp, &msg, &state),
        Err(Error::FalconBadSignature)
    );

    let (sp, mut msg, state) = first();
    msg.ln_proven_weight -= 1;
    assert_eq!(
        verify_first(&sp, &msg, &state),
        Err(Error::FalconBadSignature)
    );
}

#[test]
fn wrong_round_rejected() {
    // Signatures are bound to the ephemeral key of the attested round.
    let (sp, msg, state) = first();
    let r = verify_state_proof(
        sumhash(),
        &state.voters_commitment,
        state.ln_proven_weight,
        STRENGTH_TARGET,
        msg.last_attested_round + 256,
        &msg.hash(),
        &sp,
    );
    assert_eq!(r, Err(Error::MerkleRootMismatch));
}

#[test]
fn inflated_participant_weight_rejected() {
    let (mut sp, msg, state) = first();
    sp.reveals[0].participant.weight += 1_000_000;
    assert_eq!(
        verify_first(&sp, &msg, &state),
        Err(Error::MerkleRootMismatch)
    );
}

#[test]
fn tampered_signature_rejected() {
    let (mut sp, msg, state) = first();
    let sig = &mut sp.reveals[3].sig_slot.sig.falcon_signature;
    let mid = sig.len() / 2;
    sig[mid] ^= 0x10;
    assert!(matches!(
        verify_first(&sp, &msg, &state),
        Err(Error::FalconFormat | Error::FalconBadSignature)
    ));

    // A valid signature from a different reveal, moved onto this participant.
    let (mut sp, msg, state) = first();
    sp.reveals[3].sig_slot.sig = sp.reveals[4].sig_slot.sig.clone();
    assert_eq!(
        verify_first(&sp, &msg, &state),
        Err(Error::MerkleRootMismatch)
    );
}

#[test]
fn tampered_slot_offset_rejected() {
    let (mut sp, msg, state) = first();
    sp.reveals[1].sig_slot.l += 1;
    assert_eq!(
        verify_first(&sp, &msg, &state),
        Err(Error::MerkleRootMismatch)
    );
}

#[test]
fn signed_weight_is_bound_by_the_coins() {
    let (mut sp, msg, state) = first();
    sp.signed_weight += 1;
    assert!(matches!(
        verify_first(&sp, &msg, &state),
        Err(Error::CoinNotInRange { .. })
    ));

    // Claiming a higher proven weight than the trusted one.
    let (sp, msg, mut state) = first();
    state.ln_proven_weight += 50_000;
    assert_eq!(
        verify_first(&sp, &msg, &state),
        Err(Error::InsufficientSignedWeight)
    );
}

#[test]
fn too_few_reveals_rejected() {
    let (mut sp, msg, state) = first();
    sp.positions_to_reveal.pop();
    assert_eq!(
        verify_first(&sp, &msg, &state),
        Err(Error::InsufficientSignedWeight)
    );
}

#[test]
fn missing_reveal_rejected() {
    let (mut sp, msg, state) = first();
    sp.reveals.remove(10);
    assert!(verify_first(&sp, &msg, &state).is_err());
}

#[test]
fn salt_version_must_match() {
    let (mut sp, msg, state) = first();
    sp.merkle_signature_salt_version = 1;
    assert_eq!(
        verify_first(&sp, &msg, &state),
        Err(Error::SaltVersionMismatch)
    );
}

#[test]
fn decoder_is_strict() {
    let bytes = &fixture().txns[0].state_proof;
    let mut trailing = bytes.clone();
    trailing.push(0xc0);
    assert!(decode_state_proof(&trailing).is_err());
    assert!(decode_state_proof(&bytes[..bytes.len() - 1]).is_err());
}

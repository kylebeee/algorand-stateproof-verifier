//! Verifier for Algorand state proofs, written to run inside a zkVM (SP1, RISC Zero, ...).
//!
//! An Algorand state proof is a compact certificate: every 256 rounds the top online
//! accounts sign a [`StateProofMessage`](message::StateProofMessage) with ephemeral
//! Falcon-1024 keys, and a prover reveals a pseudo-random subset of those signatures that
//! is large enough to show that more than 30% of the online stake signed. The message
//! commits to the 256 block headers of the interval and to the voters of the *next*
//! interval, so a light client that trusts one voters commitment can walk the chain
//! forward one state proof at a time.
//!
//! This crate is a faithful, dependency-light port of the verification half of go-algorand:
//!
//! | module | go-algorand / reference |
//! |---|---|
//! | [`sumhash`] | `github.com/algorand/go-sumhash` (Sumhash512) |
//! | [`falcon`] | `github.com/algorand/falcon` (deterministic Falcon-1024 verify) |
//! | [`merkle`] | `crypto/merklearray` (vector commitments, batch proofs) |
//! | [`verify`] | `crypto/stateproof/verifier.go`, `crypto/merklesignature` |
//! | [`weights`], [`coins`] | `crypto/stateproof/weights.go`, `coinGenerator.go` |
//! | [`message`] | `data/stateproofmsg/message.go` |
//! | [`lightheader`] | `data/bookkeeping/lightBlockHeader.go`, `txn_merkle.go` |
//! | [`lightclient`] | chaining `ValidateStateProof` across intervals |
//! | [`mmr`] | accumulator over interval commitments (history proofs) |
#![no_std]

extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

/// Wraps `$body` in SP1 `cycle-tracker-report` markers when the `cycle-tracker` feature is
/// enabled (the executor then sums cycles per label); otherwise it is just `$body`.
macro_rules! track {
    ($label:literal, $body:expr) => {{
        #[cfg(feature = "cycle-tracker")]
        std::println!(concat!("cycle-tracker-report-start: ", $label));
        let result = $body;
        #[cfg(feature = "cycle-tracker")]
        std::println!(concat!("cycle-tracker-report-end: ", $label));
        result
    }};
}

pub mod block;
pub mod coins;
pub mod decode;
pub mod error;
pub mod falcon;
pub mod lightclient;
pub mod lightheader;
pub mod merkle;
pub mod message;
pub mod mmr;
pub mod msgpack;
pub mod sumhash;
pub mod types;
pub mod verify;
pub mod weights;

#[cfg(feature = "sol")]
pub mod sol;

pub use error::Error;
pub use lightclient::{apply_state_proof, TrustedState, VerifiedInterval};
pub use message::StateProofMessage;
pub use sumhash::Sumhash512;
pub use types::StateProof;
pub use verify::verify_state_proof;

/// Domain-separation prefixes (`protocol.HashID`) used by the structures verified here.
pub mod hash_id {
    pub const BLOCK_HEADER: &[u8] = b"BH";
    pub const BLOCK_HEADER_256: &[u8] = b"B256";
    pub const KEYS_IN_MSS: &[u8] = b"KP";
    pub const MERKLE_ARRAY_NODE: &[u8] = b"MA";
    pub const MERKLE_VC_BOTTOM_LEAF: &[u8] = b"MB";
    pub const SIGNED_TXN_IN_BLOCK: &[u8] = b"STIB";
    pub const STATE_PROOF_COIN: &[u8] = b"spc";
    pub const STATE_PROOF_MESSAGE: &[u8] = b"spm";
    pub const STATE_PROOF_PART: &[u8] = b"spp";
    pub const STATE_PROOF_SIG: &[u8] = b"sps";
    pub const TXN_MERKLE_LEAF: &[u8] = b"TL";
    pub const TRANSACTION: &[u8] = b"TX";
}

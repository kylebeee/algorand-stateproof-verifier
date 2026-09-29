//! Rust mirrors of the go-algorand structures carried inside a state proof.

use crate::falcon;
use alloc::vec;
use alloc::vec::Vec;

/// `crypto.HashType` values.
pub const HASH_SHA512_256: u16 = 0;
pub const HASH_SUMHASH: u16 = 1;
pub const HASH_SHA256: u16 = 2;

/// `merklearray.Proof` (also the flattened `merklearray.SingleLeafProof`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MerkleProof {
    /// Sibling hints in verification order; an empty element stands for an all-zero digest.
    pub path: Vec<Vec<u8>>,
    pub hash_type: u16,
    /// Number of edges from the root to a leaf.
    pub tree_depth: u8,
}

impl MerkleProof {
    pub fn is_zero(&self) -> bool {
        self.path.is_empty() && self.hash_type == 0 && self.tree_depth == 0
    }
}

/// `merklesignature.Signature`: an ephemeral Falcon signature plus the proof that the
/// ephemeral key sits at the right round in the participant's key tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MssSignature {
    /// Compressed deterministic Falcon-1024 signature.
    pub falcon_signature: Vec<u8>,
    pub vector_commitment_index: u64,
    pub proof: MerkleProof,
    /// Falcon public key (`FalconVerifier.PublicKey`), always [`falcon::PUBKEY_SIZE`] bytes.
    pub verifying_key: Vec<u8>,
}

impl Default for MssSignature {
    fn default() -> Self {
        Self {
            falcon_signature: Vec::new(),
            vector_commitment_index: 0,
            proof: MerkleProof::default(),
            verifying_key: vec![0u8; falcon::PUBKEY_SIZE],
        }
    }
}

impl MssSignature {
    /// `Signature.MsgIsZero()`.
    pub fn is_zero(&self) -> bool {
        self.falcon_signature.is_empty()
            && self.vector_commitment_index == 0
            && self.proof.is_zero()
            && self.verifying_key.iter().all(|&b| b == 0)
    }

    /// `CompressedSignature.SaltVersion()`: byte 1, or 0 for a too-short signature.
    pub fn salt_version(&self) -> u8 {
        if self.falcon_signature.len() < 2 {
            0
        } else {
            self.falcon_signature[1]
        }
    }
}

/// `stateproof.sigslotCommit`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SigSlot {
    pub sig: MssSignature,
    /// Total weight of all signature slots before this one.
    pub l: u64,
}

/// `basics.Participant`: a top voter's long-term key commitment and stake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Participant {
    /// Root of the participant's Merkle signature scheme key tree (Sumhash512).
    pub commitment: [u8; 64],
    pub key_lifetime: u64,
    pub weight: u64,
}

impl Default for Participant {
    fn default() -> Self {
        Self {
            commitment: [0u8; 64],
            key_lifetime: 0,
            weight: 0,
        }
    }
}

/// `stateproof.Reveal` together with its position (the key in `StateProof.Reveals`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reveal {
    pub position: u64,
    pub sig_slot: SigSlot,
    pub participant: Participant,
}

/// `stateproof.StateProof`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateProof {
    pub sig_commit: Vec<u8>,
    pub signed_weight: u64,
    pub sig_proofs: MerkleProof,
    pub part_proofs: MerkleProof,
    pub merkle_signature_salt_version: u8,
    /// Sorted by strictly increasing position.
    pub reveals: Vec<Reveal>,
    pub positions_to_reveal: Vec<u64>,
}

impl StateProof {
    pub fn reveal(&self, position: u64) -> Option<&Reveal> {
        self.reveals
            .binary_search_by_key(&position, |r| r.position)
            .ok()
            .map(|i| &self.reveals[i])
    }
}

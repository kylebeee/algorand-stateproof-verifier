//! `data/stateproofmsg.Message`: what the state proof signers attest to.

use crate::error::Result;
use crate::hash_id;
use crate::msgpack::{self, read_struct, Reader};
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// The message signed for the interval `[first_attested_round, last_attested_round]`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StateProofMessage {
    /// SHA-256 vector commitment to the interval's light block headers (32 bytes).
    pub block_headers_commitment: Vec<u8>,
    /// Sumhash512 commitment to the voters of the *next* interval (64 bytes).
    pub voters_commitment: Vec<u8>,
    /// `ln(provenWeight)` of the next interval with 16 bits of precision.
    pub ln_proven_weight: u64,
    pub first_attested_round: u64,
    pub last_attested_round: u64,
}

impl StateProofMessage {
    /// Canonical msgpack encoding (`protocol.Encode`): sorted keys, zero values omitted.
    pub fn encode(&self) -> Vec<u8> {
        let fields = [
            self.ln_proven_weight != 0,
            !self.block_headers_commitment.is_empty(),
            self.first_attested_round != 0,
            self.last_attested_round != 0,
            !self.voters_commitment.is_empty(),
        ];
        let mut out = Vec::with_capacity(128);
        msgpack::write_map_header(&mut out, fields.iter().filter(|&&f| f).count());
        if fields[0] {
            msgpack::write_str(&mut out, b"P");
            msgpack::write_uint(&mut out, self.ln_proven_weight);
        }
        if fields[1] {
            msgpack::write_str(&mut out, b"b");
            msgpack::write_bin(&mut out, &self.block_headers_commitment);
        }
        if fields[2] {
            msgpack::write_str(&mut out, b"f");
            msgpack::write_uint(&mut out, self.first_attested_round);
        }
        if fields[3] {
            msgpack::write_str(&mut out, b"l");
            msgpack::write_uint(&mut out, self.last_attested_round);
        }
        if fields[4] {
            msgpack::write_str(&mut out, b"v");
            msgpack::write_bin(&mut out, &self.voters_commitment);
        }
        out
    }

    /// `Message.Hash()`: `SHA256("spm" || encode())`. This is the byte string every
    /// participant signs with Falcon.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(hash_id::STATE_PROOF_MESSAGE);
        h.update(self.encode());
        h.finalize().into()
    }

    /// Decodes a msgpack message (e.g. the `spmsg` field of a state proof transaction).
    pub fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let mut m = StateProofMessage::default();
        read_struct(r, &[b"P", b"b", b"f", b"l", b"v"], |field, r| {
            match field {
                0 => m.ln_proven_weight = r.read_uint()?,
                1 => m.block_headers_commitment = r.read_bin()?.to_vec(),
                2 => m.first_attested_round = r.read_uint()?,
                3 => m.last_attested_round = r.read_uint()?,
                _ => m.voters_commitment = r.read_bin()?.to_vec(),
            }
            Ok(())
        })?;
        Ok(m)
    }
}

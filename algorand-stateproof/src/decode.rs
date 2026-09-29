//! Decoding of the msgpack `StateProof` as produced by go-algorand (`protocol.Encode`).
//!
//! Decoding is stricter than go-algorand's msgp decoder: unknown and repeated fields are
//! rejected (as msgp does), and additionally the reveals map must be in canonical
//! (strictly increasing) key order. Honest encoders always produce that form; rejecting
//! anything else keeps the reveal lookup unambiguous.

use crate::error::{Error, Result};
use crate::falcon;
use crate::msgpack::{read_struct, Reader};
use crate::types::{MerkleProof, MssSignature, Participant, Reveal, SigSlot, StateProof};
use alloc::vec::Vec;

/// `stateproof.MaxReveals`.
pub const MAX_REVEALS: usize = 640;
/// `merklearray.MaxNumLeavesOnEncodedTree / 2`.
const MAX_PROOF_PATH: usize = (1 << 16) / 2;

pub fn decode_state_proof(bytes: &[u8]) -> Result<StateProof> {
    let mut r = Reader::new(bytes);
    let sp = read_state_proof(&mut r)?;
    if !r.is_at_end() {
        return Err(Error::Msgpack("trailing bytes after state proof"));
    }
    Ok(sp)
}

pub fn read_state_proof(r: &mut Reader<'_>) -> Result<StateProof> {
    let mut sp = StateProof::default();
    read_struct(
        r,
        &[b"P", b"S", b"c", b"pr", b"r", b"v", b"w"],
        |field, r| {
            match field {
                0 => sp.part_proofs = read_merkle_proof(r)?,
                1 => sp.sig_proofs = read_merkle_proof(r)?,
                2 => sp.sig_commit = r.read_bin()?.to_vec(),
                3 => {
                    let n = r.read_array_len_or_nil()?;
                    if n > MAX_REVEALS {
                        return Err(Error::TooManyReveals);
                    }
                    sp.positions_to_reveal =
                        (0..n).map(|_| r.read_uint()).collect::<Result<_>>()?;
                }
                4 => {
                    let n = r.read_map_len_or_nil()?;
                    if n > MAX_REVEALS {
                        return Err(Error::TooManyReveals);
                    }
                    let mut reveals: Vec<Reveal> = Vec::with_capacity(n);
                    for _ in 0..n {
                        let position = r.read_uint()?;
                        if reveals.last().is_some_and(|prev| prev.position >= position) {
                            return Err(Error::Msgpack("reveals map keys not strictly increasing"));
                        }
                        let mut reveal = read_reveal(r)?;
                        reveal.position = position;
                        reveals.push(reveal);
                    }
                    sp.reveals = reveals;
                }
                5 => sp.merkle_signature_salt_version = r.read_u8()?,
                _ => sp.signed_weight = r.read_uint()?,
            }
            Ok(())
        },
    )?;
    Ok(sp)
}

/// `merklearray.Proof` / `SingleLeafProof` (the latter embeds `Proof` flattened).
fn read_merkle_proof(r: &mut Reader<'_>) -> Result<MerkleProof> {
    let mut p = MerkleProof::default();
    read_struct(r, &[b"hsh", b"pth", b"td"], |field, r| {
        match field {
            0 => {
                read_struct(r, &[b"t"], |_, r| {
                    p.hash_type = r.read_u16()?;
                    Ok(())
                })?;
            }
            1 => {
                let n = r.read_array_len_or_nil()?;
                if n > MAX_PROOF_PATH {
                    return Err(Error::Msgpack("merkle proof path too long"));
                }
                p.path = (0..n)
                    .map(|_| r.read_bin().map(|b| b.to_vec()))
                    .collect::<Result<_>>()?;
            }
            _ => p.tree_depth = r.read_u8()?,
        }
        Ok(())
    })?;
    Ok(p)
}

fn read_reveal(r: &mut Reader<'_>) -> Result<Reveal> {
    let mut reveal = Reveal::default();
    read_struct(r, &[b"p", b"s"], |field, r| {
        match field {
            0 => reveal.participant = read_participant(r)?,
            _ => reveal.sig_slot = read_sig_slot(r)?,
        }
        Ok(())
    })?;
    Ok(reveal)
}

fn read_participant(r: &mut Reader<'_>) -> Result<Participant> {
    let mut p = Participant::default();
    read_struct(r, &[b"p", b"w"], |field, r| {
        match field {
            0 => read_struct(r, &[b"cmt", b"lf"], |field, r| {
                match field {
                    0 => p.commitment = r.read_bin_exact::<64>()?,
                    _ => p.key_lifetime = r.read_uint()?,
                }
                Ok(())
            })?,
            _ => p.weight = r.read_uint()?,
        }
        Ok(())
    })?;
    Ok(p)
}

fn read_sig_slot(r: &mut Reader<'_>) -> Result<SigSlot> {
    let mut slot = SigSlot::default();
    read_struct(r, &[b"l", b"s"], |field, r| {
        match field {
            0 => slot.l = r.read_uint()?,
            _ => slot.sig = read_mss_signature(r)?,
        }
        Ok(())
    })?;
    Ok(slot)
}

fn read_mss_signature(r: &mut Reader<'_>) -> Result<MssSignature> {
    let mut sig = MssSignature::default();
    read_struct(r, &[b"idx", b"prf", b"sig", b"vkey"], |field, r| {
        match field {
            0 => sig.vector_commitment_index = r.read_uint()?,
            1 => sig.proof = read_merkle_proof(r)?,
            2 => {
                let s = r.read_bin()?;
                if s.len() > falcon::CT_SIG_SIZE {
                    return Err(Error::Msgpack("falcon signature too long"));
                }
                sig.falcon_signature = s.to_vec();
            }
            _ => read_struct(r, &[b"k"], |_, r| {
                sig.verifying_key = r.read_bin_exact::<{ falcon::PUBKEY_SIZE }>()?.to_vec();
                Ok(())
            })?,
        }
        Ok(())
    })?;
    Ok(sig)
}

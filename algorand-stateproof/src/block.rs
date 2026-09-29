//! Parsing of raw msgpack blocks, as served by algod `GET /v2/blocks/{round}?format=msgpack`
//! (a map `{"block": Block, "cert": ...}`), or a bare `Block` map.
//!
//! State proof transactions (`type = "stpf"`) carry the `StateProof` (`sp`) and the
//! `Message` (`spmsg`). Archival nodes keep every block, so this is how old state proofs are
//! recovered (algod's `/v2/stateproofs/{round}` only searches recent rounds).

use crate::error::{Error, Result};
use crate::message::StateProofMessage;
use crate::msgpack::{self, Reader};
use alloc::vec::Vec;

/// A state proof transaction's payload.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StateProofTxn {
    pub message: StateProofMessage,
    /// The `StateProof` exactly as encoded in the block (canonical msgpack).
    pub state_proof: Vec<u8>,
}

/// Header fields plus the transactions of a block, as raw msgpack spans.
pub struct RawBlock<'a> {
    /// `(key, raw value)` for every header field (everything but `txns`), in encoded order.
    pub header_fields: Vec<(&'a [u8], &'a [u8])>,
    /// Raw `SignedTxnInBlock` encodings in payset order.
    pub txns: Vec<&'a [u8]>,
}

impl<'a> RawBlock<'a> {
    /// Parses either an algod block response (`{"block": ..}`) or a bare block map.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let n = r.read_map_len()?;
        let mut first_key = Reader::new(&bytes[r.position()..]);
        let is_response =
            n <= 2 && matches!(first_key.read_str(), Ok(k) if k == b"block" || k == b"cert");
        if !is_response {
            return Self::parse_block_map(bytes);
        }
        let mut block = None;
        for _ in 0..n {
            let key = r.read_str()?;
            let value = r.raw_value()?;
            if key == b"block" {
                block = Some(value);
            }
        }
        Self::parse_block_map(block.ok_or(Error::Msgpack("response has no block"))?)
    }

    fn parse_block_map(bytes: &'a [u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let n = r.read_map_len()?;
        let mut header_fields = Vec::with_capacity(n);
        let mut txns = Vec::new();
        for _ in 0..n {
            let key = r.read_str()?;
            if key == b"txns" {
                let count = r.read_array_len_or_nil()?;
                for _ in 0..count {
                    txns.push(r.raw_value()?);
                }
            } else {
                header_fields.push((key, r.raw_value()?));
            }
        }
        Ok(Self {
            header_fields,
            txns,
        })
    }

    pub fn header_field(&self, key: &[u8]) -> Option<&'a [u8]> {
        self.header_fields
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| *v)
    }

    pub fn round(&self) -> Result<u64> {
        self.header_field(b"rnd")
            .map_or(Ok(0), |v| Reader::new(v).read_uint())
    }

    fn header_bytes32(&self, key: &[u8]) -> Result<[u8; 32]> {
        self.header_field(key)
            .map_or(Ok([0u8; 32]), |v| Reader::new(v).read_bin_exact::<32>())
    }

    pub fn genesis_hash(&self) -> Result<[u8; 32]> {
        self.header_bytes32(b"gh")
    }

    pub fn genesis_id(&self) -> Result<Vec<u8>> {
        self.header_field(b"gen").map_or(Ok(Vec::new()), |v| {
            Reader::new(v).read_str().map(|s| s.to_vec())
        })
    }

    pub fn seed(&self) -> Result<[u8; 32]> {
        self.header_bytes32(b"seed")
    }

    pub fn sha256_txn_commitment(&self) -> Result<[u8; 32]> {
        self.header_bytes32(b"txn256")
    }

    /// Canonical encoding of the `BlockHeader` (the block map minus `txns`, keys sorted).
    /// `SHA512_256("BH" || header_bytes())` is the block hash.
    pub fn header_bytes(&self) -> Vec<u8> {
        let mut fields = self.header_fields.clone();
        fields.sort_by(|a, b| a.0.cmp(b.0));
        let mut out = Vec::new();
        msgpack::write_map_header(&mut out, fields.len());
        for (k, v) in fields {
            msgpack::write_str(&mut out, k);
            out.extend_from_slice(v);
        }
        out
    }

    /// Every state proof transaction in the block.
    pub fn state_proof_txns(&self) -> Result<Vec<StateProofTxn>> {
        let mut out = Vec::new();
        for stib in &self.txns {
            if let Some(txn) = stib_field(stib, b"txn")? {
                if let Some(sp) = parse_state_proof_txn(txn)? {
                    out.push(sp);
                }
            }
        }
        Ok(out)
    }
}

/// Raw value of `key` in a msgpack map, if present.
pub fn stib_field<'a>(map: &'a [u8], key: &[u8]) -> Result<Option<&'a [u8]>> {
    let mut r = Reader::new(map);
    let n = r.read_map_len()?;
    for _ in 0..n {
        let k = r.read_str()?;
        let v = r.raw_value()?;
        if k == key {
            return Ok(Some(v));
        }
    }
    Ok(None)
}

fn parse_state_proof_txn(txn: &[u8]) -> Result<Option<StateProofTxn>> {
    let mut r = Reader::new(txn);
    let n = r.read_map_len()?;
    let (mut is_stpf, mut sp, mut msg) = (false, None, None);
    for _ in 0..n {
        let key = r.read_str()?;
        match key {
            b"type" => is_stpf = r.read_str()? == b"stpf",
            b"sp" => sp = Some(r.raw_value()?),
            b"spmsg" => msg = Some(StateProofMessage::decode(&mut r)?),
            _ => r.skip()?,
        }
    }
    if !is_stpf {
        return Ok(None);
    }
    match (msg, sp) {
        (Some(message), Some(sp)) => Ok(Some(StateProofTxn {
            message,
            state_proof: sp.to_vec(),
        })),
        _ => Err(Error::Msgpack("state proof transaction without sp/spmsg")),
    }
}

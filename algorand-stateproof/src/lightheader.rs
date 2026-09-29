//! Light block headers and SHA-256 transaction commitments — the data that connects a
//! verified `BlockHeadersCommitment` to an individual transaction. The Solidity contracts
//! perform exactly these computations on-chain.
//!
//! ```text
//! BlockHeadersCommitment = VC_sha256[ SHA256("B256" || msgpack(LightBlockHeader_r)) ]  r in interval
//! LightBlockHeader       = { "0": seed | "1": blockHash, "gh": genesisHash, "r": round, "tc": txn256 }
//! txn256                 = VC_sha256[ SHA256("TL" || SHA256("TX" || txn) || SHA256("STIB" || stib)) ]
//! ```

use crate::hash_id;
use crate::msgpack;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// `bookkeeping.LightBlockHeader`. Since consensus v39 (`StateProofBlockHashInLightHeader`)
/// the header carries `block_hash` and a zero `seed`; before that, `seed` and a zero
/// `block_hash`. Zero fields are omitted from the encoding.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LightBlockHeader {
    pub seed: [u8; 32],
    pub block_hash: [u8; 32],
    pub round: u64,
    pub genesis_hash: [u8; 32],
    pub sha256_txn_commitment: [u8; 32],
}

impl LightBlockHeader {
    /// Canonical msgpack encoding (`protocol.Encode(&lightBlockHeader)`).
    pub fn encode(&self) -> Vec<u8> {
        let nonzero = |b: &[u8; 32]| b.iter().any(|&x| x != 0);
        let has = [
            nonzero(&self.seed),
            nonzero(&self.block_hash),
            nonzero(&self.genesis_hash),
            self.round != 0,
        ];
        let mut out = Vec::with_capacity(160);
        // "tc" is a []byte slice of the 32-byte header field, so it is always present.
        msgpack::write_map_header(&mut out, has.iter().filter(|&&x| x).count() + 1);
        if has[0] {
            msgpack::write_str(&mut out, b"0");
            msgpack::write_bin(&mut out, &self.seed);
        }
        if has[1] {
            msgpack::write_str(&mut out, b"1");
            msgpack::write_bin(&mut out, &self.block_hash);
        }
        if has[2] {
            msgpack::write_str(&mut out, b"gh");
            msgpack::write_bin(&mut out, &self.genesis_hash);
        }
        if has[3] {
            msgpack::write_str(&mut out, b"r");
            msgpack::write_uint(&mut out, self.round);
        }
        msgpack::write_str(&mut out, b"tc");
        msgpack::write_bin(&mut out, &self.sha256_txn_commitment);
        out
    }

    /// Leaf of the block headers commitment: `SHA256("B256" || encode())`.
    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(hash_id::BLOCK_HEADER_256);
        h.update(self.encode());
        h.finalize().into()
    }
}

/// `Transaction.IDSha256()`: `SHA256("TX" || msgpack(txn))`, where `txn` is the canonical
/// encoding of the full transaction (including `gh`/`gen`, which blocks strip).
pub fn txid_sha256(txn_msgpack: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(hash_id::TRANSACTION);
    h.update(txn_msgpack);
    h.finalize().into()
}

/// `SignedTxnInBlock.HashSHA256()`: `SHA256("STIB" || msgpack(stib))`.
pub fn stib_hash_sha256(stib_msgpack: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(hash_id::SIGNED_TXN_IN_BLOCK);
    h.update(stib_msgpack);
    h.finalize().into()
}

/// Leaf of the SHA-256 transaction commitment: `SHA256("TL" || txid256 || stibHash256)`.
pub fn txn_leaf_sha256(txid256: &[u8; 32], stib_hash256: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(hash_id::TXN_MERKLE_LEAF);
    h.update(txid256);
    h.update(stib_hash256);
    h.finalize().into()
}

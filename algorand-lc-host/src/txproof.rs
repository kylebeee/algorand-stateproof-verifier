//! Building transaction inclusion proofs for the Ethereum verifier.
//!
//! Everything is recomputed locally from raw blocks and checked against the commitments in
//! the block header and the state proof message, so the output does not trust the node.

use crate::algod::{encode_algorand_digest, Algod};
use crate::json::{hex0x, LightBlockHeaderJson, TxInclusionJson};
use algorand_stateproof::block::{stib_field, RawBlock};
use algorand_stateproof::hash_id;
use algorand_stateproof::lightclient::STATE_PROOF_INTERVAL;
use algorand_stateproof::lightheader::{
    stib_hash_sha256, txid_sha256, txn_leaf_sha256, LightBlockHeader,
};
use algorand_stateproof::merkle::{sha256_vc_levels, sha256_vc_prove, sha256_vc_root};
use algorand_stateproof::msgpack::{self, Reader};
use anyhow::{bail, ensure, Context, Result};
use base64::Engine;
use sha2::{Digest, Sha512_256};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Consensus versions with state proofs whose light headers carry the seed instead of the
/// block hash (v34..=v38; `StateProofBlockHashInLightHeader` was enabled in v39).
const SEED_LIGHT_HEADER_PROTOCOLS: &[&str] = &[
    "https://github.com/algorandfoundation/specs/tree/2dd5435993f6f6d65691140f592ebca5ef19ffbd",
    "https://github.com/algorandfoundation/specs/tree/433d8e9a7274b6fca703d91213e05c7e6a589e69",
    "https://github.com/algorandfoundation/specs/tree/44fa607d6051730f5264526bf3c108d51f0eadb6",
    "https://github.com/algorandfoundation/specs/tree/1ac4dd1f85470e1fb36c8a65520e1313d7dfed5e",
    "https://github.com/algorandfoundation/specs/tree/abd3d4823c6f77349fc04c3af7b1e99fe4df699f",
];

/// `BlockHeader.Hash()`: SHA512/256("BH" || canonical header).
pub fn block_hash(raw: &RawBlock<'_>) -> [u8; 32] {
    let mut h = Sha512_256::new();
    h.update(hash_id::BLOCK_HEADER);
    h.update(raw.header_bytes());
    h.finalize().into()
}

/// `BlockHeader.ToLightBlockHeader()`.
pub fn light_block_header(raw: &RawBlock<'_>) -> Result<LightBlockHeader> {
    let proto = match raw.header_field(b"proto") {
        Some(v) => String::from_utf8(Reader::new(v).read_str()?.to_vec())?,
        None => String::new(),
    };
    let mut h = LightBlockHeader {
        round: raw.round()?,
        genesis_hash: raw.genesis_hash()?,
        sha256_txn_commitment: raw.sha256_txn_commitment()?,
        ..Default::default()
    };
    if SEED_LIGHT_HEADER_PROTOCOLS.contains(&proto.as_str()) {
        h.seed = raw.seed()?;
    } else {
        h.block_hash = block_hash(raw);
    }
    Ok(h)
}

/// The 256 light block headers of the interval starting at `first_round` (fetched in
/// parallel).
pub fn fetch_interval_light_headers(
    algod: &Algod,
    first_round: u64,
) -> Result<Vec<LightBlockHeader>> {
    let n = STATE_PROOF_INTERVAL as usize;
    let results: Mutex<Vec<Option<LightBlockHeader>>> = Mutex::new(vec![None; n]);
    let next = AtomicUsize::new(0);
    let first_error: Mutex<Option<anyhow::Error>> = Mutex::new(None);
    std::thread::scope(|s| {
        for _ in 0..8 {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= n || first_error.lock().unwrap().is_some() {
                    return;
                }
                let round = first_round + i as u64;
                let res = algod
                    .block_header_msgpack(round)
                    .and_then(|bytes| light_block_header(&RawBlock::parse(&bytes)?));
                match res {
                    Ok(h) => results.lock().unwrap()[i] = Some(h),
                    Err(e) => {
                        first_error
                            .lock()
                            .unwrap()
                            .get_or_insert(e.context(format!("light header {round}")));
                        return;
                    }
                }
            });
        }
    });
    if let Some(e) = first_error.into_inner().unwrap() {
        return Err(e);
    }
    Ok(results
        .into_inner()
        .unwrap()
        .into_iter()
        .map(|h| h.expect("all fetched"))
        .collect())
}

/// Adds the `gen`/`gh` fields that blocks strip from transactions
/// (`Block.DecodeSignedTxn`), producing the canonical `Transaction` encoding.
fn restore_txn(txn: &[u8], genesis_id: Option<&[u8]>, genesis_hash: &[u8; 32]) -> Result<Vec<u8>> {
    let mut r = Reader::new(txn);
    let n = r.read_map_len()?;
    let mut fields: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(n + 2);
    for _ in 0..n {
        let k = r.read_str()?.to_vec();
        fields.push((k, r.raw_value()?.to_vec()));
    }
    ensure!(
        !fields.iter().any(|(k, _)| k == b"gen" || k == b"gh"),
        "block transaction already has gen/gh"
    );
    if let Some(id) = genesis_id {
        let mut v = Vec::new();
        msgpack::write_str(&mut v, id);
        fields.push((b"gen".to_vec(), v));
    }
    let mut v = Vec::new();
    msgpack::write_bin(&mut v, genesis_hash);
    fields.push((b"gh".to_vec(), v));
    fields.sort();
    let mut out = Vec::new();
    msgpack::write_map_header(&mut out, fields.len());
    for (k, v) in fields {
        msgpack::write_str(&mut out, &k);
        out.extend_from_slice(&v);
    }
    Ok(out)
}

/// Builds the inclusion proof of transaction `txid` (base32) confirmed in `round`, and
/// checks it against the state proof message commitment `block_headers_commitment` of the
/// interval containing `round`.
pub fn build_tx_inclusion(
    algod: &Algod,
    round: u64,
    txid: &str,
    block_headers_commitment: &[u8; 32],
) -> Result<TxInclusionJson> {
    let block_bytes = algod.block_msgpack(round)?;
    let block = RawBlock::parse(&block_bytes)?;
    ensure!(
        block.round()? == round,
        "algod returned block {} for {round}",
        block.round()?
    );
    let genesis_hash = block.genesis_hash()?;
    let genesis_id = block.genesis_id()?;

    let mut leaves = Vec::with_capacity(block.txns.len());
    let mut found = None;
    for (i, stib) in block.txns.iter().enumerate() {
        let txn = stib_field(stib, b"txn")?.context("stib without txn")?;
        let hgi = match stib_field(stib, b"hgi")? {
            Some(v) => Reader::new(v).read_bool()?,
            None => false,
        };
        let full = restore_txn(txn, hgi.then_some(genesis_id.as_slice()), &genesis_hash)?;
        let id256 = txid_sha256(&full);
        let stib_hash = stib_hash_sha256(stib);
        leaves.push(txn_leaf_sha256(&id256, &stib_hash));

        let mut h = Sha512_256::new();
        h.update(hash_id::TRANSACTION);
        h.update(&full);
        if encode_algorand_digest(&h.finalize().into()) == txid {
            found = Some((i, full, id256, stib_hash, stib.to_vec()));
        }
    }
    let (tx_index, txn, id256, stib_hash, stib) = found.with_context(|| {
        format!("transaction {txid} is not a top-level transaction of block {round}")
    })?;

    let tx_levels = sha256_vc_levels(&leaves);
    ensure!(
        tx_levels.last().unwrap()[0] == block.sha256_txn_commitment()?,
        "recomputed txn256 commitment does not match block {round}"
    );
    let tx_proof = sha256_vc_prove(&tx_levels, tx_index as u64);
    let tx_depth = (tx_levels.len() - 1) as u8;

    // Cross-check against algod's own proof when available.
    if let Ok(api) = algod.tx_proof_sha256(round, txid) {
        let api_proof = base64::engine::general_purpose::STANDARD.decode(&api.proof)?;
        ensure!(
            api.idx == tx_index as u64 && api.treedepth == tx_depth,
            "algod tx proof index/depth disagree"
        );
        ensure!(
            api_proof == tx_proof.concat(),
            "algod tx proof path disagrees"
        );
        ensure!(
            base64::engine::general_purpose::STANDARD.decode(&api.stibhash)? == stib_hash,
            "algod stibhash disagrees"
        );
    }

    let first = crate::fetch::interval_first_round(round);
    let headers = fetch_interval_light_headers(algod, first)?;
    let header_leaves: Vec<[u8; 32]> = headers.iter().map(LightBlockHeader::leaf_hash).collect();
    let header_levels = sha256_vc_levels(&header_leaves);
    if header_levels.last().unwrap()[0] != *block_headers_commitment {
        bail!("recomputed block headers commitment for [{first}, {}] does not match the state proof message", first + 255);
    }
    let header_index = round - first;
    let header_proof = sha256_vc_prove(&header_levels, header_index);
    let header = &headers[header_index as usize];
    ensure!(
        block_hash(&block) == header.block_hash || header.block_hash == [0u8; 32],
        "block hash mismatch"
    );

    // Final self-check with the same computation the contract performs.
    let leaf = txn_leaf_sha256(&txid_sha256(&txn), &stib_hash);
    ensure!(
        sha256_vc_root(leaf, tx_index as u64, tx_depth, &tx_proof)? == header.sha256_txn_commitment
    );
    ensure!(
        sha256_vc_root(header.leaf_hash(), header_index, 8, &header_proof)?
            == *block_headers_commitment
    );

    Ok(TxInclusionJson {
        txid: txid.to_string(),
        txn: hex0x(&txn),
        txid_sha256: hex0x(&id256),
        stib_hash: hex0x(&stib_hash),
        stib: hex0x(&stib),
        tx_index: tx_index as u64,
        tx_tree_depth: tx_depth,
        tx_proof: tx_proof.iter().map(|s| hex0x(s)).collect(),
        header: LightBlockHeaderJson::from(header),
        header_index,
        header_proof: header_proof.iter().map(|s| hex0x(s)).collect(),
        interval_first_round: first,
        interval_last_round: first + STATE_PROOF_INTERVAL - 1,
        block_headers_commitment: hex0x(block_headers_commitment),
    })
}

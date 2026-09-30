//! C ABI over the Rust verifier for the differential tests. Every function takes raw bytes, so
//! decoding is compared too. Status codes: 0 = accepted, 1 = rejected while decoding,
//! 2 = rejected by verification; `aln_last_error` returns the Rust error text.

use algorand_stateproof::coins::CoinGenerator;
use algorand_stateproof::decode::decode_state_proof;
use algorand_stateproof::falcon::{verify_compressed, DetSignature};
use algorand_stateproof::lightheader::{
    stib_hash_sha256, txid_sha256, txn_leaf_sha256, LightBlockHeader,
};
use algorand_stateproof::msgpack::Reader;
use algorand_stateproof::weights::verify_weights;
use algorand_stateproof::{verify_state_proof, StateProofMessage, Sumhash512};
use std::cell::RefCell;
use std::slice;
use std::sync::OnceLock;

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

fn sumhash() -> &'static Sumhash512 {
    static SH: OnceLock<Sumhash512> = OnceLock::new();
    SH.get_or_init(Sumhash512::new)
}

fn set_error(e: impl std::fmt::Display) {
    LAST_ERROR.with(|l| *l.borrow_mut() = e.to_string());
}

unsafe fn bytes<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        slice::from_raw_parts(p, len)
    }
}

/// Copies the last error text into `buf`; returns its full length.
#[no_mangle]
pub unsafe extern "C" fn aln_last_error(buf: *mut u8, cap: usize) -> usize {
    LAST_ERROR.with(|l| {
        let s = l.borrow();
        let n = s.len().min(cap);
        if n > 0 {
            std::ptr::copy_nonoverlapping(s.as_ptr(), buf, n);
        }
        s.len()
    })
}

/// `decode_state_proof` + `verify_state_proof`, i.e. go-algorand's
/// `protocol.Decode(&StateProof)` + `MkVerifierWithLnProvenWeight(..).Verify(round, hash, sp)`.
#[no_mangle]
pub unsafe extern "C" fn aln_sp_verify(
    voters: *const u8,
    voters_len: usize,
    ln_proven_weight: u64,
    strength_target: u64,
    round: u64,
    msg_hash: *const u8,
    sp: *const u8,
    sp_len: usize,
) -> i32 {
    let sp = match decode_state_proof(bytes(sp, sp_len)) {
        Ok(sp) => sp,
        Err(e) => {
            set_error(e);
            return 1;
        }
    };
    let hash: &[u8; 32] = &*(msg_hash as *const [u8; 32]);
    match verify_state_proof(
        sumhash(),
        bytes(voters, voters_len),
        ln_proven_weight,
        strength_target,
        round,
        hash,
        &sp,
    ) {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            2
        }
    }
}

/// Decodes only (status 0 or 1).
#[no_mangle]
pub unsafe extern "C" fn aln_sp_decode(sp: *const u8, sp_len: usize) -> i32 {
    match decode_state_proof(bytes(sp, sp_len)) {
        Ok(_) => 0,
        Err(e) => {
            set_error(e);
            1
        }
    }
}

/// `stateproofmsg.Message` from msgpack, then `Hash()` into `out` (32 bytes).
#[no_mangle]
pub unsafe extern "C" fn aln_msg_decode_hash(msg: *const u8, len: usize, out: *mut u8) -> i32 {
    let data = bytes(msg, len);
    let mut r = Reader::new(data);
    match StateProofMessage::decode(&mut r) {
        Ok(m) if r.is_at_end() => {
            std::ptr::copy_nonoverlapping(m.hash().as_ptr(), out, 32);
            0
        }
        Ok(_) => {
            set_error("trailing bytes after message");
            1
        }
        Err(e) => {
            set_error(e);
            1
        }
    }
}

/// `Message.Hash()` from fields (as the light client builds it from a block).
#[no_mangle]
pub unsafe extern "C" fn aln_msg_hash(
    bhc: *const u8,
    bhc_len: usize,
    voters: *const u8,
    voters_len: usize,
    ln_proven_weight: u64,
    first: u64,
    last: u64,
    out: *mut u8,
) {
    let m = StateProofMessage {
        block_headers_commitment: bytes(bhc, bhc_len).to_vec(),
        voters_commitment: bytes(voters, voters_len).to_vec(),
        ln_proven_weight,
        first_attested_round: first,
        last_attested_round: last,
    };
    std::ptr::copy_nonoverlapping(m.hash().as_ptr(), out, 32);
}

/// `verifyWeights` (status 0 or 2).
#[no_mangle]
pub extern "C" fn aln_verify_weights(signed: u64, ln_pw: u64, num_reveals: u64, strength: u64) -> i32 {
    match verify_weights(signed, ln_pw, num_reveals, strength) {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            2
        }
    }
}

/// The first `n` coins of `makeCoinGenerator(coinChoiceSeed{..})`. `signed` must be non-zero.
#[no_mangle]
pub unsafe extern "C" fn aln_coins(
    voters: *const u8,
    voters_len: usize,
    ln_pw: u64,
    sig_commit: *const u8,
    sig_commit_len: usize,
    signed: u64,
    msg_hash: *const u8,
    n: usize,
    out: *mut u64,
) {
    let mut g = CoinGenerator::new(
        bytes(voters, voters_len),
        ln_pw,
        bytes(sig_commit, sig_commit_len),
        signed,
        &*(msg_hash as *const [u8; 32]),
    );
    for i in 0..n {
        *out.add(i) = g.next_coin();
    }
}

/// Sumhash512 (unsalted), 64 bytes into `out`.
#[no_mangle]
pub unsafe extern "C" fn aln_sumhash512(data: *const u8, len: usize, out: *mut u8) {
    let d = sumhash().hash(&[bytes(data, len)]);
    std::ptr::copy_nonoverlapping(d.as_ptr(), out, 64);
}

/// `PublicKey.Verify(CompressedSignature, msg)` (status 0 or 2).
#[no_mangle]
pub unsafe extern "C" fn aln_falcon_verify(
    pk: *const u8,
    pk_len: usize,
    sig: *const u8,
    sig_len: usize,
    msg: *const u8,
    msg_len: usize,
) -> i32 {
    match verify_compressed(bytes(pk, pk_len), bytes(sig, sig_len), bytes(msg, msg_len)) {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            2
        }
    }
}

/// `CompressedSignature.ConvertToCT()` into `out` (1538 bytes); status 0 or 1.
#[no_mangle]
pub unsafe extern "C" fn aln_falcon_to_ct(sig: *const u8, sig_len: usize, out: *mut u8) -> i32 {
    match DetSignature::decode_compressed(bytes(sig, sig_len)) {
        Ok(d) => {
            let ct = d.to_ct();
            std::ptr::copy_nonoverlapping(ct.as_ptr(), out, ct.len());
            0
        }
        Err(e) => {
            set_error(e);
            1
        }
    }
}

/// `LightBlockHeader` leaf hash, `SHA256("B256" || encode())`.
#[no_mangle]
pub unsafe extern "C" fn aln_light_header_leaf(
    seed: *const u8,
    block_hash: *const u8,
    round: u64,
    genesis_hash: *const u8,
    txn_commitment: *const u8,
    out: *mut u8,
) {
    let h = LightBlockHeader {
        seed: *(seed as *const [u8; 32]),
        block_hash: *(block_hash as *const [u8; 32]),
        round,
        genesis_hash: *(genesis_hash as *const [u8; 32]),
        sha256_txn_commitment: *(txn_commitment as *const [u8; 32]),
    };
    std::ptr::copy_nonoverlapping(h.leaf_hash().as_ptr(), out, 32);
}

/// Transaction commitment leaf `SHA256("TL" || SHA256("TX"||txn) || SHA256("STIB"||stib))`.
#[no_mangle]
pub unsafe extern "C" fn aln_txn_leaf(
    txn: *const u8,
    txn_len: usize,
    stib: *const u8,
    stib_len: usize,
    out: *mut u8,
) {
    let leaf = txn_leaf_sha256(
        &txid_sha256(bytes(txn, txn_len)),
        &stib_hash_sha256(bytes(stib, stib_len)),
    );
    std::ptr::copy_nonoverlapping(leaf.as_ptr(), out, 32);
}

/// `algorand-lc-host`'s `ln_int_approximation` (used to derive anchors); status 0 or 2.
#[no_mangle]
pub unsafe extern "C" fn aln_ln_int_approximation(x: u64, out: *mut u64) -> i32 {
    match algorand_lc_host::history::ln_int_approximation(x) {
        Ok(v) => {
            *out = v;
            0
        }
        Err(e) => {
            set_error(e);
            2
        }
    }
}

/// `algorand-lc-host`'s proven weight: `total * WEIGHT_THRESHOLD >> 32` (as in anchor_from_header).
#[no_mangle]
pub extern "C" fn aln_proven_weight(total: u64) -> u64 {
    (total as u128 * algorand_lc_host::history::WEIGHT_THRESHOLD as u128 >> 32) as u64
}

/// `sha256_vc_root(leaf, index, depth, siblings)` (how the light node checks transaction and
/// header paths); `siblings` is `n` concatenated 32-byte hashes. Status 0 (root in `out`) or 2.
#[no_mangle]
pub unsafe extern "C" fn aln_sha256_vc_root(
    leaf: *const u8,
    index: u64,
    depth: u8,
    siblings: *const u8,
    n: usize,
    out: *mut u8,
) -> i32 {
    let path: Vec<[u8; 32]> = bytes(siblings, n * 32)
        .chunks_exact(32)
        .map(|c| c.try_into().unwrap())
        .collect();
    match algorand_stateproof::merkle::sha256_vc_root(*(leaf as *const [u8; 32]), index, depth, &path) {
        Ok(root) => {
            std::ptr::copy_nonoverlapping(root.as_ptr(), out, 32);
            0
        }
        Err(e) => {
            set_error(e);
            2
        }
    }
}

/// The light block header leaf of a raw algod block (full or header-only msgpack), via
/// `algorand-lc-host::txproof::light_block_header`. Status 0 or 1.
#[no_mangle]
pub unsafe extern "C" fn aln_block_light_header_leaf(block: *const u8, len: usize, out: *mut u8) -> i32 {
    let raw = match algorand_stateproof::block::RawBlock::parse(bytes(block, len)) {
        Ok(r) => r,
        Err(e) => {
            set_error(e);
            return 1;
        }
    };
    match algorand_lc_host::txproof::light_block_header(&raw) {
        Ok(h) => {
            std::ptr::copy_nonoverlapping(h.leaf_hash().as_ptr(), out, 32);
            0
        }
        Err(e) => {
            set_error(e);
            1
        }
    }
}

/// The state proof transaction for the interval starting at `first` in a raw block, as the
/// light node extracts it (`RawBlock::state_proof_txns`): its message hash and the SHA-256 of
/// its proof bytes. Status 0, 1 (parse error) or 3 (no such transaction).
#[no_mangle]
pub unsafe extern "C" fn aln_block_stpf(
    block: *const u8,
    len: usize,
    first: u64,
    out_msg_hash: *mut u8,
    out_proof_sha256: *mut u8,
) -> i32 {
    use sha2::{Digest, Sha256};
    let txns = match algorand_stateproof::block::RawBlock::parse(bytes(block, len))
        .and_then(|b| b.state_proof_txns())
    {
        Ok(t) => t,
        Err(e) => {
            set_error(e);
            return 1;
        }
    };
    match txns.into_iter().find(|t| t.message.first_attested_round == first) {
        Some(t) => {
            std::ptr::copy_nonoverlapping(t.message.hash().as_ptr(), out_msg_hash, 32);
            let h: [u8; 32] = Sha256::digest(&t.state_proof).into();
            std::ptr::copy_nonoverlapping(h.as_ptr(), out_proof_sha256, 32);
            0
        }
        None => 3,
    }
}

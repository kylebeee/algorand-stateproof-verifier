//! Recovering state proofs from the network.
//!
//! algod's `/v2/stateproofs/{round}` only searches recent blocks, so we locate the state
//! proof transaction with the indexer and read it from the (archival) block itself.

use crate::algod::{Algod, Indexer, StateProofLocation};
use crate::json::StateProofTxnJson;
use algorand_stateproof::block::{RawBlock, StateProofTxn};
use algorand_stateproof::lightclient::STATE_PROOF_INTERVAL;
use anyhow::{bail, Context, Result};

/// Fetches the state proofs of `count` consecutive intervals, the first one starting at
/// `first_round`.
pub fn fetch_state_proofs(
    algod: &Algod,
    indexer: &Indexer,
    first_round: u64,
    count: usize,
) -> Result<Vec<StateProofTxnJson>> {
    let out = fetch_available_state_proofs(algod, indexer, first_round, count)?;
    if out.len() < count {
        bail!(
            "only {} of {count} state proofs from round {first_round} are available yet",
            out.len()
        );
    }
    Ok(out)
}

/// Fetches up to `max` consecutive state proofs starting at `first_round`, stopping at the
/// newest one posted so far.
pub fn fetch_available_state_proofs(
    algod: &Algod,
    indexer: &Indexer,
    first_round: u64,
    max: usize,
) -> Result<Vec<StateProofTxnJson>> {
    // The proof for [F, F + 255] can only be confirmed after round F + 255, and in practice
    // lands ~135-150 rounds after that; allow generous slack for delayed proofs.
    let min_round = first_round + STATE_PROOF_INTERVAL - 1;
    let max_round = min_round + (max as u64 + 8) * STATE_PROOF_INTERVAL;
    let locations = if indexer.is_enabled() {
        indexer.state_proof_txns(min_round, max_round, max + 8)?
    } else {
        locate_from_headers(algod, first_round, max)?
    };
    let mut out = Vec::with_capacity(max);
    let mut expected = first_round;
    for loc in locations {
        if out.len() == max {
            break;
        }
        if loc.first_attested_round < expected {
            continue;
        }
        if loc.first_attested_round != expected {
            bail!(
                "no state proof for the interval starting at {expected} (next one starts at {})",
                loc.first_attested_round
            );
        }
        let block = algod.block_msgpack(loc.confirmed_round)?;
        let txn = RawBlock::parse(&block)?
            .state_proof_txns()?
            .into_iter()
            .find(|t| t.message.first_attested_round == expected)
            .with_context(|| {
                format!(
                    "block {} has no state proof for round {expected}",
                    loc.confirmed_round
                )
            })?;
        out.push(StateProofTxnJson::new(loc.confirmed_round, &txn));
        expected = txn.message.last_attested_round + 1;
    }
    Ok(out)
}

/// Locates up to `max` consecutive state proof transactions from block headers alone: the block
/// that includes the proof for an interval ending at `E` is the first whose header expects the
/// next proof beyond `E` (`spt[0].n > E`). Proofs are accepted no earlier than `E + 128`.
fn locate_from_headers(algod: &Algod, first_round: u64, max: usize) -> Result<Vec<StateProofLocation>> {
    let tip = algod.last_round()?;
    let mut out = Vec::new();
    let mut last = first_round + STATE_PROOF_INTERVAL - 1;
    while out.len() < max {
        let mut r = last + STATE_PROOF_INTERVAL / 2;
        let found = loop {
            if r > tip {
                break None;
            }
            match algod.next_state_proof_round(r)? {
                Some(n) if n > last => break Some(r),
                _ => r += 1,
            }
        };
        let Some(confirmed_round) = found else { break };
        out.push(StateProofLocation {
            confirmed_round,
            first_attested_round: last + 1 - STATE_PROOF_INTERVAL,
            last_attested_round: last,
        });
        last += STATE_PROOF_INTERVAL;
    }
    Ok(out)
}

/// The signed message of the interval starting at `first_round`.
pub fn fetch_interval_message(
    algod: &Algod,
    indexer: &Indexer,
    first_round: u64,
) -> Result<StateProofTxn> {
    fetch_state_proofs(algod, indexer, first_round, 1)?
        .remove(0)
        .to_txn()
}

/// First round of the interval containing `round`.
pub fn interval_first_round(round: u64) -> u64 {
    (round - 1) / STATE_PROOF_INTERVAL * STATE_PROOF_INTERVAL + 1
}

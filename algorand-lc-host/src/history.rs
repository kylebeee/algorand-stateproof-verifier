//! Anchoring at the very first state proof, and walking the whole history from there.
//!
//! Every block whose round is a multiple of 256 carries, in its `spt` header field, a
//! commitment to the top voters (`v`) and their total weight (`t`). The voters committed at
//! round `R` sign the state proof of the interval `[R + 1, R + 256]`. The first such commitment
//! (mainnet round 23,591,936, September 2022) is therefore a trust anchor that is the same for
//! everyone and can be checked against any archival node, unlike an anchor picked at deploy time.

use crate::algod::Algod;
use algorand_stateproof::lightclient::{TrustedState, STATE_PROOF_INTERVAL};
use anyhow::{bail, ensure, Context, Result};
use base64::Engine;

/// `StateProofWeightThreshold` (consensus v34+): 30% of the top voters' weight, as a fraction of
/// 2^32.
pub const WEIGHT_THRESHOLD: u64 = (1u64 << 32) * 30 / 100;

/// go-algorand's `stateproof.LnIntApproximation`: `ceil(ln(x) * 2^16)`, computed in float64.
pub fn ln_int_approximation(x: u64) -> Result<u64> {
    ensure!(x > 0, "proven weight is zero");
    Ok(((x as f64).ln() * 65536.0).ceil() as u64)
}

/// The voters commitment and total weight a block header commits to (`spt[0]`), if any.
pub fn voters_at(algod: &Algod, round: u64) -> Result<Option<([u8; 64], u64)>> {
    let header = algod.block_header_json(round)?;
    let spt = &header["block"]["spt"]["0"];
    let (Some(v), Some(t)) = (spt["v"].as_str(), spt["t"].as_u64()) else {
        return Ok(None);
    };
    let v = base64::engine::general_purpose::STANDARD
        .decode(v)
        .context("voters commitment is not base64")?;
    let v: [u8; 64] = v
        .try_into()
        .map_err(|_| anyhow::anyhow!("voters commitment at round {round} is not 64 bytes"))?;
    Ok(Some((v, t)))
}

/// Trusted state for the interval signed by the voters committed in block `voters_round`.
pub fn anchor_from_header(algod: &Algod, voters_round: u64) -> Result<TrustedState> {
    ensure!(
        voters_round % STATE_PROOF_INTERVAL == 0,
        "voters are committed only in rounds that are multiples of {STATE_PROOF_INTERVAL}"
    );
    let (voters_commitment, total_weight) = voters_at(algod, voters_round)?
        .with_context(|| format!("block {voters_round} commits to no voters"))?;
    let proven_weight = (total_weight as u128 * WEIGHT_THRESHOLD as u128 >> 32) as u64;
    Ok(TrustedState {
        voters_commitment,
        ln_proven_weight: ln_int_approximation(proven_weight)?,
        next_round: voters_round + 1,
    })
}

/// The first round whose header commits to voters: where the state proof chain begins.
pub fn first_voters_round(algod: &Algod) -> Result<u64> {
    let tip = algod.last_round()? / STATE_PROOF_INTERVAL * STATE_PROOF_INTERVAL;
    if voters_at(algod, tip)?.is_none() {
        bail!("round {tip} commits to no voters; state proofs are not enabled on this network");
    }
    // Binary search over interval boundaries; `hi` always commits to voters.
    let (mut lo, mut hi) = (0u64, tip / STATE_PROOF_INTERVAL);
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        if voters_at(algod, mid * STATE_PROOF_INTERVAL)?.is_some() {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    Ok(hi * STATE_PROOF_INTERVAL)
}

/// One verified interval, as recorded by [`verify_history`] (one JSON object per line).
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryInterval {
    pub first_attested_round: u64,
    pub last_attested_round: u64,
    pub block_headers_commitment: String,
    /// Round of the block that carried the state proof transaction.
    pub confirmed_round: u64,
}

/// Progress of a [`verify_history`] run, so it can resume where it stopped.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryCheckpoint {
    /// The state the walk started from (e.g. the genesis anchor).
    pub anchor: crate::json::TrustedStateJson,
    /// The state after the last verified interval.
    pub state: crate::json::TrustedStateJson,
    pub intervals_verified: u64,
}

pub struct HistoryOptions {
    /// Stop once the next interval would start after this round.
    pub to_round: u64,
    /// Concurrent block downloads.
    pub jobs: usize,
    /// Intervals located and fetched per indexer query.
    pub chunk: usize,
}

/// Verifies every state proof from `checkpoint.state` onward, natively, appending each verified
/// interval to `intervals` (JSON lines) and saving `checkpoint` after every chunk.
pub fn verify_history(
    algod: &Algod,
    indexer: &crate::algod::Indexer,
    checkpoint_path: &std::path::Path,
    intervals_path: &std::path::Path,
    mut checkpoint: HistoryCheckpoint,
    opts: &HistoryOptions,
) -> Result<HistoryCheckpoint> {
    use crate::json::{hex0x, write_json};
    use algorand_stateproof::block::RawBlock;
    use algorand_stateproof::lightclient::apply_state_proof;
    use std::io::Write;

    let sh = algorand_stateproof::Sumhash512::new();
    let mut out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(intervals_path)
        .with_context(|| format!("opening {}", intervals_path.display()))?;
    let mut state = TrustedState::try_from(&checkpoint.state)?;
    let started = std::time::Instant::now();
    let mut done_this_run = 0u64;

    while state.next_round + STATE_PROOF_INTERVAL - 1 <= opts.to_round {
        // Locate the next chunk of state proof transactions.
        let min_round = state.next_round + STATE_PROOF_INTERVAL - 1;
        let max_round = min_round + (opts.chunk as u64 + 8) * STATE_PROOF_INTERVAL;
        let mut expected = state.next_round;
        let mut wanted = Vec::new();
        for loc in patiently(|| indexer.state_proof_txns(min_round, max_round, opts.chunk + 8))? {
            if wanted.len() == opts.chunk || loc.first_attested_round > opts.to_round {
                break;
            }
            if loc.first_attested_round < expected {
                continue; // a duplicate or late proof of an interval we already have
            }
            ensure!(
                loc.first_attested_round == expected,
                "no state proof for the interval starting at {expected} (next one starts at {})",
                loc.first_attested_round
            );
            wanted.push(loc);
            expected = loc.last_attested_round + 1;
        }
        if wanted.is_empty() {
            // Nothing in the window: either we caught up with the chain, or there is a gap.
            ensure!(
                max_round >= opts.to_round,
                "no state proof for the interval starting at {} confirmed in rounds {min_round}..={max_round}",
                state.next_round
            );
            break;
        }

        // Download the blocks carrying them, `jobs` at a time.
        let blocks: Vec<Result<Vec<u8>>> = std::thread::scope(|s| {
            let per = wanted.len().div_ceil(opts.jobs.max(1));
            let handles: Vec<_> = wanted
                .chunks(per)
                .map(|part| {
                    s.spawn(move || {
                        part.iter()
                            .map(|l| patiently(|| algod.block_msgpack(l.confirmed_round)))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().expect("download thread panicked"))
                .collect()
        });

        // Verify in order, each on top of the state the previous one established.
        for (loc, block) in wanted.iter().zip(blocks) {
            let block = block?;
            let txn = RawBlock::parse(&block)?
                .state_proof_txns()?
                .into_iter()
                .find(|t| t.message.first_attested_round == state.next_round)
                .with_context(|| {
                    format!("block {} has no state proof for round {}", loc.confirmed_round, state.next_round)
                })?;
            let (next, interval) = apply_state_proof(&sh, &state, &txn).with_context(|| {
                format!("state proof for the interval starting at {} does not verify", state.next_round)
            })?;
            let line = HistoryInterval {
                first_attested_round: interval.first_attested_round,
                last_attested_round: interval.last_attested_round,
                block_headers_commitment: hex0x(&interval.block_headers_commitment),
                confirmed_round: loc.confirmed_round,
            };
            writeln!(out, "{}", serde_json::to_string(&line)?)?;
            state = next;
            checkpoint.intervals_verified += 1;
            done_this_run += 1;
        }
        out.flush()?;
        checkpoint.state = (&state).into();
        write_json(checkpoint_path, &checkpoint)?;

        let rate = done_this_run as f64 / started.elapsed().as_secs_f64();
        let left = opts.to_round.saturating_sub(state.next_round) / STATE_PROOF_INTERVAL;
        eprintln!(
            "verified {} intervals, now at round {} ({rate:.1}/s, ~{:.0} min left)",
            checkpoint.intervals_verified,
            state.next_round,
            left as f64 / rate.max(1e-9) / 60.0
        );
    }
    Ok(checkpoint)
}

/// Retries network calls through outages of up to ~15 minutes (public APIs return sporadic 500s
/// during long walks). Only fetching is retried; verification failures are never retried.
fn patiently<T>(mut f: impl FnMut() -> Result<T>) -> Result<T> {
    let mut wait = 5;
    for _ in 0..8 {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) => {
                eprintln!("fetch failed, retrying in {wait}s: {e:#}");
                std::thread::sleep(std::time::Duration::from_secs(wait));
                wait = (wait * 2).min(300);
            }
        }
    }
    f()
}

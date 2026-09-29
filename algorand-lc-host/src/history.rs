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
    reconcile_intervals(intervals_path, &checkpoint)?;
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

/// Makes `intervals` agree with `checkpoint` before appending to it.
///
/// Lines are written as intervals verify, but the checkpoint is saved once per chunk, so a walk
/// stopped mid-chunk leaves lines past the checkpoint that the resumed walk would append again.
/// This drops those (and duplicates left by earlier versions), checks the remaining intervals are
/// contiguous and match the checkpoint's count, and rewrites the file atomically if it changed.
fn reconcile_intervals(path: &std::path::Path, checkpoint: &HistoryCheckpoint) -> Result<()> {
    let Ok(text) = std::fs::read_to_string(path) else {
        ensure!(checkpoint.intervals_verified == 0, "{} is missing", path.display());
        return Ok(());
    };
    let anchor_round = checkpoint.anchor.next_round;
    let state_round = checkpoint.state.next_round;
    let mut kept = Vec::new();
    let mut expected = anchor_round;
    let mut lines = 0u64;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        lines += 1;
        let interval: HistoryInterval = serde_json::from_str(line)
            .with_context(|| format!("{}: malformed line {lines}", path.display()))?;
        if interval.first_attested_round < expected || interval.first_attested_round >= state_round {
            continue; // a duplicate, or verified after the last saved checkpoint
        }
        ensure!(
            interval.first_attested_round == expected,
            "{}: missing the interval starting at {expected}",
            path.display()
        );
        expected = interval.last_attested_round + 1;
        kept.push(line);
    }
    ensure!(
        expected == state_round && kept.len() as u64 == checkpoint.intervals_verified,
        "{} has {} intervals up to round {expected}, but the checkpoint says {} up to {state_round}",
        path.display(),
        kept.len(),
        checkpoint.intervals_verified
    );
    if kept.len() as u64 != lines {
        eprintln!(
            "{}: dropped {} duplicate or unsaved line(s)",
            path.display(),
            lines - kept.len() as u64
        );
        let tmp = path.with_extension("jsonl.tmp");
        std::fs::write(&tmp, kept.join("\n") + "\n")?;
        std::fs::rename(&tmp, path)?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::TrustedStateJson;

    fn state(next_round: u64) -> TrustedStateJson {
        TrustedStateJson { voters_commitment: format!("0x{}", "00".repeat(64)), ln_proven_weight: 1, next_round }
    }

    fn line(first: u64) -> String {
        format!(
            r#"{{"firstAttestedRound":{first},"lastAttestedRound":{},"blockHeadersCommitment":"0x{first:064x}","confirmedRound":{}}}"#,
            first + 255,
            first + 400
        )
    }

    #[test]
    fn reconcile_drops_duplicates_and_unsaved_lines() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("algo-lc-reconcile-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("intervals.jsonl");
        // Checkpoint covers 3 intervals from 257; the file repeats one and has 2 unsaved lines.
        let checkpoint = HistoryCheckpoint { anchor: state(257), state: state(257 + 3 * 256), intervals_verified: 3 };
        let firsts = [257, 513, 513, 769, 1025, 1281];
        std::fs::write(&path, firsts.map(line).join("\n") + "\n")?;
        reconcile_intervals(&path, &checkpoint)?;
        assert_eq!(std::fs::read_to_string(&path)?, [257, 513, 769].map(line).join("\n") + "\n");

        // A file missing an interval the checkpoint claims is an error, not silently accepted.
        std::fs::write(&path, [257, 769].map(line).join("\n") + "\n")?;
        assert!(reconcile_intervals(&path, &checkpoint).is_err());
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}

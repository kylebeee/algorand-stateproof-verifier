//! `algo-lc`: host tooling for the Algorand state proof light client.
//!
//! ```text
//! algo-lc latest                                   # newest interval with a posted state proof
//! algo-lc anchor --interval-first-round F --out state.json
//! algo-lc anchor --genesis --out genesis.json             # the first state proof's voters
//! algo-lc verify-history --anchor genesis.json --dir history/mainnet
//! algo-lc fetch --state state.json --count 4 --out input.json
//! algo-lc verify --input input.json --out output.json   # native run of the zkVM statement
//! algo-lc tx-proof --round R --txid TXID --out tx.json
//! ```

use algorand_lc_host::algod::{Algod, Indexer, MAINNET_ALGOD, MAINNET_INDEXER};
use algorand_lc_host::fetch::{
    fetch_available_state_proofs, fetch_interval_message, fetch_state_proofs, interval_first_round,
};
use algorand_lc_host::json::{
    hex0x, read_json, unhex_n, write_json, IntervalJson, LightClientInput, LightClientOutput,
    TrustedStateJson,
};
use algorand_lc_host::history;
use algorand_lc_host::txproof::build_tx_inclusion;
use algorand_stateproof::block::RawBlock;
use algorand_stateproof::lightclient::{apply_state_proofs, TrustedState};
use algorand_stateproof::sol::encode_update;
use algorand_stateproof::Sumhash512;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser)]
#[command(version, about = "Algorand state proof light client tooling")]
struct Cli {
    /// algod REST endpoint (must serve archival blocks for old rounds).
    #[arg(long, env = "ALGOD_URL", default_value = MAINNET_ALGOD, global = true)]
    algod: String,
    #[arg(long, env = "ALGOD_TOKEN", global = true)]
    algod_token: Option<String>,
    /// Indexer endpoint, used to locate state proof transactions.
    #[arg(long, env = "INDEXER_URL", default_value = MAINNET_INDEXER, global = true)]
    indexer: String,
    #[arg(long, env = "INDEXER_TOKEN", global = true)]
    indexer_token: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the newest interval whose state proof has been posted on-chain.
    Latest,
    /// Trusted state to start a light client from. With `--interval-first-round`, the state
    /// established by that interval's (signed) message; with `--voters-round`, the voters a
    /// block header commits to; with `--genesis`, the first voters commitment on the network,
    /// which the very first state proof is checked against. Verify anchors out of band.
    Anchor {
        #[arg(long, required_unless_present_any = ["voters_round", "genesis"])]
        interval_first_round: Option<u64>,
        #[arg(long, conflicts_with_all = ["interval_first_round", "genesis"])]
        voters_round: Option<u64>,
        #[arg(long, conflicts_with = "interval_first_round")]
        genesis: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify every state proof from an anchor to the chain tip (or `--to-round`) natively.
    /// Resumable: progress lives in `<dir>/checkpoint.json`, verified intervals are appended to
    /// `<dir>/intervals.jsonl`.
    VerifyHistory {
        /// Trusted state to start from (used only when `<dir>` has no checkpoint yet).
        #[arg(long)]
        anchor: Option<PathBuf>,
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        to_round: Option<u64>,
        /// Concurrent block downloads.
        #[arg(long, default_value_t = 4)]
        jobs: usize,
        /// Intervals per indexer query.
        #[arg(long, default_value_t = 32)]
        chunk: usize,
    },
    /// Fetch consecutive state proofs following a trusted state: exactly `--count`, or with
    /// `--all` every one posted so far (up to `--max`).
    Fetch {
        #[arg(long)]
        state: PathBuf,
        #[arg(long, default_value_t = 1, conflicts_with = "all")]
        count: usize,
        #[arg(long)]
        all: bool,
        #[arg(long, default_value_t = 32)]
        max: usize,
        #[arg(long)]
        out: PathBuf,
    },
    /// Run the light client natively over an input file (exactly what the zkVM proves) and
    /// print the ABI-encoded public values.
    Verify {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print the raw `SignedTxnInBlock` (signature, txn and apply data such as logs) at `index`
    /// in block `round`, exactly as committed in the block.
    Stib {
        #[arg(long)]
        round: u64,
        #[arg(long, default_value_t = 0)]
        index: usize,
    },
    /// Build an Ethereum inclusion proof for a top-level transaction.
    TxProof {
        #[arg(long)]
        round: u64,
        #[arg(long)]
        txid: String,
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let algod = Algod::new(&cli.algod, cli.algod_token.clone());
    let indexer = Indexer::with_token(&cli.indexer, cli.indexer_token.clone());

    match cli.cmd {
        Cmd::Latest => {
            let last = algod.last_round()?;
            let locs = indexer.state_proof_txns(last.saturating_sub(1500), last, 20)?;
            let latest = locs.last().context("no recent state proof transactions")?;
            println!(
                "latest state proof: rounds [{}, {}] confirmed in round {} (chain tip {last})",
                latest.first_attested_round, latest.last_attested_round, latest.confirmed_round
            );
        }
        Cmd::Anchor {
            interval_first_round,
            voters_round,
            genesis,
            out,
        } => {
            let state = if let Some(first) = interval_first_round {
                let txn = fetch_interval_message(&algod, &indexer, first)?;
                eprintln!(
                    "anchor from interval [{}, {}], block headers commitment {}",
                    txn.message.first_attested_round,
                    txn.message.last_attested_round,
                    hex0x(&txn.message.block_headers_commitment)
                );
                TrustedState::from_message(&txn.message)?
            } else {
                let round = match voters_round {
                    Some(r) => r,
                    None => history::first_voters_round(&algod)?,
                };
                eprintln!(
                    "anchor from the voters committed in block {round}{}",
                    if genesis { " (the first voters commitment)" } else { "" }
                );
                history::anchor_from_header(&algod, round)?
            };
            let json = TrustedStateJson::from(&state);
            match out {
                Some(path) => write_json(&path, &json)?,
                None => println!("{}", serde_json::to_string_pretty(&json)?),
            }
        }
        Cmd::VerifyHistory {
            anchor,
            dir,
            to_round,
            jobs,
            chunk,
        } => {
            std::fs::create_dir_all(&dir)?;
            let checkpoint_path = dir.join("checkpoint.json");
            let checkpoint = if checkpoint_path.exists() {
                read_json(&checkpoint_path)?
            } else {
                let anchor: TrustedStateJson =
                    read_json(&anchor.context("--anchor is needed to start a new history")?)?;
                history::HistoryCheckpoint {
                    state: anchor.clone(),
                    anchor,
                    intervals_verified: 0,
                }
            };
            let to_round = match to_round {
                Some(r) => r,
                None => algod.last_round()?,
            };
            let done = history::verify_history(
                &algod,
                &indexer,
                &checkpoint_path,
                &dir.join("intervals.jsonl"),
                checkpoint,
                &history::HistoryOptions { to_round, jobs, chunk },
            )?;
            println!(
                "verified {} intervals from round {} to {}",
                done.intervals_verified,
                done.anchor.next_round,
                done.state.next_round - 1
            );
        }
        Cmd::Fetch {
            state,
            count,
            all,
            max,
            out,
        } => {
            let trusted: TrustedStateJson = read_json(&state)?;
            let proofs = if all {
                fetch_available_state_proofs(&algod, &indexer, trusted.next_round, max)?
            } else {
                fetch_state_proofs(&algod, &indexer, trusted.next_round, count)?
            };
            anyhow::ensure!(
                !proofs.is_empty(),
                "no state proof after round {} has been posted yet",
                trusted.next_round
            );
            for p in &proofs {
                eprintln!(
                    "interval [{}, {}]: {} byte state proof (block {})",
                    p.message.first_attested_round,
                    p.message.last_attested_round,
                    p.state_proof.len() * 3 / 4,
                    p.confirmed_round
                );
            }
            write_json(
                &out,
                &LightClientInput {
                    trusted_state: trusted,
                    state_proofs: proofs,
                },
            )?;
        }
        Cmd::Verify { input, out } => {
            let input: LightClientInput = read_json(&input)?;
            let prev = TrustedState::try_from(&input.trusted_state)?;
            let txns = input.txns()?;
            let t = Instant::now();
            let sh = Sumhash512::new();
            let (new, intervals) = apply_state_proofs(&sh, &prev, &txns)?;
            eprintln!(
                "verified {} state proof(s) natively in {:?}",
                intervals.len(),
                t.elapsed()
            );
            let output = LightClientOutput {
                prev_state: (&prev).into(),
                new_state: (&new).into(),
                intervals: intervals.iter().map(IntervalJson::from).collect(),
                public_values: hex0x(&encode_update(&prev, &new, &intervals)),
            };
            match out {
                Some(path) => write_json(&path, &output)?,
                None => println!("{}", serde_json::to_string_pretty(&output)?),
            }
        }
        Cmd::Stib { round, index } => {
            let bytes = algod.block_msgpack(round)?;
            let block = RawBlock::parse(&bytes)?;
            let stib = block
                .txns
                .get(index)
                .with_context(|| format!("block {round} has {} transactions", block.txns.len()))?;
            println!("{}", hex0x(stib));
        }
        Cmd::TxProof { round, txid, out } => {
            let first = interval_first_round(round);
            let msg = fetch_interval_message(&algod, &indexer, first)
                .with_context(|| {
                    format!("interval starting at {first} has no posted state proof yet")
                })?
                .message;
            let commitment = unhex_n::<32>(&hex0x(&msg.block_headers_commitment))?;
            let proof = build_tx_inclusion(&algod, round, &txid, &commitment)?;
            eprintln!(
                "tx {txid}: index {} of block {round} (depth {}), header {} of interval [{}, {}]",
                proof.tx_index,
                proof.tx_tree_depth,
                proof.header_index,
                proof.interval_first_round,
                proof.interval_last_round
            );
            write_json(&out, &proof)?;
        }
    }
    Ok(())
}

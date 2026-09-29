//! JSON formats shared by `algo-lc`, the SP1 prover script and the Foundry tests.
//! Byte strings are `0x`-prefixed hex (so `vm.parseJson*` reads them as bytes), except the
//! large msgpack state proofs, which are base64.

use algorand_stateproof::block::StateProofTxn;
use algorand_stateproof::lightclient::{TrustedState, VerifiedInterval};
use algorand_stateproof::lightheader::LightBlockHeader;
use algorand_stateproof::message::StateProofMessage;
use anyhow::{anyhow, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub fn hex0x(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

pub fn unhex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).with_context(|| format!("bad hex {s}"))
}

pub fn unhex_n<const N: usize>(s: &str) -> Result<[u8; N]> {
    unhex(s)?
        .try_into()
        .map_err(|_| anyhow!("expected {N} bytes: {s}"))
}

pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&data).with_context(|| format!("parsing {}", path.display()))
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")
        .with_context(|| format!("writing {}", path.display()))
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TrustedStateJson {
    pub voters_commitment: String,
    pub ln_proven_weight: u64,
    pub next_round: u64,
}

impl From<&TrustedState> for TrustedStateJson {
    fn from(s: &TrustedState) -> Self {
        Self {
            voters_commitment: hex0x(&s.voters_commitment),
            ln_proven_weight: s.ln_proven_weight,
            next_round: s.next_round,
        }
    }
}

impl TryFrom<&TrustedStateJson> for TrustedState {
    type Error = anyhow::Error;
    fn try_from(s: &TrustedStateJson) -> Result<Self> {
        Ok(Self {
            voters_commitment: unhex_n(&s.voters_commitment)?,
            ln_proven_weight: s.ln_proven_weight,
            next_round: s.next_round,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MessageJson {
    pub block_headers_commitment: String,
    pub voters_commitment: String,
    pub ln_proven_weight: u64,
    pub first_attested_round: u64,
    pub last_attested_round: u64,
}

impl From<&StateProofMessage> for MessageJson {
    fn from(m: &StateProofMessage) -> Self {
        Self {
            block_headers_commitment: hex0x(&m.block_headers_commitment),
            voters_commitment: hex0x(&m.voters_commitment),
            ln_proven_weight: m.ln_proven_weight,
            first_attested_round: m.first_attested_round,
            last_attested_round: m.last_attested_round,
        }
    }
}

impl TryFrom<&MessageJson> for StateProofMessage {
    type Error = anyhow::Error;
    fn try_from(m: &MessageJson) -> Result<Self> {
        Ok(Self {
            block_headers_commitment: unhex(&m.block_headers_commitment)?,
            voters_commitment: unhex(&m.voters_commitment)?,
            ln_proven_weight: m.ln_proven_weight,
            first_attested_round: m.first_attested_round,
            last_attested_round: m.last_attested_round,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct StateProofTxnJson {
    /// Round of the block that contains the state proof transaction.
    pub confirmed_round: u64,
    pub message: MessageJson,
    /// Canonical msgpack `StateProof`, base64.
    pub state_proof: String,
}

impl StateProofTxnJson {
    pub fn new(confirmed_round: u64, txn: &StateProofTxn) -> Self {
        Self {
            confirmed_round,
            message: (&txn.message).into(),
            state_proof: base64::engine::general_purpose::STANDARD.encode(&txn.state_proof),
        }
    }

    pub fn to_txn(&self) -> Result<StateProofTxn> {
        Ok(StateProofTxn {
            message: (&self.message).try_into()?,
            state_proof: base64::engine::general_purpose::STANDARD.decode(&self.state_proof)?,
        })
    }
}

/// Input of the zkVM program: a trusted state and the consecutive state proofs after it.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LightClientInput {
    pub trusted_state: TrustedStateJson,
    pub state_proofs: Vec<StateProofTxnJson>,
}

impl LightClientInput {
    pub fn txns(&self) -> Result<Vec<StateProofTxn>> {
        self.state_proofs
            .iter()
            .map(StateProofTxnJson::to_txn)
            .collect()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct IntervalJson {
    pub first_attested_round: u64,
    pub last_attested_round: u64,
    pub block_headers_commitment: String,
}

impl From<&VerifiedInterval> for IntervalJson {
    fn from(i: &VerifiedInterval) -> Self {
        Self {
            first_attested_round: i.first_attested_round,
            last_attested_round: i.last_attested_round,
            block_headers_commitment: hex0x(&i.block_headers_commitment),
        }
    }
}

/// Result of running the light client over a [`LightClientInput`]; `publicValues` is
/// exactly what the zkVM program commits.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LightClientOutput {
    pub prev_state: TrustedStateJson,
    pub new_state: TrustedStateJson,
    pub intervals: Vec<IntervalJson>,
    pub public_values: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LightBlockHeaderJson {
    pub seed: String,
    pub block_hash: String,
    pub round: u64,
    pub genesis_hash: String,
    pub txn_commitment: String,
}

impl From<&LightBlockHeader> for LightBlockHeaderJson {
    fn from(h: &LightBlockHeader) -> Self {
        Self {
            seed: hex0x(&h.seed),
            block_hash: hex0x(&h.block_hash),
            round: h.round,
            genesis_hash: hex0x(&h.genesis_hash),
            txn_commitment: hex0x(&h.sha256_txn_commitment),
        }
    }
}

impl TryFrom<&LightBlockHeaderJson> for LightBlockHeader {
    type Error = anyhow::Error;
    fn try_from(h: &LightBlockHeaderJson) -> Result<Self> {
        Ok(Self {
            seed: unhex_n(&h.seed)?,
            block_hash: unhex_n(&h.block_hash)?,
            round: h.round,
            genesis_hash: unhex_n(&h.genesis_hash)?,
            sha256_txn_commitment: unhex_n(&h.txn_commitment)?,
        })
    }
}

/// Everything an Ethereum contract needs to check that `txn` was committed on Algorand in
/// a block covered by a verified state proof interval.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TxInclusionJson {
    /// Canonical Algorand transaction id (base32 of SHA512/256("TX" || txn)).
    pub txid: String,
    /// Canonical msgpack encoding of the transaction (with `gh`/`gen` restored).
    pub txn: String,
    /// SHA256("TX" || txn).
    pub txid_sha256: String,
    /// SHA256("STIB" || signedTxnInBlock) — binds signature and apply data.
    pub stib_hash: String,
    /// Raw `SignedTxnInBlock` (signature, txn without gh/gen, apply data such as logs).
    pub stib: String,
    /// Position of the transaction in the block's payset.
    pub tx_index: u64,
    pub tx_tree_depth: u8,
    pub tx_proof: Vec<String>,
    pub header: LightBlockHeaderJson,
    /// `round - intervalFirstRound`.
    pub header_index: u64,
    pub header_proof: Vec<String>,
    pub interval_first_round: u64,
    pub interval_last_round: u64,
    pub block_headers_commitment: String,
}

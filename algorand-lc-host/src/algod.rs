//! Minimal algod / indexer REST clients (blocking).

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::io::Read;
use std::time::Duration;

pub const MAINNET_ALGOD: &str = "https://mainnet-api.4160.nodely.dev";
pub const MAINNET_INDEXER: &str = "https://mainnet-idx.4160.nodely.dev";

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(120))
        .build()
}

fn get_with_retry(agent: &ureq::Agent, url: &str, token: Option<&str>) -> Result<ureq::Response> {
    let mut last_err = None;
    for attempt in 0..4 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(500 << attempt));
        }
        let mut req = agent.get(url);
        if let Some(t) = token {
            req = req.set("X-Algo-API-Token", t);
        }
        match req.call() {
            Ok(resp) => return Ok(resp),
            // 4xx other than rate limiting will not get better on retry.
            Err(ureq::Error::Status(code, resp)) if code != 429 && code < 500 => {
                let body = resp.into_string().unwrap_or_default();
                bail!("GET {url}: HTTP {code}: {body}");
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(anyhow!("GET {url}: {}", last_err.unwrap()))
}

pub struct Algod {
    base: String,
    token: Option<String>,
    agent: ureq::Agent,
}

#[derive(Deserialize)]
pub struct TxProofResponse {
    pub idx: u64,
    /// Base64 concatenation of 32-byte siblings, leaf level first.
    pub proof: String,
    pub stibhash: String,
    pub treedepth: u8,
    pub hashtype: String,
}

impl Algod {
    pub fn new(base: &str, token: Option<String>) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            token,
            agent: agent(),
        }
    }

    fn get(&self, path: &str) -> Result<ureq::Response> {
        get_with_retry(
            &self.agent,
            &format!("{}{}", self.base, path),
            self.token.as_deref(),
        )
    }

    fn get_bytes(&self, path: &str) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.get(path)?.into_reader().read_to_end(&mut out)?;
        Ok(out)
    }

    pub fn last_round(&self) -> Result<u64> {
        let v: serde_json::Value = self.get("/v2/status")?.into_json()?;
        v["last-round"].as_u64().context("status has no last-round")
    }

    /// Full block (header + payset) as canonical msgpack.
    pub fn block_msgpack(&self, round: u64) -> Result<Vec<u8>> {
        self.get_bytes(&format!("/v2/blocks/{round}?format=msgpack"))
    }

    /// Block header only, as msgpack.
    pub fn block_header_msgpack(&self, round: u64) -> Result<Vec<u8>> {
        self.get_bytes(&format!(
            "/v2/blocks/{round}?format=msgpack&header-only=true"
        ))
    }

    /// Block header as algod's JSON (`{"block": {...}}`).
    pub fn block_header_json(&self, round: u64) -> Result<serde_json::Value> {
        Ok(self
            .get(&format!("/v2/blocks/{round}?header-only=true"))?
            .into_json()?)
    }

    /// The round the next state proof must attest up to (`spt[0].n` of the block header), if
    /// state proofs are enabled at `round`.
    pub fn next_state_proof_round(&self, round: u64) -> Result<Option<u64>> {
        Ok(self.block_header_json(round)?["block"]["spt"]["0"]["n"].as_u64())
    }

    /// `GET /v2/blocks/{round}/hash`.
    pub fn block_hash(&self, round: u64) -> Result<[u8; 32]> {
        let v: serde_json::Value = self.get(&format!("/v2/blocks/{round}/hash"))?.into_json()?;
        let s = v["blockHash"].as_str().context("no blockHash")?;
        decode_algorand_digest(s)
    }

    /// `GET /v2/blocks/{round}/transactions/{txid}/proof?hashtype=sha256`.
    pub fn tx_proof_sha256(&self, round: u64, txid: &str) -> Result<TxProofResponse> {
        Ok(self
            .get(&format!(
                "/v2/blocks/{round}/transactions/{txid}/proof?hashtype=sha256"
            ))?
            .into_json()?)
    }
}

pub struct Indexer {
    base: String,
    token: Option<String>,
    agent: ureq::Agent,
}

/// A state proof transaction located via the indexer.
#[derive(Debug, Clone, Copy)]
pub struct StateProofLocation {
    pub confirmed_round: u64,
    pub first_attested_round: u64,
    pub last_attested_round: u64,
}

impl Indexer {
    /// `base` may be `none`: state proofs are then located from block headers through algod
    /// (see [`crate::fetch`]), which works against a node without an indexer.
    pub fn new(base: &str) -> Self {
        Self::with_token(base, None)
    }

    /// An indexer that sends `token` as `X-Algo-API-Token` (e.g. a Nodely API key).
    pub fn with_token(base: &str, token: Option<String>) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            token,
            agent: agent(),
        }
    }

    /// Whether this is a real indexer (not `none`).
    pub fn is_enabled(&self) -> bool {
        self.base != "none"
    }

    /// State proof transactions confirmed in `min_round..=max_round`, in round order. Public
    /// indexers time out on open-ended searches over old rounds, so the range is always bounded.
    pub fn state_proof_txns(
        &self,
        min_round: u64,
        max_round: u64,
        limit: usize,
    ) -> Result<Vec<StateProofLocation>> {
        let url = format!(
            "{}/v2/transactions?tx-type=stpf&min-round={min_round}&max-round={max_round}&limit={limit}",
            self.base
        );
        let v: serde_json::Value = get_with_retry(&self.agent, &url, self.token.as_deref())?.into_json()?;
        let txns = v["transactions"]
            .as_array()
            .context("indexer response has no transactions")?;
        txns.iter()
            .map(|t| {
                let m = &t["state-proof-transaction"]["message"];
                Ok(StateProofLocation {
                    confirmed_round: t["confirmed-round"].as_u64().context("confirmed-round")?,
                    first_attested_round: m["first-attested-round"]
                        .as_u64()
                        .context("first-attested-round")?,
                    last_attested_round: m["latest-attested-round"]
                        .as_u64()
                        .context("latest-attested-round")?,
                })
            })
            .collect()
    }
}

/// Algorand's 52-character base32 encoding of a 32-byte digest (txids, block hashes).
pub fn encode_algorand_digest(d: &[u8; 32]) -> String {
    data_encoding::BASE32_NOPAD.encode(d)
}

pub fn decode_algorand_digest(s: &str) -> Result<[u8; 32]> {
    let v = data_encoding::BASE32_NOPAD
        .decode(s.as_bytes())
        .with_context(|| format!("bad base32 digest {s}"))?;
    v.try_into()
        .map_err(|_| anyhow!("digest {s} is not 32 bytes"))
}

//! Host-side tooling for the Algorand state proof light client.
//!
//! * [`algod`]: minimal algod + indexer REST clients.
//! * [`fetch`]: recover consecutive state proofs (from archival blocks) and anchor states.
//! * [`history`]: the genesis anchor (first state proof) and full-history verification.
//! * [`txproof`]: build the inclusion proof an Ethereum contract needs for a transaction.
//! * [`json`]: the JSON files exchanged between these tools, the SP1 prover and Foundry.

pub mod algod;
pub mod fetch;
pub mod history;
pub mod json;
pub mod txproof;

//! Public values committed by the zkVM program, ABI-encoded for the Ethereum contract
//! (`chains/evm/src/AlgorandStateProofLightClient.sol` declares the same structs).

use crate::lightclient::{self, VerifiedInterval};
use alloc::vec::Vec;
use alloy_sol_types::private::FixedBytes;
use alloy_sol_types::{sol, SolValue};

sol! {
    /// Voters commitment (Sumhash512, split into two words), ln(provenWeight) and the first
    /// round of the next interval to prove.
    struct TrustedState {
        bytes32[2] votersCommitment;
        uint64 lnProvenWeight;
        uint64 nextRound;
    }

    /// Block headers commitment of one verified 256-round interval.
    struct IntervalCommitment {
        uint64 firstAttestedRound;
        uint64 lastAttestedRound;
        bytes32 blockHeadersCommitment;
    }

    /// The statement proven by the zkVM: starting from `prevState`, the state proofs for
    /// `intervals` verify in sequence and leave the light client at `newState`.
    struct StateProofUpdate {
        TrustedState prevState;
        TrustedState newState;
        IntervalCommitment[] intervals;
    }
}

impl From<&lightclient::TrustedState> for TrustedState {
    fn from(s: &lightclient::TrustedState) -> Self {
        let (hi, lo) = s.voters_commitment.split_at(32);
        TrustedState {
            votersCommitment: [FixedBytes::from_slice(hi), FixedBytes::from_slice(lo)],
            lnProvenWeight: s.ln_proven_weight,
            nextRound: s.next_round,
        }
    }
}

impl From<&TrustedState> for lightclient::TrustedState {
    fn from(s: &TrustedState) -> Self {
        let mut voters_commitment = [0u8; 64];
        voters_commitment[..32].copy_from_slice(s.votersCommitment[0].as_slice());
        voters_commitment[32..].copy_from_slice(s.votersCommitment[1].as_slice());
        lightclient::TrustedState {
            voters_commitment,
            ln_proven_weight: s.lnProvenWeight,
            next_round: s.nextRound,
        }
    }
}

impl From<&VerifiedInterval> for IntervalCommitment {
    fn from(i: &VerifiedInterval) -> Self {
        IntervalCommitment {
            firstAttestedRound: i.first_attested_round,
            lastAttestedRound: i.last_attested_round,
            blockHeadersCommitment: FixedBytes::from(i.block_headers_commitment),
        }
    }
}

/// ABI-encodes the public values (`abi.decode(publicValues, (StateProofUpdate))` on-chain).
pub fn encode_update(
    prev: &lightclient::TrustedState,
    new: &lightclient::TrustedState,
    intervals: &[VerifiedInterval],
) -> Vec<u8> {
    StateProofUpdate {
        prevState: prev.into(),
        newState: new.into(),
        intervals: intervals.iter().map(Into::into).collect(),
    }
    .abi_encode()
}

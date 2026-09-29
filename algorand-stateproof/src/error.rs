use core::fmt;

/// Every way a state proof (or its encoding) can be rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Malformed or non-canonical msgpack.
    Msgpack(&'static str),

    // --- crypto/stateproof ---
    InvalidHashType,
    InvalidSigCommitSize,
    TreeDepthTooLarge,
    TooManyReveals,
    ZeroSignedWeight,
    InsufficientSignedWeight,
    SaltVersionMismatch,
    EmptyFalconSignature,
    MssProofTooDeep,
    MssProofMalformed,
    NoRevealInPos(u64),
    CoinNotInRange {
        pos: u64,
        coin: u64,
    },

    // --- crypto/merklesignature ---
    KeyLifetimeZero,

    // --- falcon ---
    FalconFormat,
    FalconBadSignature,

    // --- crypto/merklearray ---
    MerklePathElementSize,
    MerkleMissingHint,
    MerklePosOutOfBound,
    MerkleRootMismatch,
    MerkleNonEmptyProofForEmptyElements,
    MerkleDuplicatePosition,

    // --- light client ---
    RoundMismatch {
        expected: u64,
        got: u64,
    },
    InvalidMessage(&'static str),
    NoStateProofs,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Msgpack(what) => write!(f, "msgpack: {what}"),
            Error::InvalidHashType => f.write_str("state proof uses an unexpected hash algorithm"),
            Error::InvalidSigCommitSize => {
                f.write_str("state proof SigCommit has an unexpected size")
            }
            Error::TreeDepthTooLarge => f.write_str("tree depth is too large"),
            Error::TooManyReveals => f.write_str("too many reveals in state proof"),
            Error::ZeroSignedWeight => f.write_str("signed weight cannot be zero"),
            Error::InsufficientSignedWeight => f.write_str(
                "the number of reveals is not large enough to prove that the desired weight signed",
            ),
            Error::SaltVersionMismatch => {
                f.write_str("the signature's salt version does not match")
            }
            Error::EmptyFalconSignature => f.write_str("revealed signature is empty"),
            Error::MssProofTooDeep => f.write_str("merkle signature proof depth exceeds 16"),
            Error::MssProofMalformed => f.write_str("merkle signature proof path is malformed"),
            Error::NoRevealInPos(pos) => write!(f, "no reveal for position {pos}"),
            Error::CoinNotInRange { pos, coin } => {
                write!(
                    f,
                    "coin {coin} is not within the slot weight range of reveal {pos}"
                )
            }
            Error::KeyLifetimeZero => f.write_str("received zero KeyLifetime"),
            Error::FalconFormat => f.write_str("falcon: malformed key or signature"),
            Error::FalconBadSignature => f.write_str("falcon: signature does not verify"),
            Error::MerklePathElementSize => {
                f.write_str("merkle: proof path element has wrong size")
            }
            Error::MerkleMissingHint => f.write_str("merkle: no more sibling hints"),
            Error::MerklePosOutOfBound => f.write_str("merkle: position out of bound"),
            Error::MerkleRootMismatch => f.write_str("merkle: root mismatch"),
            Error::MerkleNonEmptyProofForEmptyElements => {
                f.write_str("merkle: non-empty proof for empty set of elements")
            }
            Error::MerkleDuplicatePosition => f.write_str("merkle: duplicate leaf position"),
            Error::RoundMismatch { expected, got } => {
                write!(f, "state proof starts at round {got}, expected {expected}")
            }
            Error::InvalidMessage(what) => write!(f, "invalid state proof message: {what}"),
            Error::NoStateProofs => f.write_str("no state proofs supplied"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

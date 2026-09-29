//! Merkle vector commitments (`crypto/merklearray`).
//!
//! A vector commitment is a full binary Merkle tree whose leaves are the array elements
//! placed at *bit-reversed* positions and padded to a power of two with "bottom" leaves.
//! Internal nodes are `H("MA" || left || right)` with each child zero-padded to the digest
//! size (a missing sibling hint is an all-zero digest).
//!
//! Batch proofs (`Proof.Path`) list the sibling hashes the verifier cannot compute itself,
//! in the deterministic order in which [`verify_vector_commitment`] asks for them.

use crate::error::{Error, Result};
use crate::hash_id;
use crate::sumhash::{Sumhash512, DIGEST_SIZE as SUMHASH_SIZE};
use crate::types::MerkleProof;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// Maximum depth of a tree whose proofs are encoded (`merklearray.MaxEncodedTreeDepth`).
pub const MAX_ENCODED_TREE_DEPTH: u8 = 16;

/// `merkleTreeToVectorCommitmentIndex`: array index -> leaf position (bit reversal over
/// `depth` bits).
pub fn vc_position(index: u64, depth: u8) -> Result<u64> {
    if depth >= 64 || index >= (1u64 << depth) {
        return Err(Error::MerklePosOutOfBound);
    }
    if depth == 0 {
        return Ok(0);
    }
    Ok(index.reverse_bits() >> (64 - depth as u32))
}

fn sumhash_node(
    sh: &Sumhash512,
    left: &[u8; SUMHASH_SIZE],
    right: &[u8; SUMHASH_SIZE],
) -> [u8; SUMHASH_SIZE] {
    sh.hash(&[hash_id::MERKLE_ARRAY_NODE, left, right])
}

/// Verifies a (batch) Sumhash512 vector-commitment proof.
///
/// `leaves` are `(array index, leaf hash)` pairs with distinct indices. Mirrors
/// `merklearray.VerifyVectorCommitment` + `Verify`: the walk continues while hints remain
/// or more than one node is left, and the result must be the node at position 0 equal to
/// `root`. The caller is responsible for checking `proof.hash_type`.
pub fn verify_vector_commitment(
    sh: &Sumhash512,
    root: &[u8],
    mut leaves: Vec<(u64, [u8; SUMHASH_SIZE])>,
    proof: &MerkleProof,
) -> Result<()> {
    if leaves.len() == 1 {
        return verify_single_leaf(sh, root, leaves[0], proof);
    }
    if leaves.is_empty() {
        return if proof.path.is_empty() {
            Ok(())
        } else {
            Err(Error::MerkleNonEmptyProofForEmptyElements)
        };
    }
    for leaf in leaves.iter_mut() {
        leaf.0 = vc_position(leaf.0, proof.tree_depth)?;
    }
    leaves.sort_unstable_by_key(|l| l.0);
    if leaves.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(Error::MerkleDuplicatePosition);
    }
    if proof
        .path
        .iter()
        .any(|h| !h.is_empty() && h.len() != SUMHASH_SIZE)
    {
        return Err(Error::MerklePathElementSize);
    }

    let mut hints = proof.path.iter();
    let mut hints_left = proof.path.len();
    let mut layer = leaves;
    while hints_left > 0 || layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i < layer.len() {
            let (pos, hash) = layer[i];
            let sibling = if i + 1 < layer.len() && layer[i + 1].0 == pos ^ 1 {
                i += 1;
                layer[i].1
            } else {
                let hint = hints.next().ok_or(Error::MerkleMissingHint)?;
                hints_left -= 1;
                *sibling_array(hint)?
            };
            let parent = if pos & 1 == 0 {
                sumhash_node(sh, &hash, &sibling)
            } else {
                sumhash_node(sh, &sibling, &hash)
            };
            next.push((pos / 2, parent));
            i += 1;
        }
        layer = next;
    }
    if layer[0].0 != 0 || layer[0].1[..] != *root {
        return Err(Error::MerkleRootMismatch);
    }
    Ok(())
}

/// A proof hint as a digest: empty hints stand for the all-zero digest.
fn sibling_array(hint: &[u8]) -> Result<&[u8; SUMHASH_SIZE]> {
    const ZERO: [u8; SUMHASH_SIZE] = [0; SUMHASH_SIZE];
    if hint.is_empty() {
        return Ok(&ZERO);
    }
    hint.try_into().map_err(|_| Error::MerklePathElementSize)
}

/// The one-leaf case of [`verify_vector_commitment`] (Merkle signature key paths): the
/// layer never has more than one node, so every hint is the sibling at the next level.
fn verify_single_leaf(
    sh: &Sumhash512,
    root: &[u8],
    (index, leaf): (u64, [u8; SUMHASH_SIZE]),
    proof: &MerkleProof,
) -> Result<()> {
    let mut pos = vc_position(index, proof.tree_depth)?;
    let mut node = leaf;
    for hint in &proof.path {
        let sibling = sibling_array(hint)?;
        node = if pos & 1 == 0 {
            sumhash_node(sh, &node, sibling)
        } else {
            sumhash_node(sh, sibling, &node)
        };
        pos /= 2;
    }
    if pos != 0 || node[..] != *root {
        return Err(Error::MerkleRootMismatch);
    }
    Ok(())
}

/// SHA-256 internal node `SHA256("MA" || left || right)`.
pub fn sha256_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(hash_id::MERKLE_ARRAY_NODE);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Recomputes the root of a SHA-256 vector commitment from a single-leaf proof as returned
/// by algod (`GetConcatenatedProof`: one 32-byte sibling per level, leaf level first).
/// This is the computation the Solidity verifier performs.
pub fn sha256_vc_root(
    leaf: [u8; 32],
    index: u64,
    depth: u8,
    siblings: &[[u8; 32]],
) -> Result<[u8; 32]> {
    if siblings.len() != depth as usize {
        return Err(Error::MerkleMissingHint);
    }
    let mut pos = vc_position(index, depth)?;
    let mut node = leaf;
    for sibling in siblings {
        node = if pos & 1 == 0 {
            sha256_node(&node, sibling)
        } else {
            sha256_node(sibling, &node)
        };
        pos >>= 1;
    }
    Ok(node)
}

/// Builds a SHA-256 vector commitment over already-hashed leaves and returns every level
/// (level 0 = leaves in tree order). Used off-chain to produce proofs and to check roots.
pub fn sha256_vc_levels(leaf_hashes: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    let n = leaf_hashes.len().max(1) as u64;
    let depth = if n <= 1 {
        0
    } else {
        64 - (n - 1).leading_zeros()
    } as u8;
    let bottom: [u8; 32] = Sha256::digest(hash_id::MERKLE_VC_BOTTOM_LEAF).into();
    let mut level = alloc::vec![bottom; 1usize << depth];
    for (i, leaf) in leaf_hashes.iter().enumerate() {
        level[vc_position(i as u64, depth).expect("index < 2^depth") as usize] = *leaf;
    }
    let mut levels = alloc::vec![level];
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let next = prev.chunks(2).map(|c| sha256_node(&c[0], &c[1])).collect();
        levels.push(next);
    }
    levels
}

/// Single-leaf proof (siblings, leaf level first) for array `index` from [`sha256_vc_levels`].
pub fn sha256_vc_prove(levels: &[Vec<[u8; 32]>], index: u64) -> Vec<[u8; 32]> {
    let depth = (levels.len() - 1) as u8;
    let mut pos = vc_position(index, depth).expect("index in range");
    let mut siblings = Vec::with_capacity(depth as usize);
    for level in &levels[..levels.len() - 1] {
        siblings.push(level[(pos ^ 1) as usize]);
        pos >>= 1;
    }
    siblings
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn bit_reversed_positions() {
        assert_eq!(vc_position(0, 0).unwrap(), 0);
        assert_eq!(vc_position(1, 3).unwrap(), 4);
        assert_eq!(vc_position(3, 3).unwrap(), 6);
        assert_eq!(vc_position(1, 8).unwrap(), 128);
        assert!(vc_position(8, 3).is_err());
    }

    #[test]
    #[allow(clippy::needless_range_loop)]
    fn sumhash_batch_proof_roundtrip() {
        // Build a depth-3 tree by hand, prove leaves {1, 2, 6}, and check tampering fails.
        let sh = Sumhash512::new();
        let leaf = |i: u8| sh.hash(&[b"leaf", &[i]]);
        let mut tree = vec![[[0u8; 64]; 8]];
        for i in 0..8u64 {
            tree[0][vc_position(i, 3).unwrap() as usize] = leaf(i as u8);
        }
        for l in 0..3 {
            let mut next = [[0u8; 64]; 8];
            for p in 0..(8 >> (l + 1)) {
                next[p] = sumhash_node(&sh, &tree[l][2 * p], &tree[l][2 * p + 1]);
            }
            tree.push(next);
        }
        let root = tree[3][0];

        // Replay the verifier's sibling requests to build the hint list.
        let proven = [1u64, 2, 6];
        let mut layer: Vec<u64> = proven.iter().map(|&i| vc_position(i, 3).unwrap()).collect();
        layer.sort();
        let mut path = vec![];
        for l in 0..3 {
            let mut next = vec![];
            let mut i = 0;
            while i < layer.len() {
                let p = layer[i];
                if i + 1 < layer.len() && layer[i + 1] == p ^ 1 {
                    i += 1;
                } else {
                    path.push(tree[l][(p ^ 1) as usize].to_vec());
                }
                next.push(p / 2);
                i += 1;
            }
            layer = next;
        }
        let proof = MerkleProof {
            path,
            hash_type: crate::types::HASH_SUMHASH,
            tree_depth: 3,
        };
        let leaves: Vec<_> = proven.iter().map(|&i| (i, leaf(i as u8))).collect();
        verify_vector_commitment(&sh, &root, leaves.clone(), &proof).unwrap();

        let mut bad = leaves.clone();
        bad[1].1[0] ^= 1;
        assert_eq!(
            verify_vector_commitment(&sh, &root, bad, &proof),
            Err(Error::MerkleRootMismatch)
        );
        let mut short = proof.clone();
        short.path.pop();
        assert!(verify_vector_commitment(&sh, &root, leaves, &short).is_err());
    }

    #[test]
    fn sha256_prove_verify_roundtrip() {
        let leaves: Vec<[u8; 32]> = (0..5u8).map(|i| Sha256::digest([i]).into()).collect();
        let levels = sha256_vc_levels(&leaves);
        let root = levels.last().unwrap()[0];
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = sha256_vc_prove(&levels, i as u64);
            assert_eq!(sha256_vc_root(*leaf, i as u64, 3, &proof).unwrap(), root);
        }
    }
}

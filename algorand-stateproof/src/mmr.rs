//! Merkle Mountain Range over interval commitments: a 32-byte root that commits to every
//! verified interval's block headers commitment, in order.
//!
//! ```text
//! leaf(c)        = SHA256(0x00 || c)
//! node(l, r)     = SHA256(0x01 || l || r)
//! peaks          = roots of the perfect subtrees given by the binary digits of n, largest first
//! root(n, peaks) = SHA256(0x02 || u64_be(n) || peak_0 || ... || peak_m)
//! ```
//!
//! A light client that follows state proofs appends each interval's commitment, so a single
//! root (e.g. one storage slot on Ethereum) commits to its whole history, and any older
//! interval's commitment is checked with a [`HistoryProof`] (at most ~2·log2(n) hashes).
//! The root includes `n`, so a root also fixes how many intervals it covers.

use crate::error::{Error, Result};
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

pub fn leaf_hash(commitment: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(commitment);
    h.finalize().into()
}

pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

pub fn bag(n: u64, peaks: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x02]);
    h.update(n.to_be_bytes());
    for p in peaks {
        h.update(p);
    }
    h.finalize().into()
}

/// The accumulator: the number of leaves and the peaks (largest subtree first).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Mmr {
    n: u64,
    peaks: Vec<[u8; 32]>,
}

impl Mmr {
    pub fn new() -> Self {
        Self::default()
    }

    /// An accumulator from its parts; the peak count must match `n`.
    pub fn from_peaks(n: u64, peaks: Vec<[u8; 32]>) -> Result<Self> {
        if peaks.len() != n.count_ones() as usize {
            return Err(Error::InvalidHistory("peak count does not match the leaf count"));
        }
        Ok(Self { n, peaks })
    }

    pub fn len(&self) -> u64 {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    pub fn peaks(&self) -> &[[u8; 32]] {
        &self.peaks
    }

    pub fn root(&self) -> [u8; 32] {
        bag(self.n, &self.peaks)
    }

    pub fn append(&mut self, commitment: &[u8; 32]) {
        let mut h = leaf_hash(commitment);
        // Each trailing one bit of n is a peak of the same height as the new node: merge.
        let mut m = self.n;
        while m & 1 == 1 {
            let left = self.peaks.pop().expect("a peak per one bit");
            h = node_hash(&left, &h);
            m >>= 1;
        }
        self.peaks.push(h);
        self.n += 1;
    }

    pub fn from_commitments(commitments: &[[u8; 32]]) -> Self {
        let mut m = Self::new();
        for c in commitments {
            m.append(c);
        }
        m
    }

    /// Checks that `path` proves its commitment is leaf `path.index` of this accumulator.
    pub fn verify_path(&self, path: &HistoryPath) -> Result<()> {
        let peak = climb(path.index, self.n, &path.commitment, &path.siblings)?;
        if peak != self.peaks[peak_number(path.index, self.n)] {
            return Err(Error::InvalidHistory("path does not lead to its peak"));
        }
        Ok(())
    }
}

/// Proof that `commitment` is leaf `index` of an accumulator whose peaks the verifier already
/// has (e.g. a zkVM program that was given them and checked them against a root).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HistoryPath {
    pub index: u64,
    pub commitment: [u8; 32],
    /// Siblings from the leaf up to the root of its peak (leaf level first).
    pub siblings: Vec<[u8; 32]>,
}

/// Proof that `commitment` is leaf `index` of the MMR of `size` leaves, checked against a root.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HistoryProof {
    pub index: u64,
    pub commitment: [u8; 32],
    pub size: u64,
    /// Siblings from the leaf up to the root of its peak (leaf level first).
    pub siblings: Vec<[u8; 32]>,
    /// All peaks of the MMR of `size` leaves, largest first.
    pub peaks: Vec<[u8; 32]>,
}

/// Where leaf `index` sits in an MMR of `size` leaves: (peak number, first leaf of that peak,
/// peak height).
fn locate(index: u64, size: u64) -> Option<(usize, u64, u32)> {
    if index >= size {
        return None;
    }
    let mut start = 0u64;
    let mut peak = 0usize;
    for h in (0..64).rev() {
        if size >> h & 1 == 1 {
            let span = 1u64 << h;
            if index < start + span {
                return Some((peak, start, h));
            }
            start += span;
            peak += 1;
        }
    }
    None
}

fn peak_number(index: u64, size: u64) -> usize {
    locate(index, size).map_or(0, |(p, _, _)| p)
}

/// Hashes from leaf `index` up through `siblings` to the root of its peak.
fn climb(index: u64, size: u64, commitment: &[u8; 32], siblings: &[[u8; 32]]) -> Result<[u8; 32]> {
    let Some((_, start, height)) = locate(index, size) else {
        return Err(Error::InvalidHistory("index outside the MMR"));
    };
    if siblings.len() != height as usize {
        return Err(Error::InvalidHistory("path length does not match the peak height"));
    }
    let mut h = leaf_hash(commitment);
    let mut pos = index - start;
    for s in siblings {
        h = if pos & 1 == 0 { node_hash(&h, s) } else { node_hash(s, &h) };
        pos >>= 1;
    }
    Ok(h)
}

/// Siblings of leaf `index` up to its peak, over the first `size` of `commitments`.
fn siblings(commitments: &[[u8; 32]], index: u64, size: u64) -> Result<Vec<[u8; 32]>> {
    if size as usize > commitments.len() {
        return Err(Error::InvalidHistory("not enough commitments for that size"));
    }
    let (_, start, height) = locate(index, size).ok_or(Error::InvalidHistory("index outside the MMR"))?;
    let mut level: Vec<[u8; 32]> = commitments[start as usize..(start + (1 << height)) as usize]
        .iter()
        .map(leaf_hash)
        .collect();
    let mut pos = (index - start) as usize;
    let mut out = Vec::with_capacity(height as usize);
    while level.len() > 1 {
        out.push(level[pos ^ 1]);
        level = level.chunks_exact(2).map(|p| node_hash(&p[0], &p[1])).collect();
        pos >>= 1;
    }
    Ok(out)
}

impl HistoryPath {
    /// Builds the path for leaf `index` over the first `size` of `commitments`.
    pub fn build(commitments: &[[u8; 32]], index: u64, size: u64) -> Result<Self> {
        Ok(Self { index, commitment: commitments[index as usize], siblings: siblings(commitments, index, size)? })
    }
}

impl HistoryProof {
    /// Builds the proof for leaf `index` over the first `size` of `commitments`.
    pub fn build(commitments: &[[u8; 32]], index: u64, size: u64) -> Result<Self> {
        let path = HistoryPath::build(commitments, index, size)?;
        Ok(Self {
            index,
            commitment: path.commitment,
            size,
            siblings: path.siblings,
            peaks: Mmr::from_commitments(&commitments[..size as usize]).peaks,
        })
    }

    /// Checks the proof against `root`, the MMR root of `self.size` leaves.
    pub fn verify(&self, root: &[u8; 32]) -> Result<()> {
        if self.peaks.len() != self.size.count_ones() as usize {
            return Err(Error::InvalidHistory("peak count does not match the size"));
        }
        let peak = climb(self.index, self.size, &self.commitment, &self.siblings)?;
        if peak != self.peaks[peak_number(self.index, self.size)] {
            return Err(Error::InvalidHistory("path does not lead to its peak"));
        }
        if bag(self.size, &self.peaks) != *root {
            return Err(Error::InvalidHistory("peaks do not match the root"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commitments(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| Sha256::digest((i as u64).to_le_bytes()).into()).collect()
    }

    /// Independent definition: split into perfect subtrees by the bits of n, hash each recursively.
    fn reference_root(cs: &[[u8; 32]]) -> [u8; 32] {
        fn tree(leaves: &[[u8; 32]]) -> [u8; 32] {
            if leaves.len() == 1 {
                return leaf_hash(&leaves[0]);
            }
            let (l, r) = leaves.split_at(leaves.len() / 2);
            node_hash(&tree(l), &tree(r))
        }
        let n = cs.len() as u64;
        let mut peaks = Vec::new();
        let mut start = 0usize;
        for h in (0..64).rev() {
            if n >> h & 1 == 1 {
                peaks.push(tree(&cs[start..start + (1 << h)]));
                start += 1 << h;
            }
        }
        bag(n, &peaks)
    }

    #[test]
    fn roots_match_the_recursive_definition() {
        let cs = commitments(300);
        let mut m = Mmr::new();
        assert_eq!(m.root(), bag(0, &[]));
        for n in 1..=cs.len() {
            m.append(&cs[n - 1]);
            assert_eq!(m.root(), reference_root(&cs[..n]), "n = {n}");
            assert_eq!(m.peaks().len(), (n as u64).count_ones() as usize);
        }
    }

    /// Fixed vectors, shared with the Solidity `AlgorandHistory` library tests.
    #[test]
    fn vectors() {
        let empty: [u8; 32] = Sha256::digest([2u8, 0, 0, 0, 0, 0, 0, 0, 0]).into();
        assert_eq!(bag(0, &[]), empty);
        let cs = commitments(3);
        let m = Mmr::from_commitments(&cs);
        assert_eq!(m.peaks()[0], node_hash(&leaf_hash(&cs[0]), &leaf_hash(&cs[1])));
        assert_eq!(m.peaks()[1], leaf_hash(&cs[2]));
    }

    #[test]
    fn every_leaf_proves_and_tampering_fails() {
        let cs = commitments(300);
        for size in [1u64, 2, 3, 4, 5, 7, 8, 9, 31, 32, 33, 100, 255, 256, 257, 300] {
            let mmr = Mmr::from_commitments(&cs[..size as usize]);
            let root = mmr.root();
            for index in 0..size {
                let p = HistoryProof::build(&cs, index, size).unwrap();
                p.verify(&root).unwrap();
                let path = HistoryPath::build(&cs, index, size).unwrap();
                mmr.verify_path(&path).unwrap();

                let mut bad = p.clone();
                bad.commitment[0] ^= 1;
                assert!(bad.verify(&root).is_err());
                let mut bad = path.clone();
                bad.commitment[0] ^= 1;
                assert!(mmr.verify_path(&bad).is_err());
                let mut bad = p.clone();
                bad.index = (index + 1) % size;
                assert!(bad.index == index || bad.verify(&root).is_err());
                let mut bad = path.clone();
                bad.index = size;
                assert!(mmr.verify_path(&bad).is_err());
                if let Some(s) = p.siblings.first() {
                    let mut bad = p.clone();
                    bad.siblings[0] = [s[0] ^ 1; 32];
                    assert!(bad.verify(&root).is_err());
                    let mut bad = p.clone();
                    bad.siblings.pop();
                    assert!(bad.verify(&root).is_err());
                }
                let mut bad = p.clone();
                bad.size += 1;
                assert!(bad.verify(&root).is_err());
            }
        }
    }
}

//! Sumhash512: Algorand's subset-sum hash (`github.com/algorand/go-sumhash`).
//!
//! The compression function maps 1024 input bits `x` to `A·x mod 2^64` for a fixed
//! 8×1024 matrix `A` of 64-bit words derived from SHAKE256 (seed `"Algorand"`). The input is
//! the 64-byte chaining value followed by a 64-byte message block; the hash is a
//! Merkle–Damgård chain starting from a zero IV, padded with `0x01 00..00` up to 48 mod 64
//! bytes and a 128-bit little-endian bit length.
//!
//! As in go-sumhash, compression uses a byte-indexed lookup table (the sum of the 8 matrix
//! columns selected by each possible byte value), turning 1024 conditional additions per
//! row into 128 table lookups. The table is 2 MiB and is built once per [`Sumhash512`].

use alloc::boxed::Box;
use alloc::vec;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// Output size in bytes.
pub const DIGEST_SIZE: usize = 64;
/// Message bytes consumed per compression.
pub const BLOCK_SIZE: usize = 64;

const ROWS: usize = 8; // n: output words
const INPUT_BYTES: usize = 128; // m / 8: compression input (chaining value + block)
const COLS: usize = INPUT_BYTES * 8; // m = 1024

/// `table[j][b][i]` = Σ A[i][8j + k] over the set bits k of byte value b.
type Table = [[[u64; ROWS]; 256]; INPUT_BYTES];

/// A Sumhash512 instance holding the precomputed compression lookup table.
pub struct Sumhash512 {
    table: Box<Table>,
}

/// 8-byte aligned block, so the chaining value is written with whole-word stores.
#[derive(Clone, Copy)]
#[repr(C, align(8))]
struct Aligned64([u8; DIGEST_SIZE]);

impl Default for Sumhash512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sumhash512 {
    /// Derives the Algorand matrix (`RandomMatrixFromSeed("Algorand", 8, 1024)`) and builds
    /// the byte lookup table.
    pub fn new() -> Self {
        let mut xof = Shake256::default();
        xof.update(&64u16.to_le_bytes()); // u = 64 (word size in bits)
        xof.update(&(ROWS as u16).to_le_bytes());
        xof.update(&(COLS as u16).to_le_bytes());
        xof.update(b"Algorand");
        let mut reader = xof.finalize_xof();

        // Row-major: A[i][j] for i in rows, j in columns, each read as a little-endian u64.
        let mut matrix = vec![[0u64; COLS]; ROWS];
        let mut word = [0u8; 8];
        for row in matrix.iter_mut() {
            for entry in row.iter_mut() {
                reader.read(&mut word);
                *entry = u64::from_le_bytes(word);
            }
        }

        let mut table: Box<Table> = vec![[[0u64; ROWS]; 256]; INPUT_BYTES]
            .into_boxed_slice()
            .try_into()
            .expect("INPUT_BYTES entries");
        for (j, byte_table) in table.iter_mut().enumerate() {
            for b in 1..256usize {
                // Bits are read LSB-first: bit k of byte j selects column 8j + k.
                let col = 8 * j + b.trailing_zeros() as usize;
                let mut sums = byte_table[b & (b - 1)];
                for (i, s) in sums.iter_mut().enumerate() {
                    *s = s.wrapping_add(matrix[i][col]);
                }
                byte_table[b] = sums;
            }
        }
        Self { table }
    }

    /// Compresses `chain || block` into `chain`. This is the hot loop of the whole
    /// verifier (~10k calls per state proof): one 8-word table row per input byte.
    #[inline]
    fn compress(&self, chain: &mut Aligned64, block: &[u8; BLOCK_SIZE], chain_is_iv: bool) {
        let (chain_tables, block_tables) = self.table.split_at(DIGEST_SIZE);
        let mut acc = [0u64; ROWS];
        // Zero bytes contribute nothing (table[j][0] = 0). The chaining value is the zero IV
        // on a message's first block, and padding blocks and the zero digests of Merkle
        // signature proofs are mostly zeros.
        // Walk 8 bytes per iteration so the inner loop unrolls.
        if !chain_is_iv {
            for (tables, bytes) in chain_tables.chunks_exact(8).zip(chain.0.chunks_exact(8)) {
                for (byte_table, &b) in tables.iter().zip(bytes) {
                    let entry = &byte_table[b as usize];
                    for i in 0..ROWS {
                        acc[i] = acc[i].wrapping_add(entry[i]);
                    }
                }
            }
        }
        for (tables, bytes) in block_tables.chunks_exact(8).zip(block.chunks_exact(8)) {
            for (byte_table, &b) in tables.iter().zip(bytes) {
                if b != 0 {
                    let entry = &byte_table[b as usize];
                    for i in 0..ROWS {
                        acc[i] = acc[i].wrapping_add(entry[i]);
                    }
                }
            }
        }
        for (i, word) in acc.iter().enumerate() {
            chain.0[8 * i..8 * i + 8].copy_from_slice(&word.to_le_bytes());
        }
    }

    /// Starts an incremental hash.
    pub fn hasher(&self) -> SumhashState<'_> {
        SumhashState {
            sh: self,
            chain: Aligned64([0u8; DIGEST_SIZE]),
            started: false,
            buf: [0u8; BLOCK_SIZE],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Hashes the concatenation of `parts`.
    pub fn hash(&self, parts: &[&[u8]]) -> [u8; DIGEST_SIZE] {
        let mut h = self.hasher();
        for p in parts {
            h.update(p);
        }
        h.finalize()
    }
}

/// Incremental Sumhash512 state (unsalted mode, which is what Algorand uses).
pub struct SumhashState<'a> {
    sh: &'a Sumhash512,
    chain: Aligned64,
    /// Whether a block has been compressed (before that, `chain` is the zero IV).
    started: bool,
    buf: [u8; BLOCK_SIZE],
    buf_len: usize,
    total_len: u64,
}

impl SumhashState<'_> {
    #[inline]
    fn compress(&mut self, block: &[u8; BLOCK_SIZE]) {
        self.sh.compress(&mut self.chain, block, !self.started);
        self.started = true;
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let n = (BLOCK_SIZE - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + n].copy_from_slice(&data[..n]);
            self.buf_len += n;
            data = &data[n..];
            if self.buf_len == BLOCK_SIZE {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while let Some((block, rest)) = data.split_first_chunk::<BLOCK_SIZE>() {
            self.compress(block);
            data = rest;
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; DIGEST_SIZE] {
        const P: u64 = (BLOCK_SIZE - 16) as u64;
        const B: u64 = BLOCK_SIZE as u64;
        let bit_len = self.total_len << 3;
        let rem = self.total_len % B;
        let pad_len = if rem < P { P - rem } else { B + P - rem } as usize;
        let mut pad = [0u8; 2 * BLOCK_SIZE];
        pad[0] = 0x01;
        self.update(&pad[..pad_len]);
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&bit_len.to_le_bytes());
        self.update(&len_block);
        debug_assert_eq!(self.buf_len, 0);
        self.chain.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from go-sumhash/sumhash512_test.go.
    const VECTORS: &[(&str, &str)] = &[
        ("", "591591c93181f8f90054d138d6fa85b63eeeb416e6fd201e8375ba05d3cb55391047b9b64e534042562cc61944930c0075f906f16710cdade381ee9dd47d10a0"),
        ("a", "ea067eb25622c633f5ead70ab83f1d1d76a7def8d140a587cb29068b63cb6407107aceecfdffa92579ed43db1eaa5bbeb4781223a6e07dd5b5a12d5e8bde82c6"),
        ("ab", "ef09d55b6add510f1706a52c4b45420a6945d0751d73b801cbc195a54bc0ade0c9ebe30e09c2c00864f2bd1692eba79500965925e2be2d1ac334425d8d343694"),
        ("abc", "a8e9b8259a93b8d2557434905790114a2a2e979fbdc8aa6fd373315a322bf0920a9b49f3dc3a744d8c255c46cd50ff196415c8245cdbb2899dec453fca2ba0f4"),
        ("abcd", "1d4277f17e522c4607bc2912bb0d0ac407e60e3c86e2b6c7daa99e1f740fe2b4fc928defad8e1ccc4e7d96b79896ffe086836c172a3db40a154d2229484f359b"),
        ("You must be the change you wish to see in the world. -Mahatma Gandhi", "5c5f63ac24392d640e5799c4164b7cc03593feeec85844cc9691ea0612a97caabc8775482624e1cd01fb8ce1eca82a17dd9d4b73e00af4c0468fd7d8e6c2e4b5"),
        ("I think, therefore I am. – Rene Descartes.", "2d4583cdb18710898c78ec6d696a86cc2a8b941bb4d512f9d46d96816d95cbe3f867c9b8bd31964406c847791f5669d60b603c9c4d69dadcb87578e613b60b7a"),
    ];

    #[test]
    fn go_sumhash_test_vectors() {
        let sh = Sumhash512::new();
        for (input, expected) in VECTORS {
            assert_eq!(
                hex::encode(sh.hash(&[input.as_bytes()])),
                *expected,
                "input {input:?}"
            );
        }
    }

    #[test]
    fn long_input_and_incremental_writes() {
        // TestSumHash512: 6000 bytes of SHAKE256("sumhash input").
        let mut xof = Shake256::default();
        xof.update(b"sumhash input");
        let mut input = vec![0u8; 6000];
        xof.finalize_xof().read(&mut input);
        let expected = "43dc59ca43da473a3976a952f1c33a2b284bf858894ef7354b8fc0bae02b966391070230dd23e0713eaf012f7ad525f198341000733aa87a904f7053ce1a43c6";

        let sh = Sumhash512::new();
        assert_eq!(hex::encode(sh.hash(&[&input])), expected);

        // Same digest regardless of how the input is split across updates.
        for split in [1usize, 7, 63, 64, 65, 129, 1000] {
            let mut h = sh.hasher();
            for chunk in input.chunks(split) {
                h.update(chunk);
            }
            assert_eq!(hex::encode(h.finalize()), expected, "split {split}");
        }
    }
}

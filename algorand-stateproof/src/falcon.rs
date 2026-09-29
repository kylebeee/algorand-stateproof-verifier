//! Deterministic Falcon-1024 ("det1024") signature verification, as used by Algorand's
//! state proof keys (`github.com/algorand/falcon`, `deterministic.c` on top of the Falcon
//! reference implementation by Thomas Pornin, MIT licensed).
//!
//! A deterministic signature replaces the random 40-byte nonce of Falcon with a *fixed*
//! salt derived from a one-byte salt version, and flips the MSB of the header byte:
//!
//! ```text
//! compressed:  0xBA || salt_version || comp_encode(s2)          (<= 1423 bytes)
//! CT:          0xDA || salt_version || 12-bit two's complement s2 (1538 bytes)
//! salt:        salt_version || 0x0A || "FALCON_DET" || 0^28      (40 bytes)
//! ```
//!
//! Verification hashes `salt || msg` to a point `c` with SHAKE256 and checks that
//! `(c - s2·h, s2)` is short, with `h` the public key polynomial in `Z_q[x]/(x^1024+1)`.

use crate::error::{Error, Result};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

pub const LOGN: u32 = 10;
pub const N: usize = 1 << LOGN;
pub const Q: u32 = 12289;

/// Public key: header byte `0x0A` followed by 1024 coefficients packed on 14 bits.
pub const PUBKEY_SIZE: usize = 1793;
/// `FALCON_SIG_COMPRESSED_MAXSIZE(10) - 40 + 1`.
pub const COMPRESSED_SIG_MAX_SIZE: usize = 1423;
/// `FALCON_SIG_CT_SIZE(10) - 40 + 1`.
pub const CT_SIG_SIZE: usize = 1538;
pub const SIG_COMPRESSED_HEADER: u8 = 0x3A | 0x80;
pub const SIG_CT_HEADER: u8 = 0x5A | 0x80;
const PUBKEY_HEADER: u8 = LOGN as u8;

const L2_BOUND: u32 = 70_265_242; // l2bound[10]
const CT_BITS: u32 = 12; // max_sig_bits[10]

// ---------------------------------------------------------------------------------------
// Polynomial arithmetic in Z_q[x]/(x^1024 + 1).
//
// This is the negacyclic NTT of vrfy.c (psi = 7, a primitive 2048-th root of unity mod q,
// twiddles in bit-reversed order), re-tuned for a zkVM instead of for constant time:
// multiplication and remainder are single RISC-V instructions there, so a product is
// reduced with one `%` instead of a Montgomery sequence, and the forward transform leaves
// its sums unreduced. vrfy.c's Montgomery code is kept in `tests::reference` as an oracle.

const fn modpow(base: u32, mut exp: u32) -> u32 {
    let mut result = 1u32;
    let mut b = base % Q;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * b % Q;
        }
        b = b * b % Q;
        exp >>= 1;
    }
    result
}

const fn rev10(x: usize) -> u32 {
    let mut r = 0u32;
    let mut i = 0;
    while i < 10 {
        r |= (((x >> i) & 1) as u32) << (9 - i);
        i += 1;
    }
    r
}

const fn root_table(g: u32) -> [u32; N] {
    let mut t = [0u32; N];
    let mut x = 0;
    while x < N {
        t[x] = modpow(g, rev10(x));
        x += 1;
    }
    t
}

/// `psi^rev10(x)` and `psi^-rev10(x)` mod q.
static ROOTS: [u32; N] = root_table(7);
static INV_ROOTS: [u32; N] = root_table(modpow(7, Q - 2));
/// `1/1024 mod q`.
const N_INV: u32 = modpow(N as u32, Q - 2);

/// `q`, hidden from the optimizer inside the zkVM. LLVM lowers `% constant` to a
/// multiply-and-shift sequence, which is right for real CPUs; in SP1 `remu` is a single
/// instruction and costs less prover gas than that sequence.
#[inline(always)]
fn modulus() -> u32 {
    #[cfg(target_os = "zkvm")]
    return core::hint::black_box(Q);
    #[cfg(not(target_os = "zkvm"))]
    return Q;
}

/// Forward NTT (Cooley–Tukey, as `mq_NTT`). Input coefficients `< q`; output `< q`.
fn ntt(a: &mut [u32; N]) {
    let q = modulus();
    let mut t = N;
    let mut m = 1;
    while m < N {
        let ht = t >> 1;
        for (&s, block) in ROOTS[m..2 * m].iter().zip(a.chunks_exact_mut(t)) {
            let (lo, hi) = block.split_at_mut(ht);
            for (x, y) in lo.iter_mut().zip(hi.iter_mut()) {
                // Each layer raises the bound by less than q: after 10 layers every value
                // is < 11q, so `*y * s < 10q * q < 2^32` never overflows.
                let v = *y * s % q;
                let u = *x;
                *x = u + v;
                *y = u + Q - v;
            }
        }
        t = ht;
        m <<= 1;
    }
    for x in a.iter_mut() {
        *x %= q;
    }
}

/// Inverse NTT (Gentleman–Sande, as `mq_iNTT`) including the `1/n` scaling. Input `< q`;
/// output `< q`.
fn intt(a: &mut [u32; N]) {
    let q = modulus();
    let mut t = 1;
    let mut m = N;
    while m > 1 {
        let hm = m >> 1;
        let dt = t << 1;
        for (&s, block) in INV_ROOTS[hm..2 * hm].iter().zip(a.chunks_exact_mut(dt)) {
            let (lo, hi) = block.split_at_mut(t);
            for (x, y) in lo.iter_mut().zip(hi.iter_mut()) {
                let (u, v) = (*x, *y);
                let sum = u + v;
                *x = if sum >= Q { sum - Q } else { sum };
                *y = (u + Q - v) * s % q;
            }
        }
        t = dt;
        m = hm;
    }
    for x in a.iter_mut() {
        *x = *x * N_INV % q;
    }
}

/// `s2·h - c0` in `Z_q[x]/(x^1024 + 1)`, centered into `[-q/2, q/2]`. This is vrfy.c's
/// `-s1`; the sign does not matter for the norm.
fn compute_s1(c0: &[u16; N], s2: &[i16; N], mut h: [u32; N]) -> [i16; N] {
    let mut t = [0u32; N];
    for (t, &s) in t.iter_mut().zip(s2.iter()) {
        *t = if s < 0 {
            (s as i32 + Q as i32) as u32
        } else {
            s as u32
        };
    }
    track!("falcon-ntt", ntt(&mut h));
    track!("falcon-ntt", ntt(&mut t));
    let q = modulus();
    for (t, &hv) in t.iter_mut().zip(h.iter()) {
        *t = *t * hv % q;
    }
    track!("falcon-intt", intt(&mut t));
    let mut s1 = [0i16; N];
    for ((s, &tv), &c) in s1.iter_mut().zip(t.iter()).zip(c0.iter()) {
        let d = tv + Q - c as u32;
        let d = if d >= Q { d - Q } else { d };
        *s = (if d > Q / 2 {
            d as i32 - Q as i32
        } else {
            d as i32
        }) as i16;
    }
    s1
}

/// `Zf(is_short)`: squared l2 norm of `(s1, s2)` with saturation, compared to the bound.
fn is_short(s1: &[i16; N], s2: &[i16; N]) -> bool {
    let mut s: u32 = 0;
    let mut ng: u32 = 0;
    for u in 0..N {
        let z = s1[u] as i32;
        s = s.wrapping_add((z * z) as u32);
        ng |= s;
        let z = s2[u] as i32;
        s = s.wrapping_add((z * z) as u32);
        ng |= s;
    }
    s |= (ng >> 31).wrapping_neg();
    s <= L2_BOUND
}

// ---------------------------------------------------------------------------------------
// Encodings.

/// `Zf(modq_decode)` for n = 1024: 14-bit big-endian packed coefficients, each < q.
/// 1024 coefficients fill exactly 1792 bytes, so there are no trailing bits; every 7 bytes
/// hold 4 coefficients.
fn modq_decode(input: &[u8]) -> Option<[u32; N]> {
    const IN_LEN: usize = (N * 14 + 7) >> 3; // 1792
    if input.len() != IN_LEN {
        return None;
    }
    let mut h = [0u32; N];
    for (group, out) in input.chunks_exact(7).zip(h.chunks_exact_mut(4)) {
        let acc = group.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
        for (k, coef) in out.iter_mut().enumerate() {
            let w = ((acc >> (42 - 14 * k)) & 0x3FFF) as u32;
            if w >= Q {
                return None;
            }
            *coef = w;
        }
    }
    Some(h)
}

/// `Zf(comp_decode)`: Falcon's compressed (Golomb–Rice style) encoding of s2.
/// Returns the coefficients and the number of bytes consumed.
fn comp_decode(input: &[u8]) -> Option<([i16; N], usize)> {
    let mut x = [0i16; N];
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mut v = 0usize;
    for coef in x.iter_mut() {
        // Next eight bits: sign and low seven bits of the absolute value.
        if v >= input.len() {
            return None;
        }
        acc = (acc << 8) | input[v] as u32;
        v += 1;
        let b = acc >> acc_len;
        let s = b & 128;
        let mut m = b & 127;
        // High bits in unary, terminated by a 1.
        loop {
            if acc_len == 0 {
                if v >= input.len() {
                    return None;
                }
                acc = (acc << 8) | input[v] as u32;
                v += 1;
                acc_len = 8;
            }
            acc_len -= 1;
            if (acc >> acc_len) & 1 != 0 {
                break;
            }
            m += 128;
            if m > 2047 {
                return None;
            }
        }
        // "-0" is forbidden.
        if s != 0 && m == 0 {
            return None;
        }
        *coef = if s != 0 { -(m as i32) as i16 } else { m as i16 };
    }
    // Unused bits in the last byte must be zero.
    if acc & ((1u32 << acc_len) - 1) != 0 {
        return None;
    }
    Some((x, v))
}

/// `Zf(trim_i16_encode)` with 12 bits per coefficient (the CT signature body).
fn ct_encode_body(s2: &[i16; N], out: &mut [u8]) {
    debug_assert_eq!(out.len(), (N * CT_BITS as usize) / 8);
    let mask = (1u32 << CT_BITS) - 1;
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mut o = 0;
    for &c in s2.iter() {
        acc = (acc << CT_BITS) | (c as u16 as u32 & mask);
        acc_len += CT_BITS;
        while acc_len >= 8 {
            acc_len -= 8;
            out[o] = (acc >> acc_len) as u8;
            o += 1;
        }
    }
}

/// A decoded deterministic Falcon-1024 signature.
pub struct DetSignature {
    pub salt_version: u8,
    pub s2: [i16; N],
}

impl DetSignature {
    /// Decodes a compressed det1024 signature. Accepts exactly the signatures accepted by
    /// `falcon_det1024_convert_compressed_to_ct` (header, exact consumption, canonical bits).
    pub fn decode_compressed(sig: &[u8]) -> Result<Self> {
        if sig.len() < 2 || sig[0] != SIG_COMPRESSED_HEADER {
            return Err(Error::FalconFormat);
        }
        let (s2, used) = comp_decode(&sig[2..]).ok_or(Error::FalconFormat)?;
        if used != sig.len() - 2 {
            return Err(Error::FalconFormat);
        }
        Ok(Self {
            salt_version: sig[1],
            s2,
        })
    }

    /// The fixed-length CT encoding (`CompressedSignature.ConvertToCT`), which is what the
    /// state proof signature commitment hashes. comp_decode bounds |s2[i]| <= 2047, so the
    /// 12-bit encoding cannot fail.
    pub fn to_ct(&self) -> [u8; CT_SIG_SIZE] {
        let mut out = [0u8; CT_SIG_SIZE];
        out[0] = SIG_CT_HEADER;
        out[1] = self.salt_version;
        ct_encode_body(&self.s2, &mut out[2..]);
        out
    }

    /// Verifies this signature over `msg` under `pubkey` (`falcon_det1024_verify_*`).
    pub fn verify(&self, pubkey: &[u8], msg: &[u8]) -> Result<()> {
        if pubkey.len() != PUBKEY_SIZE || pubkey[0] != PUBKEY_HEADER {
            return Err(Error::FalconFormat);
        }
        let h = track!("falcon-pubkey", modq_decode(&pubkey[1..])).ok_or(Error::FalconFormat)?;
        let c0 = track!(
            "falcon-hash-to-point",
            hash_to_point(self.salt_version, msg)
        );
        let s1 = track!("falcon-s1", compute_s1(&c0, &self.s2, h));
        if track!("falcon-norm", is_short(&s1, &self.s2)) {
            Ok(())
        } else {
            Err(Error::FalconBadSignature)
        }
    }
}

/// Verifies a compressed deterministic Falcon-1024 signature (`PublicKey.Verify`).
pub fn verify_compressed(pubkey: &[u8], sig: &[u8], msg: &[u8]) -> Result<()> {
    if sig.len() > COMPRESSED_SIG_MAX_SIZE {
        return Err(Error::FalconFormat);
    }
    DetSignature::decode_compressed(sig)?.verify(pubkey, msg)
}

/// The fixed 40-byte salt of a deterministic signature (`falcon_det1024_write_salt`).
pub fn salt(salt_version: u8) -> [u8; 40] {
    let mut s = [0u8; 40];
    s[0] = salt_version;
    s[1] = LOGN as u8;
    s[2..12].copy_from_slice(b"FALCON_DET");
    s
}

/// `Zf(hash_to_point_vartime)` over `SHAKE256(salt || msg)`.
fn hash_to_point(salt_version: u8, msg: &[u8]) -> [u16; N] {
    let mut xof = Shake256::default();
    xof.update(&salt(salt_version));
    xof.update(msg);
    let mut reader = xof.finalize_xof();

    let mut c = [0u16; N];
    let mut buf = [0u8; 272]; // two SHAKE256 rate blocks per refill
    let mut pos = buf.len();
    let mut n = 0;
    while n < N {
        if pos == buf.len() {
            reader.read(&mut buf);
            pos = 0;
        }
        let mut w = ((buf[pos] as u32) << 8) | buf[pos + 1] as u32;
        pos += 2;
        if w < 61445 {
            while w >= Q {
                w -= Q;
            }
            c[n] = w as u16;
            n += 1;
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    /// vrfy.c's Montgomery-form NTT, kept as an oracle for the arithmetic above.
    mod reference {
        use super::super::{modpow, rev10, N, Q};

        const Q0I: u32 = 12287; // -1/q mod 2^16
        const R: u32 = 4091; // 2^16 mod q
        const R2: u32 = 10952; // 2^32 mod q

        const fn table(g: u32) -> [u16; N] {
            let mut t = [0u16; N];
            let mut x = 0;
            while x < N {
                t[x] = (R * modpow(g, rev10(x)) % Q) as u16;
                x += 1;
            }
            t
        }

        /// GMb / iGMb: `R * psi^(±rev10(x)) mod q`.
        pub static GMB: [u16; N] = table(7);
        pub static IGMB: [u16; N] = table(modpow(7, Q - 2));

        fn mq_add(x: u32, y: u32) -> u32 {
            let d = x.wrapping_add(y).wrapping_sub(Q);
            d.wrapping_add(Q & (d >> 31).wrapping_neg())
        }

        fn mq_sub(x: u32, y: u32) -> u32 {
            let d = x.wrapping_sub(y);
            d.wrapping_add(Q & (d >> 31).wrapping_neg())
        }

        fn mq_rshift1(x: u32) -> u32 {
            x.wrapping_add(Q & (x & 1).wrapping_neg()) >> 1
        }

        fn mq_montymul(x: u32, y: u32) -> u32 {
            let z = x.wrapping_mul(y);
            let w = (z.wrapping_mul(Q0I) & 0xFFFF).wrapping_mul(Q);
            let z = (z.wrapping_add(w) >> 16).wrapping_sub(Q);
            z.wrapping_add(Q & (z >> 31).wrapping_neg())
        }

        fn mq_ntt(a: &mut [u16; N]) {
            let (mut t, mut m) = (N, 1);
            while m < N {
                let ht = t >> 1;
                let mut j1 = 0;
                for i in 0..m {
                    let s = GMB[m + i] as u32;
                    for j in j1..j1 + ht {
                        let u = a[j] as u32;
                        let v = mq_montymul(a[j + ht] as u32, s);
                        a[j] = mq_add(u, v) as u16;
                        a[j + ht] = mq_sub(u, v) as u16;
                    }
                    j1 += t;
                }
                t = ht;
                m <<= 1;
            }
        }

        fn mq_intt(a: &mut [u16; N]) {
            let (mut t, mut m) = (1, N);
            while m > 1 {
                let hm = m >> 1;
                let dt = t << 1;
                let mut j1 = 0;
                for i in 0..hm {
                    let s = IGMB[hm + i] as u32;
                    for j in j1..j1 + t {
                        let u = a[j] as u32;
                        let v = a[j + t] as u32;
                        a[j] = mq_add(u, v) as u16;
                        a[j + t] = mq_montymul(mq_sub(u, v), s) as u16;
                    }
                    j1 += dt;
                }
                t = dt;
                m = hm;
            }
            let mut ni = R;
            let mut m = N;
            while m > 1 {
                ni = mq_rshift1(ni);
                m >>= 1;
            }
            for x in a.iter_mut() {
                *x = mq_montymul(*x as u32, ni) as u16;
            }
        }

        /// vrfy.c `to_ntt_monty` + `verify_raw` up to the norm check.
        pub fn s1(c0: &[u16; N], s2: &[i16; N], h: &[u16; N]) -> [i16; N] {
            let mut h = *h;
            mq_ntt(&mut h);
            for x in h.iter_mut() {
                *x = mq_montymul(*x as u32, R2) as u16;
            }
            let mut tt = [0u16; N];
            for (t, &s) in tt.iter_mut().zip(s2.iter()) {
                let w = s as i32 as u32;
                *t = w.wrapping_add(Q & (w >> 31).wrapping_neg()) as u16;
            }
            mq_ntt(&mut tt);
            for (t, &hv) in tt.iter_mut().zip(h.iter()) {
                *t = mq_montymul(*t as u32, hv as u32) as u16;
            }
            mq_intt(&mut tt);
            let mut s1 = [0i16; N];
            for u in 0..N {
                let w = mq_sub(tt[u] as u32, c0[u] as u32) as i32;
                let w = w - (Q & ((Q >> 1).wrapping_sub(w as u32) >> 31).wrapping_neg()) as i32;
                s1[u] = w as i16;
            }
            s1
        }
    }

    /// vrfy.c's bit-serial `modq_decode`.
    fn modq_decode_reference(input: &[u8]) -> Option<[u32; N]> {
        let mut h = [0u32; N];
        let (mut acc, mut acc_len, mut u, mut i) = (0u32, 0u32, 0, 0);
        while u < N {
            acc = (acc << 8) | input[i] as u32;
            i += 1;
            acc_len += 8;
            if acc_len >= 14 {
                acc_len -= 14;
                let w = (acc >> acc_len) & 0x3FFF;
                if w >= Q {
                    return None;
                }
                h[u] = w;
                u += 1;
            }
        }
        Some(h)
    }

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn reference_tables_match_vrfy_c() {
        // First rows of GMb / iGMb in falcon/vrfy.c.
        assert_eq!(
            &reference::GMB[..8],
            &[4091, 7888, 11060, 11208, 6960, 4342, 6275, 9759]
        );
        assert_eq!(
            &reference::GMB[1016..],
            &[6261, 5887, 2652, 10172, 1580, 10379, 4638, 9949]
        );
        assert_eq!(
            &reference::IGMB[..8],
            &[4091, 4401, 1081, 1229, 2530, 6014, 7947, 5329]
        );
    }

    #[test]
    fn ntt_roundtrip_is_identity() {
        let mut a = [0u32; N];
        for (i, x) in a.iter_mut().enumerate() {
            *x = ((i * 7919 + 13) % Q as usize) as u32;
        }
        let orig = a;
        ntt(&mut a);
        intt(&mut a);
        assert_eq!(a, orig);
    }

    #[test]
    fn fast_arithmetic_matches_reference() {
        let mut rng = 0x9e37_79b9_7f4a_7c15u64;
        let check = |h: [u32; N], s2: [i16; N], c0: [u16; N]| {
            let h16: [u16; N] = core::array::from_fn(|i| h[i] as u16);
            assert_eq!(compute_s1(&c0, &s2, h), reference::s1(&c0, &s2, &h16));
        };
        // Extremes: zero, q - 1 everywhere, and the largest |s2| comp_decode allows.
        check([0; N], [0; N], [0; N]);
        check([Q - 1; N], [2047; N], [Q as u16 - 1; N]);
        check([Q - 1; N], [-2047; N], [0; N]);
        for _ in 0..200 {
            let h = core::array::from_fn(|_| (xorshift(&mut rng) % Q as u64) as u32);
            let s2 = core::array::from_fn(|_| (xorshift(&mut rng) % 4095) as i16 - 2047);
            let c0 = core::array::from_fn(|_| (xorshift(&mut rng) % Q as u64) as u16);
            check(h, s2, c0);
        }
    }

    #[test]
    fn modq_decode_matches_reference() {
        let mut rng = 0x2545_f491_4f6c_dd1du64;
        for case in 0..100 {
            // Coefficients near q so some cases are rejected, like invalid keys.
            let limit = if case % 4 == 0 { 0x4000 } else { Q as u64 };
            let mut bits = alloc::vec::Vec::new();
            for _ in 0..N {
                bits.push(xorshift(&mut rng) % limit);
            }
            let mut packed = alloc::vec![0u8; 1792];
            for (k, &c) in bits.iter().enumerate() {
                for bit in 0..14 {
                    if (c >> (13 - bit)) & 1 == 1 {
                        let pos = 14 * k + bit;
                        packed[pos / 8] |= 0x80 >> (pos % 8);
                    }
                }
            }
            assert_eq!(modq_decode(&packed), modq_decode_reference(&packed));
        }
    }

    #[test]
    fn salt_layout() {
        let s = salt(0);
        assert_eq!(s[0], 0);
        assert_eq!(s[1], 10);
        assert_eq!(&s[2..12], b"FALCON_DET");
        assert!(s[12..].iter().all(|&b| b == 0));
    }
}

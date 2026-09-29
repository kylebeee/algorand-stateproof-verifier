//! `crypto/stateproof/weights.go`: checks that a state proof reveals enough positions for
//! its signed weight to imply, with `strengthTarget` bits of security, that more than the
//! proven weight actually signed.
//!
//! The verifier checks (with P = lnProvenWeight, T = ln2IntApproximation, b = 16 bits of
//! precision, d = bitlen(signedWeight) - 1):
//!
//! ```text
//! numReveals · (3·2^b·(sw² − 2^2d) + d·(T−1)·Y)  >=  (strengthTarget·T + numReveals·P) · Y
//! where Y = 2^2d + 2^(d+2)·sw + sw²
//! ```
//!
//! Intermediate values reach ~2^205, so this uses a small 256-bit unsigned integer.

use crate::decode::MAX_REVEALS;
use crate::error::{Error, Result};
use core::cmp::Ordering;

const PRECISION_BITS: u32 = 16;
/// `ceil(2^16 · ln 2)`.
pub const LN2_INT_APPROXIMATION: u64 = 45427;

/// Little-endian 256-bit unsigned integer (only the operations needed here).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct U256([u64; 4]);

impl U256 {
    const fn from_u128(x: u128) -> Self {
        U256([x as u64, (x >> 64) as u64, 0, 0])
    }

    fn pow2(n: u32) -> Self {
        assert!(n < 256);
        let mut limbs = [0u64; 4];
        limbs[(n / 64) as usize] = 1 << (n % 64);
        U256(limbs)
    }

    fn add(self, o: Self) -> Self {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for (i, limb) in out.iter_mut().enumerate() {
            let (s1, c1) = self.0[i].overflowing_add(o.0[i]);
            let (s2, c2) = s1.overflowing_add(carry);
            *limb = s2;
            carry = (c1 as u64) + (c2 as u64);
        }
        assert!(carry == 0, "U256 add overflow");
        U256(out)
    }

    fn sub(self, o: Self) -> Self {
        let mut out = [0u64; 4];
        let mut borrow = 0u64;
        for (i, limb) in out.iter_mut().enumerate() {
            let (d1, b1) = self.0[i].overflowing_sub(o.0[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            *limb = d2;
            borrow = (b1 as u64) + (b2 as u64);
        }
        assert!(borrow == 0, "U256 sub underflow");
        U256(out)
    }

    fn mul_u64(self, m: u64) -> Self {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for (i, limb) in out.iter_mut().enumerate() {
            let t = (self.0[i] as u128) * (m as u128) + carry;
            *limb = t as u64;
            carry = t >> 64;
        }
        assert!(carry == 0, "U256 mul overflow");
        U256(out)
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        Ordering::Equal
    }
}

/// `getSubExpressions`: returns (y, x, w). Requires `signed_weight > 0`.
fn sub_expressions(signed_weight: u64) -> (U256, U256, u64) {
    let d = 63 - signed_weight.leading_zeros(); // bits.Len64(sw) - 1
    let sw2 = U256::from_u128(signed_weight as u128 * signed_weight as u128);
    let tmp = U256::pow2(d + 2).mul_u64(signed_weight);
    let y = U256::pow2(2 * d).add(tmp).add(sw2);
    let x = sw2
        .sub(U256::pow2(2 * d))
        .mul_u64(3)
        .mul_u64(1 << PRECISION_BITS);
    let w = d as u64 * (LN2_INT_APPROXIMATION - 1);
    (y, x, w)
}

/// `verifyWeights`.
pub fn verify_weights(
    signed_weight: u64,
    ln_proven_weight: u64,
    num_reveals: u64,
    strength_target: u64,
) -> Result<()> {
    if num_reveals > MAX_REVEALS as u64 {
        return Err(Error::TooManyReveals);
    }
    if signed_weight == 0 {
        return Err(Error::ZeroSignedWeight);
    }
    let (y, x, w) = sub_expressions(signed_weight);
    let lhs = y.mul_u64(w).add(x).mul_u64(num_reveals);
    let rhs_factor = strength_target as u128 * LN2_INT_APPROXIMATION as u128
        + num_reveals as u128 * ln_proven_weight as u128;
    let rhs = y_mul_u128(y, rhs_factor);
    if lhs < rhs {
        return Err(Error::InsufficientSignedWeight);
    }
    Ok(())
}

fn y_mul_u128(y: U256, m: u128) -> U256 {
    // y · m = y · lo + (y · hi) · 2^64, with hi < 2^64.
    let lo = y.mul_u64(m as u64);
    let hi = y.mul_u64((m >> 64) as u64);
    let shifted = U256([0, hi.0[0], hi.0[1], hi.0[2]]);
    assert!(hi.0[3] == 0, "U256 mul overflow");
    lo.add(shifted)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference implementation in f64-free exact arithmetic via u128 where it fits, to
    /// cross-check the U256 path on small weights.
    fn reference(sw: u64, p: u64, nr: u64, t: u64) -> bool {
        let d = 63 - sw.leading_zeros() as u128;
        let sw = sw as u128;
        let y = (1u128 << (2 * d)) + (1u128 << (d + 2)) * sw + sw * sw;
        let x = (sw * sw - (1u128 << (2 * d))) * 3 * (1 << 16);
        let w = d * (LN2_INT_APPROXIMATION as u128 - 1);
        let lhs = nr as u128 * (x + w * y);
        let rhs = (t as u128 * LN2_INT_APPROXIMATION as u128 + nr as u128 * p as u128) * y;
        lhs >= rhs
    }

    #[test]
    fn matches_u128_reference_on_small_weights() {
        for sw in [1u64, 2, 3, 100, 1000, 65_535, 1 << 20, (1 << 24) + 12345] {
            for p in [0u64, 1000, 100_000, 500_000] {
                for nr in [0u64, 1, 50, 200, 640] {
                    let ok = verify_weights(sw, p, nr, 256).is_ok();
                    assert_eq!(ok, reference(sw, p, nr, 256), "sw={sw} p={p} nr={nr}");
                }
            }
        }
    }

    #[test]
    fn rejects_degenerate_inputs() {
        assert_eq!(verify_weights(0, 0, 10, 256), Err(Error::ZeroSignedWeight));
        assert_eq!(verify_weights(10, 0, 641, 256), Err(Error::TooManyReveals));
        // More reveals never hurt: if n reveals suffice, so do n + 1.
        let sw = 5_000_000_000_000_000u64;
        let p = 2_230_000; // ~ ln(0.3 * total stake) with 16 bits of precision
        let first_ok = (1..=640)
            .find(|&nr| verify_weights(sw, p, nr, 256).is_ok())
            .unwrap();
        assert!((first_ok..=640).all(|nr| verify_weights(sw, p, nr, 256).is_ok()));
    }
}

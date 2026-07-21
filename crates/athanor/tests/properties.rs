//! Property-based tests.
//!
//! The headline property is the first one: *any* byte string is a program,
//! and no program may abort the process. Everything an adversary controls
//! goes through this interpreter, so panic-freedom is a security property,
//! not a style preference. The rest pin algebraic laws of the signed
//! arithmetic that unit tests can only spot-check.

mod common;

use athanor::{i256, U256};
use common::run;
use proptest::prelude::*;

fn u256(bytes: [u8; 32]) -> U256 {
    U256::from_big_endian(&bytes)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn arbitrary_bytecode_never_panics(code in proptest::collection::vec(any::<u8>(), 0..512)) {
        // Outcome is irrelevant; returning at all is the assertion.
        let _ = run(code);
    }

    /// Truncating signed division: q*b + r == a under wrapping arithmetic,
    /// for every pair — including MIN / -1, where q wraps to MIN.
    #[test]
    fn sdiv_smod_reconstruct(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        let (a, b) = (u256(a), u256(b));
        prop_assume!(!b.is_zero());
        let q = i256::sdiv(a, b);
        let r = i256::smod(a, b);
        prop_assert_eq!(q.overflowing_mul(b).0.overflowing_add(r).0, a);
    }

    /// For non-negative values an arithmetic shift is a logical shift.
    #[test]
    fn sar_matches_shr_when_sign_clear(shift in 0u64..300, mut v in any::<[u8; 32]>()) {
        v[0] &= 0x7f;
        let value = u256(v);
        let shift = U256::from(shift);
        let logical = if shift >= U256::from(256u64) { U256::zero() } else { value >> shift.as_usize() };
        prop_assert_eq!(i256::sar(shift, value), logical);
    }

    /// SIGNEXTEND is idempotent: extending twice at the same byte index
    /// changes nothing the first pass didn't.
    #[test]
    fn signextend_is_idempotent(k in any::<[u8; 32]>(), x in any::<[u8; 32]>()) {
        let (k, x) = (u256(k), u256(x));
        let once = i256::signextend(k, x);
        prop_assert_eq!(i256::signextend(k, once), once);
    }

    /// Signed comparison is a strict total order: exactly one of
    /// `a < b`, `b < a`, `a == b`.
    #[test]
    fn slt_trichotomy(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        let (a, b) = (u256(a), u256(b));
        let truths = [i256::slt(a, b), i256::slt(b, a), a == b];
        prop_assert_eq!(truths.iter().filter(|&&t| t).count(), 1);
    }
}

//! Two's-complement views over `U256`.
//!
//! The EVM has no signed word type; `SDIV`, `SMOD`, `SLT`, `SGT`, `SAR` and
//! `SIGNEXTEND` reinterpret the same 256 bits. The one genuinely dangerous
//! corner is `SDIV(i256::MIN, -1)`: the true quotient 2^255 does not exist,
//! and the spec pins the result to `i256::MIN` itself (YP eq. (E.3), same
//! wrap the hardware gives you for `INT_MIN / -1` when it doesn't trap).

use crate::primitives::U256;

pub const SIGN_BIT: usize = 255;

#[inline]
pub fn is_negative(x: U256) -> bool {
    x.bit(SIGN_BIT)
}

/// `i256::MIN`, i.e. `-2^255`, i.e. `1 << 255`.
#[inline]
pub fn min_value() -> U256 {
    U256::one() << SIGN_BIT
}

/// Two's-complement negation. `neg(0) == 0`, `neg(MIN) == MIN`.
#[inline]
pub fn neg(x: U256) -> U256 {
    (!x).overflowing_add(U256::one()).0
}

#[inline]
fn abs(x: U256) -> U256 {
    if is_negative(x) {
        neg(x)
    } else {
        x
    }
}

pub fn sdiv(a: U256, b: U256) -> U256 {
    if b.is_zero() {
        return U256::zero();
    }
    if a == min_value() && b == U256::MAX {
        // MIN / -1 overflows; defined to wrap to MIN.
        return min_value();
    }
    let q = abs(a) / abs(b);
    if is_negative(a) != is_negative(b) {
        neg(q)
    } else {
        q
    }
}

/// Sign of the result follows the *dividend*, matching C99 `%` and the
/// Yellow Paper: `smod(-8, 3) == -2`, `smod(8, -3) == 2`.
pub fn smod(a: U256, b: U256) -> U256 {
    if b.is_zero() {
        return U256::zero();
    }
    let r = abs(a) % abs(b);
    if is_negative(a) {
        neg(r)
    } else {
        r
    }
}

pub fn slt(a: U256, b: U256) -> bool {
    match (is_negative(a), is_negative(b)) {
        (true, false) => true,
        (false, true) => false,
        // Same sign: two's complement preserves unsigned ordering.
        _ => a < b,
    }
}

/// Arithmetic shift right. Shifts of 256 or more saturate to the sign fill.
pub fn sar(shift: U256, value: U256) -> U256 {
    let negative = is_negative(value);
    if shift >= U256::from(256) {
        return if negative { U256::MAX } else { U256::zero() };
    }
    let s = shift.as_usize();
    if s == 0 {
        return value;
    }
    let logical = value >> s;
    if negative {
        // Fill the vacated high `s` bits with ones.
        logical | (U256::MAX << (256 - s))
    } else {
        logical
    }
}

/// `SIGNEXTEND(k, x)`: treat `x` as a signed integer of `k + 1` bytes and
/// widen it to 256 bits. `k >= 31` is the identity.
pub fn signextend(k: U256, x: U256) -> U256 {
    if k >= U256::from(31) {
        return x;
    }
    let bit = k.as_usize() * 8 + 7;
    if x.bit(bit) {
        x | (U256::MAX << (bit + 1))
    } else {
        x & ((U256::one() << (bit + 1)) - U256::one())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(v: i64) -> U256 {
        if v >= 0 {
            U256::from(v as u64)
        } else {
            neg(U256::from((-v) as u64))
        }
    }

    #[test]
    fn division_sign_matrix() {
        assert_eq!(sdiv(u(7), u(2)), u(3));
        assert_eq!(sdiv(u(-7), u(2)), u(-3));
        assert_eq!(sdiv(u(7), u(-2)), u(-3));
        assert_eq!(sdiv(u(-7), u(-2)), u(3));
        assert_eq!(sdiv(u(1), U256::zero()), U256::zero());
    }

    #[test]
    fn division_min_by_minus_one_wraps() {
        assert_eq!(sdiv(min_value(), U256::MAX), min_value());
        // While a plain MIN / 1 is exact.
        assert_eq!(sdiv(min_value(), u(1)), min_value());
    }

    #[test]
    fn modulo_follows_dividend() {
        assert_eq!(smod(u(8), u(3)), u(2));
        assert_eq!(smod(u(-8), u(3)), u(-2));
        assert_eq!(smod(u(8), u(-3)), u(2));
        assert_eq!(smod(u(-8), u(-3)), u(-2));
        assert_eq!(smod(u(3), U256::zero()), U256::zero());
    }

    #[test]
    fn signed_comparison() {
        assert!(slt(u(-1), u(0)));
        assert!(slt(u(-2), u(-1)));
        assert!(slt(u(1), u(2)));
        assert!(!slt(u(0), u(-1)));
        assert!(slt(min_value(), U256::MAX)); // MIN < -1
    }

    #[test]
    fn arithmetic_shift() {
        assert_eq!(sar(U256::from(1), u(-4)), u(-2));
        assert_eq!(sar(U256::from(1), u(4)), u(2));
        assert_eq!(sar(U256::from(300), u(-1)), U256::MAX);
        assert_eq!(sar(U256::from(300), u(1)), U256::zero());
        assert_eq!(sar(U256::zero(), u(-5)), u(-5));
        assert_eq!(sar(U256::from(255), min_value()), U256::MAX);
    }

    #[test]
    fn sign_extension() {
        // 0xff as a 1-byte value is -1.
        assert_eq!(signextend(U256::zero(), U256::from(0xff)), U256::MAX);
        // 0x7f stays positive.
        assert_eq!(signextend(U256::zero(), U256::from(0x7f)), U256::from(0x7f));
        // High garbage above the chosen width is masked off.
        assert_eq!(
            signextend(U256::zero(), U256::from(0x1234)),
            U256::from(0x34)
        );
        // k >= 31 is the identity.
        assert_eq!(signextend(U256::from(31), U256::MAX), U256::MAX);
        assert_eq!(signextend(U256::from(500), u(-1)), U256::MAX);
    }
}

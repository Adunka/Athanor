//! Gas accounting.
//!
//! One counter per frame, refunds tracked signed (EIP-2200 both credits and
//! debits the counter), and the SSTORE pricing function kept in one place —
//! it is the single most revised piece of the fee schedule (EIP-1087, 1283,
//! 2200, 2929, 3529) and the easiest to get subtly wrong when spread across
//! call sites.

use crate::primitives::U256;
use crate::result::Halt;

#[derive(Debug, Clone, Copy)]
pub struct Gas {
    limit: u64,
    remaining: u64,
    refunded: i64,
}

impl Gas {
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            remaining: limit,
            refunded: 0,
        }
    }

    #[inline]
    pub fn limit(&self) -> u64 {
        self.limit
    }

    #[inline]
    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    #[inline]
    pub fn spent(&self) -> u64 {
        self.limit - self.remaining
    }

    #[inline]
    pub fn refunded(&self) -> i64 {
        self.refunded
    }

    #[inline]
    pub fn record(&mut self, cost: u64) -> Result<(), Halt> {
        match self.remaining.checked_sub(cost) {
            Some(left) => {
                self.remaining = left;
                Ok(())
            }
            None => {
                self.remaining = 0;
                Err(Halt::OutOfGas)
            }
        }
    }

    /// Return unused gas from a finished child frame.
    #[inline]
    pub fn credit(&mut self, returned: u64) {
        self.remaining += returned;
    }

    #[inline]
    pub fn record_refund(&mut self, delta: i64) {
        self.refunded += delta;
    }

    /// Exceptional halt: the frame forfeits everything it was given.
    #[inline]
    pub fn consume_all(&mut self) {
        self.remaining = 0;
    }
}

/// The fee schedule, YP appendix G plus the EIPs that amended it.
/// Berlin/London/Shanghai/Cancun values.
pub mod cost {
    pub const KECCAK256_WORD: u64 = 6;
    pub const COPY_WORD: u64 = 3;
    pub const EXP_BYTE: u64 = 50; // EIP-160
    pub const LOG_DATA: u64 = 8;
    pub const LOG_TOPIC: u64 = 375;

    // EIP-2929 access lists.
    pub const COLD_ACCOUNT_ACCESS: u64 = 2600;
    pub const COLD_SLOAD: u64 = 2100;
    pub const WARM_ACCESS: u64 = 100;

    // SSTORE, post-Berlin/London.
    pub const SSTORE_SET: u64 = 20_000;
    pub const SSTORE_RESET: u64 = 5000 - COLD_SLOAD; // 2900
    pub const SSTORE_CLEARS_REFUND: u64 = 4800; // EIP-3529
    /// EIP-2200: SSTORE aborts outright if less than this remains, so the
    /// 2300 call stipend can never mutate state.
    pub const SSTORE_SENTRY: u64 = 2300;

    // Calls.
    pub const CALL_VALUE: u64 = 9000;
    pub const CALL_STIPEND: u64 = 2300;
    pub const NEW_ACCOUNT: u64 = 25_000;

    // Creation.
    pub const CODE_DEPOSIT_BYTE: u64 = 200;
    pub const INITCODE_WORD: u64 = 2; // EIP-3860
    pub const MAX_CODE_SIZE: usize = 24_576; // EIP-170
    pub const MAX_INITCODE_SIZE: usize = 2 * MAX_CODE_SIZE; // EIP-3860

    pub const SELFDESTRUCT_NEW_ACCOUNT: u64 = 25_000;

    // Transactions.
    pub const TX_BASE: u64 = 21_000;
    pub const TX_CREATE: u64 = 32_000;
    pub const TX_DATA_ZERO: u64 = 4;
    pub const TX_DATA_NONZERO: u64 = 16; // EIP-2028

    /// Per-entry intrinsic cost of an EIP-2930 access list.
    pub const ACCESS_LIST_ADDRESS: u64 = 2400;
    pub const ACCESS_LIST_STORAGE_KEY: u64 = 1900;

    /// Identity precompile (0x04), YP appendix E.
    pub const IDENTITY_BASE: u64 = 15;
    pub const IDENTITY_WORD: u64 = 3;

    /// SHA-256 precompile (0x02).
    pub const SHA256_BASE: u64 = 60;
    pub const SHA256_WORD: u64 = 12;

    /// RIPEMD-160 precompile (0x03).
    pub const RIPEMD160_BASE: u64 = 600;
    pub const RIPEMD160_WORD: u64 = 120;

    /// ecrecover precompile (0x01): a flat fee.
    pub const ECRECOVER: u64 = 3000;

    /// modexp (0x05, EIP-2565): the gas floor.
    pub const MODEXP_MIN: u64 = 200;

    /// bn256 curve precompiles (0x06/0x07/0x08), repriced by EIP-1108.
    pub const BN_ADD: u64 = 150;
    pub const BN_MUL: u64 = 6000;
    pub const BN_PAIRING_BASE: u64 = 45_000;
    pub const BN_PAIRING_PER_PAIR: u64 = 34_000;
}

/// `len` bytes rounded up to words, times `per_word`. Saturates: a value
/// this produces is always fed into `Gas::record`, where saturation just
/// means certain out-of-gas.
#[inline]
pub fn word_cost(len: u64, per_word: u64) -> u64 {
    len.div_ceil(32).saturating_mul(per_word)
}

/// EIP-150: a call may forward at most 63/64 of what remains.
#[inline]
pub fn all_but_one_64th(gas: u64) -> u64 {
    gas - gas / 64
}

/// Dynamic gas of `EXP`: 50 per byte of the exponent's minimal
/// big-endian encoding.
#[inline]
pub fn exp_cost(exponent: U256) -> u64 {
    let bytes = (exponent.bits() as u64).div_ceil(8);
    cost::EXP_BYTE * bytes
}

/// SSTORE cost and refund delta given `(original, current, new)` — the
/// value at transaction start, the value now, and the value being written —
/// plus slot temperature. Net-metering per EIP-2200 with Berlin (EIP-2929)
/// prices and London (EIP-3529) refunds.
pub fn sstore(original: U256, current: U256, new: U256, is_cold: bool) -> (u64, i64) {
    let mut cost = if is_cold { cost::COLD_SLOAD } else { 0 };
    let mut refund: i64 = 0;

    if new == current {
        // No-op write.
        cost += cost::WARM_ACCESS;
        return (cost, refund);
    }

    if current == original {
        // First write to this slot in the transaction.
        cost += if original.is_zero() {
            cost::SSTORE_SET
        } else {
            cost::SSTORE_RESET
        };
        if !original.is_zero() && new.is_zero() {
            refund += cost::SSTORE_CLEARS_REFUND as i64;
        }
        return (cost, refund);
    }

    // Dirty slot: every further write is cheap, refunds keep the net cost
    // equal to what the final (original -> new) transition would have been.
    cost += cost::WARM_ACCESS;
    if !original.is_zero() {
        if current.is_zero() {
            refund -= cost::SSTORE_CLEARS_REFUND as i64;
        } else if new.is_zero() {
            refund += cost::SSTORE_CLEARS_REFUND as i64;
        }
    }
    if new == original {
        refund += if original.is_zero() {
            (cost::SSTORE_SET - cost::WARM_ACCESS) as i64
        } else {
            (cost::SSTORE_RESET - cost::WARM_ACCESS) as i64
        };
    }
    (cost, refund)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(x: u64) -> U256 {
        U256::from(x)
    }

    #[test]
    fn record_and_out_of_gas() {
        let mut g = Gas::new(100);
        g.record(60).unwrap();
        assert_eq!(g.remaining(), 40);
        assert_eq!(g.spent(), 60);
        assert_eq!(g.record(41), Err(Halt::OutOfGas));
        assert_eq!(g.remaining(), 0);
    }

    #[test]
    fn sixty_three_sixty_fourths() {
        assert_eq!(all_but_one_64th(64), 63);
        assert_eq!(all_but_one_64th(6400), 6300);
        assert_eq!(all_but_one_64th(63), 63);
    }

    #[test]
    fn exp_byte_length() {
        assert_eq!(exp_cost(U256::zero()), 0);
        assert_eq!(exp_cost(v(1)), 50);
        assert_eq!(exp_cost(v(255)), 50);
        assert_eq!(exp_cost(v(256)), 100);
        assert_eq!(exp_cost(U256::MAX), 50 * 32);
    }

    /// The canonical Berlin/London SSTORE matrix, warm slots.
    /// Columns: original, current, new -> (cost, refund).
    #[test]
    fn sstore_matrix_warm() {
        let cases: &[(u64, u64, u64, u64, i64)] = &[
            (0, 0, 0, 100, 0),
            (0, 0, 1, 20_000, 0),
            (0, 1, 0, 100, 19_900),
            (0, 1, 2, 100, 0),
            (0, 1, 1, 100, 0), // no-op write to dirty slot
            (1, 0, 0, 100, 0), // dirty, stays cleared
            (1, 0, 1, 100, -4800 + 2800),
            (1, 0, 2, 100, -4800),
            (1, 1, 0, 2900, 4800),
            (1, 1, 2, 2900, 0),
            (1, 2, 0, 100, 4800),
            (1, 2, 1, 100, 2800),
            (1, 2, 3, 100, 0),
            (1, 2, 2, 100, 0),
        ];
        for &(o, c, n, cost, refund) in cases {
            assert_eq!(
                sstore(v(o), v(c), v(n), false),
                (cost, refund),
                "case ({o}, {c}, {n})"
            );
        }
    }

    #[test]
    fn sstore_cold_adds_2100() {
        assert_eq!(sstore(v(0), v(0), v(1), true), (22_100, 0));
        assert_eq!(sstore(v(1), v(1), v(0), true), (5000, 4800));
        assert_eq!(sstore(v(0), v(0), v(0), true), (2200, 0));
    }
}

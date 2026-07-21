//! Execution outcomes, from single-instruction failures up to whole
//! transaction results.

use crate::primitives::{Address, U256};
use crate::state::Log;

/// An exceptional halt. The current frame is aborted and *all* gas given to
/// it is consumed (Yellow Paper §9.4.1). Contrast with `REVERT`, which
/// returns remaining gas to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Halt {
    OutOfGas,
    StackUnderflow,
    StackOverflow,
    /// Jump destination is not a `JUMPDEST`, or points into push data.
    InvalidJump,
    /// Undefined opcode, or `INVALID` (0xFE) itself.
    InvalidOpcode(u8),
    /// State-modifying instruction inside a `STATICCALL` context (EIP-214).
    StaticViolation,
    /// `RETURNDATACOPY` past the end of the return buffer (EIP-211).
    ReturnDataOutOfBounds,
    /// Memory offset arithmetic overflowed the addressable range.
    MemoryLimit,
    /// Deployed code exceeds 24576 bytes (EIP-170).
    CodeSizeLimit,
    /// Init code exceeds 49152 bytes (EIP-3860).
    InitCodeSizeLimit,
    /// Deployed code starts with the 0xEF reserved byte (EIP-3541).
    InvalidCodeFirstByte,
    /// `CREATE`/`CREATE2` target address already has code or nonce.
    CreateCollision,
    /// Instruction defined by the spec but not yet implemented here.
    NotImplemented(u8),
    /// A precompile rejected its input (e.g. a bn256 point off the curve).
    /// The call fails and all forwarded gas is consumed.
    PrecompileError,
}

/// How a single call frame finished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// `STOP`, or running off the end of code. No return data.
    Stop,
    /// `RETURN` with the given data.
    Return(Vec<u8>),
    /// `REVERT` (EIP-140): state changes rolled back, remaining gas kept.
    Revert(Vec<u8>),
    /// `SELFDESTRUCT` (EIP-6780 semantics).
    SelfDestruct,
    /// Exceptional abort; consumes all frame gas.
    Halt(Halt),
}

impl Outcome {
    pub fn is_success(&self) -> bool {
        matches!(
            self,
            Outcome::Stop | Outcome::Return(_) | Outcome::SelfDestruct
        )
    }

    pub fn output(&self) -> &[u8] {
        match self {
            Outcome::Return(d) | Outcome::Revert(d) => d,
            _ => &[],
        }
    }

    pub fn into_output(self) -> Vec<u8> {
        match self {
            Outcome::Return(d) | Outcome::Revert(d) => d,
            _ => Vec::new(),
        }
    }
}

/// Errors detected before any EVM code runs. These abort the transaction
/// entirely; nothing is charged and no state is touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxError {
    /// `gas_limit * gas_price + value` exceeds the sender balance.
    InsufficientFunds {
        required: U256,
        available: U256,
    },
    /// Gas limit below the intrinsic cost of the transaction (YP eq. 60).
    IntrinsicGas {
        intrinsic: u64,
        limit: u64,
    },
    /// EIP-1559: the effective gas price is below the block base fee, so the
    /// transaction cannot cover the mandatory burn and is not included.
    GasPriceBelowBaseFee {
        gas_price: U256,
        basefee: U256,
    },
    /// Init code of a create transaction exceeds EIP-3860 limit.
    InitCodeSizeLimit,
    /// EIP-3607: the sender has deployed code; only EOAs may originate
    /// transactions.
    SenderNotEoa,
    /// The transaction's declared nonce does not match the account.
    NonceMismatch {
        state: u64,
        tx: u64,
    },
    /// EIP-2681: the sender nonce is already at 2^64 - 1 and cannot be
    /// incremented.
    NonceOverflow,
    Overflow,
}

/// What a create produced, when it succeeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxKind {
    Call,
    Create(Address),
}

/// The result of one full transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    pub outcome: Outcome,
    /// Gas actually charged to the sender, refunds already applied.
    pub gas_used: u64,
    /// Portion of `gas_used` that was returned via the refund counter,
    /// capped at `gas_used / 5` (EIP-3529).
    pub gas_refunded: u64,
    pub logs: Vec<Log>,
    pub kind: TxKind,
}

impl ExecutionResult {
    pub fn created(&self) -> Option<Address> {
        match self.kind {
            TxKind::Create(a) if self.outcome.is_success() => Some(a),
            _ => None,
        }
    }
}

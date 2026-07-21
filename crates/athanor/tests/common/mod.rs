//! Shared harness: a tiny assembler and a pre-seeded EVM.
//!
//! The assembler emits real bytecode — tests hand-compute jump offsets the
//! way you would reading a disassembly, which keeps them honest about the
//! actual encoding (push widths, immediate placement).

// Each integration-test binary compiles this module independently, so
// helpers used by one binary register as dead code in another.
#![allow(dead_code)]

use athanor::opcode as op;
use athanor::primitives::address_to_u256;
use athanor::{Account, Address, Env, Evm, ExecutionResult, U256};

pub struct Asm(Vec<u8>);

impl Asm {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn op(mut self, opcode: u8) -> Self {
        self.0.push(opcode);
        self
    }

    /// Minimal-width push: `PUSH0` for zero, otherwise the smallest
    /// `PUSHn` that fits.
    pub fn push(mut self, value: impl Into<U256>) -> Self {
        let v: U256 = value.into();
        if v.is_zero() {
            self.0.push(op::PUSH0);
            return self;
        }
        let n = v.bits().div_ceil(8);
        self.0.push(op::PUSH1 + (n - 1) as u8);
        let mut buf = [0u8; 32];
        v.to_big_endian(&mut buf);
        self.0.extend_from_slice(&buf[32 - n..]);
        self
    }

    /// Fixed `PUSH1`, for hand-computed jump targets where the encoding
    /// width must not depend on the value.
    pub fn push1(mut self, byte: u8) -> Self {
        self.0.push(op::PUSH1);
        self.0.push(byte);
        self
    }

    pub fn build(self) -> Vec<u8> {
        self.0
    }
}

pub fn caller() -> Address {
    Address::from_low_u64_be(0x00c0_ffee)
}

pub fn contract() -> Address {
    Address::from_low_u64_be(0x0000_cafe)
}

pub fn other() -> Address {
    Address::from_low_u64_be(0x0000_0b0b)
}

pub fn as_word(a: Address) -> U256 {
    address_to_u256(a)
}

pub const GAS_LIMIT: u64 = 1_000_000;

/// EVM with a funded caller and `code` installed at [`contract`], set up
/// for a zero-price call transaction so gas math stays legible.
pub fn evm_with(code: Vec<u8>) -> Evm {
    let mut evm = Evm::new(Env::default());
    evm.env.tx.caller = caller();
    evm.env.tx.to = Some(contract());
    evm.env.tx.gas_limit = GAS_LIMIT;
    evm.journal.seed(
        caller(),
        Account {
            balance: U256::from(u64::MAX),
            ..Default::default()
        },
    );
    evm.journal.seed(
        contract(),
        Account {
            nonce: 1,
            code: code.into(),
            ..Default::default()
        },
    );
    evm
}

pub fn run(code: Vec<u8>) -> ExecutionResult {
    evm_with(code).transact().expect("valid transaction")
}

/// Last 32 bytes of the output as a word; panics if the output is shorter.
pub fn word_at(output: &[u8], index: usize) -> U256 {
    U256::from_big_endian(&output[index * 32..(index + 1) * 32])
}

//! The interpreter's window onto everything that is not the interpreter:
//! block context, transaction context, and account state.
//!
//! Instructions never touch state directly — they go through [`Host`], so
//! the interpreter can be pointed at a journaled in-memory state, a fork of
//! a live chain, or a mock in tests, without knowing the difference.

use crate::bytecode::Bytecode;
use crate::primitives::{Address, B256, U256};
use crate::state::Log;

#[derive(Debug, Clone, Default)]
pub struct BlockEnv {
    pub number: U256,
    pub coinbase: Address,
    pub timestamp: U256,
    pub gas_limit: u64,
    pub basefee: U256,
    /// Post-Merge randomness beacon (EIP-4399); what `PREVRANDAO` returns.
    pub prevrandao: B256,
    pub blob_basefee: U256,
}

#[derive(Debug, Clone)]
pub struct TxEnv {
    pub caller: Address,
    pub gas_limit: u64,
    pub gas_price: U256,
    /// Declared sender nonce. `None` skips the check (useful in tests and
    /// tools that intend "whatever the account says"); `Some` must match
    /// the account state exactly, as on chain.
    pub nonce: Option<u64>,
    /// `None` is a create transaction.
    pub to: Option<Address>,
    pub value: U256,
    pub data: Vec<u8>,
    /// EIP-2930 access list: addresses and their storage keys declared up
    /// front. They are charged in the intrinsic gas and enter the
    /// transaction warm, so their first access inside the EVM is cheap.
    pub access_list: Vec<(Address, Vec<U256>)>,
    /// Versioned hashes of blob commitments (EIP-4844); what `BLOBHASH`
    /// indexes into.
    pub blob_hashes: Vec<B256>,
}

impl Default for TxEnv {
    fn default() -> Self {
        Self {
            caller: Address::zero(),
            gas_limit: 30_000_000,
            gas_price: U256::zero(),
            nonce: None,
            to: None,
            value: U256::zero(),
            data: Vec::new(),
            access_list: Vec::new(),
            blob_hashes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CfgEnv {
    pub chain_id: u64,
}

impl Default for CfgEnv {
    fn default() -> Self {
        Self { chain_id: 1 }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Env {
    pub cfg: CfgEnv,
    pub block: BlockEnv,
    pub tx: TxEnv,
}

/// Result of an account-state read that participates in EIP-2929 warm/cold
/// accounting. `cold` is true exactly once per (transaction, key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessResult<T> {
    pub value: T,
    pub cold: bool,
}

/// Everything `SSTORE` pricing needs to know (see [`crate::gas::sstore`]).
#[derive(Debug, Clone, Copy)]
pub struct SStoreResult {
    /// Slot value at the start of the transaction.
    pub original: U256,
    /// Slot value immediately before this write.
    pub current: U256,
    pub cold: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct SelfDestructResult {
    pub had_value: bool,
    /// Beneficiary existed (in the EIP-161 sense) before the transfer.
    pub target_exists: bool,
    pub cold: bool,
}

pub trait Host {
    fn env(&self) -> &Env;

    fn balance(&mut self, address: Address) -> AccessResult<U256>;
    /// Bytecode of an account; empty for EOAs and non-existent accounts.
    fn code(&mut self, address: Address) -> AccessResult<Bytecode>;
    /// `EXTCODEHASH` semantics (EIP-1052): zero for non-existent accounts,
    /// `KECCAK_EMPTY` for existing accounts without code.
    fn code_hash(&mut self, address: Address) -> AccessResult<B256>;

    fn sload(&mut self, address: Address, key: U256) -> AccessResult<U256>;
    /// Journals the write and reports what pricing needs. Gas is charged by
    /// the caller *after* the write; on out-of-gas the frame halts and the
    /// journal rolls the write back, so ordering is observationally correct.
    fn sstore(&mut self, address: Address, key: U256, value: U256) -> SStoreResult;

    /// Mark an address warm without reading anything (the access charge of
    /// `CALL`-family instructions). Returns whether it was cold.
    fn access_account(&mut self, address: Address) -> bool;
    /// EIP-161 "dead": absent or empty. Decides the `G_newaccount`
    /// surcharge on value-bearing calls.
    fn is_account_dead(&mut self, address: Address) -> bool;

    fn tload(&mut self, address: Address, key: U256) -> U256;
    fn tstore(&mut self, address: Address, key: U256, value: U256);

    fn log(&mut self, log: Log);
    /// Hash of one of the 256 most recent blocks, zero outside that window.
    fn block_hash(&mut self, number: U256) -> B256;

    fn selfdestruct(&mut self, address: Address, beneficiary: Address) -> SelfDestructResult;
}

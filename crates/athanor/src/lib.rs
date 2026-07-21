//! athanor — an Ethereum Virtual Machine, written from first principles.
//!
//! The crate is split along the lines the protocol itself draws:
//!
//! * [`interpreter`] executes one call frame and knows nothing about call
//!   depth or state layout;
//! * [`evm`] owns the frame stack and everything that spans frames — value
//!   transfer, create collisions, code deposit, refund settlement;
//! * [`state`] is a journaled world state with checkpoint/revert;
//! * [`bytecode`] carries contract code behind an `Arc` with memoized
//!   `JUMPDEST` analysis and code hash;
//! * [`gas`], [`memory`], [`stack`], [`i256`], [`opcode`] are the small
//!   sharp pieces the above are assembled from.
//!
//! Target ruleset: Cancun. See the README for the exact EIP coverage and
//! the road to execution-spec-tests.

// The `uint` and `fixed-hash` macros expand to code that trips a couple of
// lints newer toolchains added (a `dev` cfg reference, a manual `div_ceil`);
// these fire on the macro expansion, not on our own code. `unknown_lints`
// comes first so the allows stay harmless on the 1.75 MSRV, where those
// lints do not yet exist.
#![allow(unknown_lints)]
#![allow(unexpected_cfgs)]
#![allow(clippy::manual_div_ceil)]

// Memory offsets ride through usize after the 2^32 hard cap check; that
// arithmetic assumes a 64-bit target. Fail loudly at compile time instead
// of subtly at runtime on anything narrower.
#[cfg(not(target_pointer_width = "64"))]
compile_error!("athanor assumes a 64-bit target");

pub mod bytecode;
pub mod evm;
pub mod gas;
pub mod host;
pub mod i256;
pub mod interpreter;
pub mod memory;
pub mod opcode;
pub mod precompile;
pub mod primitives;
pub mod result;
pub mod stack;
pub mod state;
pub mod trie_root;

pub use bytecode::{Bytecode, JumpTable};
pub use evm::Evm;
pub use host::{BlockEnv, CfgEnv, Env, Host, TxEnv};
pub use interpreter::{Action, CallInputs, CallScheme, CreateInputs, Interpreter};
pub use primitives::{Address, B256, H160, H256, U256};
pub use result::{ExecutionResult, Halt, Outcome, TxError, TxKind};
pub use state::{Account, JournaledState, Log};

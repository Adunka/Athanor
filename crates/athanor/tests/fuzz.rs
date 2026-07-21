//! Property-based robustness fuzzing.
//!
//! These do not check athanor against a reference — that is what the state
//! tests and precompile vectors are for. They check the properties that must
//! hold for *every* input, reference or not: the interpreter must never panic,
//! execution must be deterministic, and a transaction must never charge past
//! its gas limit. Bugs those catch — an unchecked add, an unbounded copy, a
//! slice index off the end — are exactly the ones fixed test vectors miss,
//! because a vector only probes the inputs someone thought to write down.
//!
//! Two generators feed them. One is unstructured random bytes, which mostly
//! probes the decoder and the malformed-input paths. The other primes the
//! stack with `PUSH1`s and then emits stack-consuming opcodes, so arithmetic,
//! memory, and hashing run for real instead of tripping an immediate
//! stack-underflow. Gas is always bounded, so even a tight `JUMP` loop halts.

use athanor::{Account, Address, Bytecode, Env, Evm, B256, U256};
use proptest::prelude::*;

const CALLER: [u8; 20] = [0x11; 20];
const CONTRACT: [u8; 20] = [0xc0; 20];

/// Execute `code` against a funded contract and return `(gas_used, root)`, or
/// `None` if the transaction was rejected. Never panics for any input — that
/// is the property under test.
fn run(code: Vec<u8>, calldata: Vec<u8>, gas: u64) -> Option<(u64, B256)> {
    let limit = gas.max(21_000);
    let mut evm = Evm::new(Env::default());
    evm.env.block.gas_limit = limit;
    evm.journal.seed(
        Address::from_slice(&CALLER),
        Account {
            balance: U256::from(u128::MAX),
            nonce: 0,
            code: Bytecode::new(Vec::new()),
            storage: Default::default(),
        },
    );
    evm.journal.seed(
        Address::from_slice(&CONTRACT),
        Account {
            balance: U256::from(1_000_000u64),
            nonce: 0,
            code: Bytecode::new(code),
            storage: Default::default(),
        },
    );
    evm.env.tx.caller = Address::from_slice(&CALLER);
    evm.env.tx.to = Some(Address::from_slice(&CONTRACT));
    evm.env.tx.gas_limit = limit;
    evm.env.tx.gas_price = U256::from(1u64);
    evm.env.tx.nonce = None;
    evm.env.tx.data = calldata;

    let result = evm.transact().ok()?;
    Some((result.gas_used, evm.journal.state_root()))
}

/// Stack-consuming opcodes worth exercising in depth: arithmetic, comparison
/// and bitwise ops, `KECCAK256`, memory, small `DUP`/`SWAP`, and control flow.
const OPS: &[u8] = &[
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // arithmetic
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, // comparison
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, // bitwise
    0x20, // KECCAK256
    0x50, 0x51, 0x52, 0x53, // POP MLOAD MSTORE MSTORE8
    0x80, 0x81, 0x82, 0x83, // DUP1..DUP4
    0x90, 0x91, 0x92, 0x93, // SWAP1..SWAP4
    0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, // JUMP JUMPI PC MSIZE GAS JUMPDEST
];

/// A stack-primed program: some `PUSH1 <byte>` fills, then random opcodes.
fn deep_program() -> impl Strategy<Value = Vec<u8>> {
    (
        prop::collection::vec(any::<u8>(), 1..40),
        prop::collection::vec(prop::sample::select(OPS), 0..300),
    )
        .prop_map(|(fills, ops)| {
            let mut code = Vec::with_capacity(fills.len() * 2 + ops.len());
            for byte in fills {
                code.push(0x60); // PUSH1
                code.push(byte);
            }
            code.extend(ops);
            code
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Arbitrary bytecode and calldata must never make the interpreter panic.
    #[test]
    fn raw_bytecode_never_panics(
        code in prop::collection::vec(any::<u8>(), 0..300),
        calldata in prop::collection::vec(any::<u8>(), 0..128),
        gas in 0u64..2_000_000,
    ) {
        let _ = run(code, calldata, gas);
    }

    /// Stack-primed programs reach the opcode implementations proper; those
    /// must not panic either.
    #[test]
    fn deep_programs_never_panic(code in deep_program(), gas in 0u64..5_000_000) {
        let _ = run(code, Vec::new(), gas);
    }

    /// Identical input yields an identical gas charge and post-state root.
    #[test]
    fn execution_is_deterministic(code in deep_program(), gas in 0u64..5_000_000) {
        prop_assert_eq!(run(code.clone(), Vec::new(), gas), run(code, Vec::new(), gas));
    }

    /// A transaction never charges more gas than its limit.
    #[test]
    fn never_charges_over_the_limit(code in deep_program(), gas in 21_000u64..5_000_000) {
        if let Some((used, _)) = run(code, Vec::new(), gas) {
            prop_assert!(used <= gas);
        }
    }
}

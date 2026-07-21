//! End-to-end transactions through [`athanor::Evm`].
//!
//! Bytecode is assembled by hand (see `common::Asm`), so each test doubles
//! as a worked example of operand order on the stack. Gas assertions are
//! exact where the arithmetic is small enough to do on paper — those
//! numbers are the test.

mod common;

use common::{as_word, caller, contract, evm_with, other, run, word_at, Asm, GAS_LIMIT};

use athanor::opcode as op;
use athanor::primitives::{create2_address, create_address, keccak256, KECCAK_EMPTY};
use athanor::{Account, Halt, Outcome, TxError, U256};

#[test]
fn add_and_return() {
    // 2 + 3, stored at 0, returned as one word.
    let code = Asm::new()
        .push(3u64)
        .push(2u64)
        .op(op::ADD)
        .push(0u64)
        .op(op::MSTORE)
        .push(32u64)
        .push(0u64)
        .op(op::RETURN)
        .build();
    let result = run(code);
    match &result.outcome {
        Outcome::Return(output) => assert_eq!(word_at(output, 0), U256::from(5u64)),
        other => panic!("expected Return, got {other:?}"),
    }
    assert!(result.gas_used > 21_000);
    assert_eq!(result.gas_refunded, 0);
}

#[test]
fn jump_into_push_data_is_invalid() {
    // Offset 4 is the 0x5b byte *inside* the PUSH1 immediate — the
    // jumpdest analysis must refuse it.
    let code = Asm::new()
        .push1(4)
        .op(op::JUMP)
        .push1(0x5b)
        .op(op::STOP)
        .build();
    let result = run(code);
    assert!(matches!(result.outcome, Outcome::Halt(Halt::InvalidJump)));
    assert_eq!(
        result.gas_used, GAS_LIMIT,
        "exceptional halt consumes everything"
    );
}

#[test]
fn jump_over_invalid_opcode() {
    // PUSH1 4, JUMP, INVALID, JUMPDEST, STOP — the INVALID is dead code.
    let code = Asm::new()
        .push1(4)
        .op(op::JUMP)
        .op(op::INVALID)
        .op(op::JUMPDEST)
        .op(op::STOP)
        .build();
    let result = run(code);
    assert!(matches!(result.outcome, Outcome::Stop));
}

#[test]
fn bare_add_underflows() {
    let result = run(Asm::new().op(op::ADD).build());
    assert!(matches!(
        result.outcome,
        Outcome::Halt(Halt::StackUnderflow)
    ));
    assert_eq!(result.gas_used, GAS_LIMIT);
}

#[test]
fn absurd_mload_offset_halts() {
    let code = Asm::new().push(1u64 << 40).op(op::MLOAD).build();
    let result = run(code);
    assert!(matches!(result.outcome, Outcome::Halt(_)));
    assert_eq!(result.gas_used, GAS_LIMIT);
}

#[test]
fn keccak_of_empty_region() {
    let code = Asm::new()
        .push(0u64) // len
        .push(0u64) // offset
        .op(op::KECCAK256)
        .push(0u64)
        .op(op::MSTORE)
        .push(32u64)
        .push(0u64)
        .op(op::RETURN)
        .build();
    let result = run(code);
    let Outcome::Return(output) = &result.outcome else {
        panic!("expected Return")
    };
    assert_eq!(&output[..], KECCAK_EMPTY.as_bytes());
}

#[test]
fn calldataload_pads_with_zeros() {
    let code = Asm::new()
        .push(0u64)
        .op(op::CALLDATALOAD)
        .push(0u64)
        .op(op::MSTORE)
        .push(32u64)
        .push(0u64)
        .op(op::RETURN)
        .build();
    let mut evm = evm_with(code);
    evm.env.tx.data = vec![0xaa];
    let result = evm.transact().unwrap();
    let Outcome::Return(output) = &result.outcome else {
        panic!("expected Return")
    };
    assert_eq!(word_at(output, 0), U256::from(0xaau64) << 248);
}

#[test]
fn sstore_clear_refunds_exactly() {
    // Slot 1 holds 1 from a previous transaction; this one zeroes it.
    // 21000 intrinsic + 2 (PUSH0) + 3 (PUSH1) + 5000 (cold reset) = 26005
    // spent, minus the 4800 clear refund (EIP-3529) = 21205.
    let code = Asm::new()
        .push(0u64) // value
        .push(1u64) // key
        .op(op::SSTORE)
        .op(op::STOP)
        .build();
    let mut evm = evm_with(code.clone());
    evm.journal.seed(
        contract(),
        Account {
            nonce: 1,
            code: code.into(),
            storage: [(U256::from(1u64), U256::from(1u64))].into_iter().collect(),
            ..Default::default()
        },
    );
    let result = evm.transact().unwrap();
    assert!(matches!(result.outcome, Outcome::Stop));
    assert_eq!(result.gas_refunded, 4_800);
    assert_eq!(result.gas_used, 21_205);
    assert_eq!(
        evm.journal.storage(contract(), U256::from(1u64)),
        U256::zero()
    );
}

#[test]
fn transient_storage_clears_between_transactions() {
    let roundtrip = Asm::new()
        .push(42u64) // value
        .push(0u64) // key
        .op(op::TSTORE)
        .push(0u64)
        .op(op::TLOAD)
        .push(0u64)
        .op(op::MSTORE)
        .push(32u64)
        .push(0u64)
        .op(op::RETURN)
        .build();
    let mut evm = evm_with(roundtrip);
    let first = evm.transact().unwrap();
    let Outcome::Return(output) = &first.outcome else {
        panic!("expected Return")
    };
    assert_eq!(
        word_at(output, 0),
        U256::from(42u64),
        "TSTORE/TLOAD within one tx"
    );

    // Same slot read in a fresh transaction: EIP-1153 wipes it.
    let read_only = Asm::new()
        .push(0u64)
        .op(op::TLOAD)
        .push(0u64)
        .op(op::MSTORE)
        .push(32u64)
        .push(0u64)
        .op(op::RETURN)
        .build();
    evm.journal.seed(
        contract(),
        Account {
            nonce: 1,
            code: read_only.into(),
            ..Default::default()
        },
    );
    let second = evm.transact().unwrap();
    let Outcome::Return(output) = &second.outcome else {
        panic!("expected Return")
    };
    assert_eq!(
        word_at(output, 0),
        U256::zero(),
        "transient state must not survive the tx"
    );
}

#[test]
fn call_writes_return_window_and_buffer() {
    // B returns the word 7; A forwards it plus the status flag.
    let b_code = Asm::new()
        .push(7u64)
        .push(0u64)
        .op(op::MSTORE)
        .push(32u64)
        .push(0u64)
        .op(op::RETURN)
        .build();
    let a_code = Asm::new()
        .push(32u64) // out_len
        .push(0u64) // out_offset
        .push(0u64) // in_len
        .push(0u64) // in_offset
        .push(0u64) // value
        .push(as_word(other()))
        .push(60_000u64) // gas
        .op(op::CALL)
        .push(32u64)
        .op(op::MSTORE) // flag at [32..64)
        .push(64u64)
        .push(0u64)
        .op(op::RETURN)
        .build();
    let mut evm = evm_with(a_code);
    evm.journal.seed(
        other(),
        Account {
            nonce: 1,
            code: b_code.into(),
            ..Default::default()
        },
    );
    let result = evm.transact().unwrap();
    let Outcome::Return(output) = &result.outcome else {
        panic!("expected Return")
    };
    assert_eq!(
        word_at(output, 0),
        U256::from(7u64),
        "callee output in the window"
    );
    assert_eq!(word_at(output, 1), U256::one(), "success flag");
}

#[test]
fn revert_rolls_back_callee_state() {
    // B writes a slot, then reverts with two bytes of data.
    let b_code = Asm::new()
        .push(1u64)
        .push(0u64)
        .op(op::SSTORE)
        .push(0xdeadu64)
        .push(0u64)
        .op(op::MSTORE)
        .push(2u64) // len
        .push(30u64) // offset
        .op(op::REVERT)
        .build();
    let a_code = Asm::new()
        .push(0u64)
        .push(0u64)
        .push(0u64)
        .push(0u64)
        .push(0u64)
        .push(as_word(other()))
        .push(100_000u64)
        .op(op::CALL)
        .op(op::RETURNDATASIZE)
        .push(0u64)
        .op(op::MSTORE) // returndata size at [0..32)
        .push(32u64)
        .op(op::MSTORE) // flag at [32..64)
        .push(64u64)
        .push(0u64)
        .op(op::RETURN)
        .build();
    let mut evm = evm_with(a_code);
    evm.journal.seed(
        other(),
        Account {
            nonce: 1,
            code: b_code.into(),
            ..Default::default()
        },
    );
    let result = evm.transact().unwrap();
    let Outcome::Return(output) = &result.outcome else {
        panic!("expected Return")
    };
    assert_eq!(
        word_at(output, 0),
        U256::from(2u64),
        "revert data is visible"
    );
    assert_eq!(word_at(output, 1), U256::zero(), "status flag is failure");
    assert_eq!(
        evm.journal.storage(other(), U256::zero()),
        U256::zero(),
        "callee write rolled back"
    );
    assert!(result.outcome.is_success(), "caller itself succeeded");
}

#[test]
fn staticcall_forbids_sstore() {
    let b_code = Asm::new()
        .push(1u64)
        .push(0u64)
        .op(op::SSTORE)
        .op(op::STOP)
        .build();
    let a_code = Asm::new()
        .push(0u64) // out_len
        .push(0u64) // out_offset
        .push(0u64) // in_len
        .push(0u64) // in_offset
        .push(as_word(other()))
        .push(100_000u64)
        .op(op::STATICCALL)
        .push(0u64)
        .op(op::MSTORE)
        .push(32u64)
        .push(0u64)
        .op(op::RETURN)
        .build();
    let mut evm = evm_with(a_code);
    evm.journal.seed(
        other(),
        Account {
            nonce: 1,
            code: b_code.into(),
            ..Default::default()
        },
    );
    let result = evm.transact().unwrap();
    let Outcome::Return(output) = &result.outcome else {
        panic!("expected Return")
    };
    assert_eq!(
        word_at(output, 0),
        U256::zero(),
        "static frame must reject the write"
    );
    assert_eq!(evm.journal.storage(other(), U256::zero()), U256::zero());
}

#[test]
fn delegatecall_uses_caller_context() {
    // B writes 0x77 to slot 0 — under DELEGATECALL that is A's slot 0.
    let write_code = Asm::new()
        .push(0x77u64)
        .push(0u64)
        .op(op::SSTORE)
        .op(op::STOP)
        .build();
    let a_code = Asm::new()
        .push(0u64)
        .push(0u64)
        .push(0u64)
        .push(0u64)
        .push(as_word(other()))
        .push(200_000u64)
        .op(op::DELEGATECALL)
        .op(op::POP)
        .op(op::STOP)
        .build();
    let mut evm = evm_with(a_code);
    evm.journal.seed(
        other(),
        Account {
            nonce: 1,
            code: write_code.into(),
            ..Default::default()
        },
    );
    evm.transact().unwrap();
    assert_eq!(
        evm.journal.storage(contract(), U256::zero()),
        U256::from(0x77u64)
    );
    assert_eq!(evm.journal.storage(other(), U256::zero()), U256::zero());

    // And CALLER inside the delegated frame is A's caller, not A.
    let caller_probe = Asm::new()
        .op(op::CALLER)
        .push(0u64)
        .op(op::MSTORE)
        .push(32u64)
        .push(0u64)
        .op(op::RETURN)
        .build();
    let a2_code = Asm::new()
        .push(32u64)
        .push(0u64)
        .push(0u64)
        .push(0u64)
        .push(as_word(other()))
        .push(200_000u64)
        .op(op::DELEGATECALL)
        .push(32u64)
        .push(0u64)
        .op(op::RETURN)
        .build();
    let mut evm = evm_with(a2_code);
    evm.journal.seed(
        other(),
        Account {
            nonce: 1,
            code: caller_probe.into(),
            ..Default::default()
        },
    );
    let result = evm.transact().unwrap();
    let Outcome::Return(output) = &result.outcome else {
        panic!("expected Return")
    };
    assert_eq!(word_at(output, 0), as_word(caller()));
}

#[test]
fn create_deploys_at_derived_address() {
    // Init code `PUSH1 1, PUSH1 0, RETURN` (60 01 60 00 f3) returns one
    // zero byte — a contract whose runtime is a single STOP.
    let init = Asm::new().push1(1).push1(0).op(op::RETURN).build();
    assert_eq!(init, vec![0x60, 0x01, 0x60, 0x00, 0xf3]);

    let factory = Asm::new()
        .push(0x60016000f3u64) // init code, right-aligned in a word
        .push(0u64)
        .op(op::MSTORE) // bytes [27..32)
        .push(5u64) // len
        .push(27u64) // offset
        .push(0u64) // value
        .op(op::CREATE)
        .push(0u64)
        .op(op::MSTORE)
        .push(32u64)
        .push(0u64)
        .op(op::RETURN)
        .build();
    let mut evm = evm_with(factory);
    let result = evm.transact().unwrap();

    let expected = create_address(contract(), 1);
    let Outcome::Return(output) = &result.outcome else {
        panic!("expected Return")
    };
    assert_eq!(word_at(output, 0), as_word(expected));
    assert_eq!(
        evm.journal.code(expected).bytes(),
        &[0x00],
        "runtime code deposited"
    );
    assert_eq!(evm.journal.nonce(expected), 1, "EIP-161 starting nonce");
}

#[test]
fn create2_address_is_salt_derived() {
    let init = Asm::new().push1(1).push1(0).op(op::RETURN).build();
    let salt = 0x5a17u64;
    let factory = Asm::new()
        .push(0x60016000f3u64)
        .push(0u64)
        .op(op::MSTORE)
        .push(salt) // salt, deepest of the four operands
        .push(5u64) // len
        .push(27u64) // offset
        .push(0u64) // value
        .op(op::CREATE2)
        .push(0u64)
        .op(op::MSTORE)
        .push(32u64)
        .push(0u64)
        .op(op::RETURN)
        .build();
    let mut evm = evm_with(factory);
    let result = evm.transact().unwrap();

    let expected = create2_address(
        contract(),
        athanor::H256::from_low_u64_be(salt),
        keccak256(&init),
    );
    let Outcome::Return(output) = &result.outcome else {
        panic!("expected Return")
    };
    assert_eq!(word_at(output, 0), as_word(expected));
    assert_eq!(evm.journal.code(expected).bytes(), &[0x00]);
}

#[test]
fn create_rejects_ef_prefixed_code() {
    // Init returns a single 0xEF byte; EIP-3541 forbids depositing it.
    // 60 ef 60 00 53 60 01 60 00 f3 — ten bytes, right-aligned at 22.
    let factory = Asm::new()
        .push(0x60ef60005360016000f3u128)
        .push(0u64)
        .op(op::MSTORE)
        .push(10u64) // len
        .push(22u64) // offset
        .push(0u64) // value
        .op(op::CREATE)
        .push(0u64)
        .op(op::MSTORE)
        .push(32u64)
        .push(0u64)
        .op(op::RETURN)
        .build();
    let result = run(factory);
    let Outcome::Return(output) = &result.outcome else {
        panic!("expected Return")
    };
    assert_eq!(
        word_at(output, 0),
        U256::zero(),
        "failed create pushes zero"
    );
    assert!(
        result.outcome.is_success(),
        "the factory itself is unaffected"
    );
}

#[test]
fn call_forwards_exactly_the_requested_gas() {
    // B's first instruction is GAS, so it observes its limit minus the 2
    // gas that GAS itself costs. A requests 50 000 — under the 63/64 cap,
    // so the child limit is exactly that.
    let b_code = Asm::new()
        .op(op::GAS)
        .push(0u64)
        .op(op::MSTORE)
        .push(32u64)
        .push(0u64)
        .op(op::RETURN)
        .build();
    let a_code = Asm::new()
        .push(32u64)
        .push(0u64)
        .push(0u64)
        .push(0u64)
        .push(0u64)
        .push(as_word(other()))
        .push(50_000u64)
        .op(op::CALL)
        .push(32u64)
        .push(0u64)
        .op(op::RETURN)
        .build();
    let mut evm = evm_with(a_code);
    evm.journal.seed(
        other(),
        Account {
            nonce: 1,
            code: b_code.into(),
            ..Default::default()
        },
    );
    let result = evm.transact().unwrap();
    let Outcome::Return(output) = &result.outcome else {
        panic!("expected Return")
    };
    assert_eq!(word_at(output, 0), U256::from(49_998u64));
}

#[test]
fn log1_records_topic_and_data() {
    let code = Asm::new()
        .push(0xabcdu64)
        .push(0u64)
        .op(op::MSTORE) // data bytes at [30..32)
        .push(0x11u64) // topic
        .push(2u64) // len
        .push(30u64) // offset
        .op(op::LOG1)
        .op(op::STOP)
        .build();
    let result = run(code);
    assert!(result.outcome.is_success());
    assert_eq!(result.logs.len(), 1);
    let log = &result.logs[0];
    assert_eq!(log.address, contract());
    assert_eq!(log.topics, vec![athanor::H256::from_low_u64_be(0x11)]);
    assert_eq!(log.data, vec![0xab, 0xcd]);
}

#[test]
fn selfdestruct_moves_balance_but_keeps_code() {
    // EIP-6780: a pre-existing contract that self-destructs sends its
    // balance away but is *not* deleted.
    let code = Asm::new().push(0xbeefu64).op(op::SELFDESTRUCT).build();
    let mut evm = evm_with(code.clone());
    evm.journal.seed(
        contract(),
        Account {
            nonce: 1,
            balance: U256::from(500u64),
            code: code.into(),
            ..Default::default()
        },
    );
    let result = evm.transact().unwrap();
    assert!(matches!(result.outcome, Outcome::SelfDestruct));

    let beneficiary = athanor::Address::from_low_u64_be(0xbeef);
    assert_eq!(evm.journal.balance(beneficiary), U256::from(500u64));
    assert_eq!(evm.journal.balance(contract()), U256::zero());
    assert!(
        !evm.journal.code(contract()).is_empty(),
        "EIP-6780 keeps the account"
    );
}

#[test]
fn intrinsic_gas_prices_calldata() {
    // 21000 + 4 + 4 + 16 for [0, 0, 1].
    let mut evm = evm_with(Asm::new().op(op::STOP).build());
    evm.env.tx.data = vec![0, 0, 1];
    let result = evm.transact().unwrap();
    assert_eq!(result.gas_used, 21_024);
    assert_eq!(result.gas_refunded, 0);
}

#[test]
fn underfunded_sender_is_rejected() {
    let mut evm = evm_with(Asm::new().op(op::STOP).build());
    evm.journal.seed(
        caller(),
        Account {
            balance: U256::from(1_000u64),
            ..Default::default()
        },
    );
    evm.env.tx.gas_price = U256::one();
    let err = evm.transact().unwrap_err();
    assert!(matches!(err, TxError::InsufficientFunds { .. }));
}

#[test]
fn self_recursion_burns_down_and_unwinds() {
    // A contract that calls itself with everything it has. The 63/64 rule
    // shrinks each frame's budget until a child can no longer execute;
    // the whole tower then unwinds successfully — and because the
    // executor is a loop over a frame stack, native stack depth is O(1).
    let code = Asm::new()
        .push(0u64) // out_len
        .push(0u64) // out_offset
        .push(0u64) // in_len
        .push(0u64) // in_offset
        .push(0u64) // value
        .op(op::ADDRESS)
        .push(GAS_LIMIT) // gas request: whatever the cap allows
        .op(op::CALL)
        .op(op::POP)
        .op(op::STOP)
        .build();
    let result = run(code);
    assert!(result.outcome.is_success());
    assert!(result.gas_used <= GAS_LIMIT);
}

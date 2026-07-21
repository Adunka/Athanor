//! Transaction-validity rules: the checks that reject a transaction before
//! any bytecode runs, plus the in-VM edge of the nonce cap.

mod common;

use common::{caller, contract, evm_with, run, word_at, Asm};

use athanor::opcode as op;
use athanor::{Account, Outcome, TxError, U256};

#[test]
fn sender_with_code_is_rejected() {
    // EIP-3607: contracts do not originate transactions.
    let mut evm = evm_with(Asm::new().op(op::STOP).build());
    evm.journal.seed(
        caller(),
        Account {
            balance: U256::from(u64::MAX),
            code: vec![op::STOP].into(),
            ..Default::default()
        },
    );
    assert!(matches!(evm.transact().unwrap_err(), TxError::SenderNotEoa));
}

#[test]
fn declared_nonce_must_match_state() {
    let mut evm = evm_with(Asm::new().op(op::STOP).build());
    evm.env.tx.nonce = Some(5);
    match evm.transact().unwrap_err() {
        TxError::NonceMismatch { state, tx } => {
            assert_eq!((state, tx), (0, 5));
        }
        other => panic!("expected NonceMismatch, got {other:?}"),
    }

    // The matching declaration goes through, and the account advances.
    evm.env.tx.nonce = Some(0);
    assert!(evm.transact().is_ok());
    assert_eq!(evm.journal.nonce(caller()), 1);
}

#[test]
fn sender_nonce_at_cap_is_rejected() {
    // EIP-2681: the increment must not wrap.
    let mut evm = evm_with(Asm::new().op(op::STOP).build());
    evm.journal.seed(
        caller(),
        Account {
            balance: U256::from(u64::MAX),
            nonce: u64::MAX,
            ..Default::default()
        },
    );
    assert!(matches!(
        evm.transact().unwrap_err(),
        TxError::NonceOverflow
    ));
}

#[test]
fn create_from_capped_factory_pushes_zero() {
    // EIP-2681 at the opcode level: a factory whose nonce is 2^64 - 1
    // fails the CREATE like an underfunded one — status zero on the
    // stack, the factory itself unaffected.
    let factory = Asm::new()
        .push(0x60016000f3u64)
        .push(0u64)
        .op(op::MSTORE)
        .push(5u64)
        .push(27u64)
        .push(0u64)
        .op(op::CREATE)
        .push(0u64)
        .op(op::MSTORE)
        .push(32u64)
        .push(0u64)
        .op(op::RETURN)
        .build();
    let mut evm = evm_with(factory.clone());
    evm.journal.seed(
        contract(),
        Account {
            nonce: u64::MAX,
            code: factory.into(),
            ..Default::default()
        },
    );
    let result = evm.transact().unwrap();
    let Outcome::Return(output) = &result.outcome else {
        panic!("expected Return")
    };
    assert_eq!(word_at(output, 0), U256::zero());
    assert_eq!(evm.journal.nonce(contract()), u64::MAX, "nonce untouched");
}

#[test]
fn valid_transaction_still_goes_through() {
    // Guard against the guards: the happy path is unaffected.
    let result = run(Asm::new().op(op::STOP).build());
    assert!(result.outcome.is_success());
}

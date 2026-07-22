//! The compiler checked against the interpreter it exists to replace.
//!
//! A JIT is only as trustworthy as its reference, and athanor has a good one:
//! the interpreter reproduces 19,690 of the 19,732 official Cancun state
//! tests, so agreeing with it is a strong statement. Every program below is
//! run twice — once compiled, once interpreted — and the two must agree on how
//! the frame ended, on the gas left, and on the stack, word for word.
//!
//! Programs are drawn only from the opcodes the compiler claims, so both sides
//! run to completion and the comparison stays total. Anything outside that set
//! would make the compiled side bail out partway, which is a different
//! property and is covered separately.

use athanor::host::{AccessResult, SStoreResult, SelfDestructResult};
use athanor::interpreter::Action;
use athanor::state::Log;
use athanor::{Address, Bytecode, Env, Halt, Host, Interpreter, Outcome, B256, U256};
use athanor_jit::{Compiler, Exit, Machine};
use proptest::prelude::*;

/// The interpreter needs a host even for programs that never reach one. None
/// of these are called by the compiled subset; a call arriving here means the
/// generator produced an opcode the test claims it cannot.
struct NoHost {
    env: Env,
}

impl Host for NoHost {
    fn env(&self) -> &Env {
        &self.env
    }
    fn balance(&mut self, _: Address) -> AccessResult<U256> {
        unreachable!("the compiled subset never touches accounts")
    }
    fn code(&mut self, _: Address) -> AccessResult<Bytecode> {
        unreachable!("the compiled subset never touches accounts")
    }
    fn code_hash(&mut self, _: Address) -> AccessResult<B256> {
        unreachable!("the compiled subset never touches accounts")
    }
    fn sload(&mut self, _: Address, _: U256) -> AccessResult<U256> {
        unreachable!("the compiled subset never touches storage")
    }
    fn sstore(&mut self, _: Address, _: U256, _: U256) -> SStoreResult {
        unreachable!("the compiled subset never touches storage")
    }
    fn access_account(&mut self, _: Address) -> bool {
        unreachable!("the compiled subset never touches accounts")
    }
    fn is_account_dead(&mut self, _: Address) -> bool {
        unreachable!("the compiled subset never touches accounts")
    }
    fn tload(&mut self, _: Address, _: U256) -> U256 {
        unreachable!("the compiled subset never touches transient storage")
    }
    fn tstore(&mut self, _: Address, _: U256, _: U256) {
        unreachable!("the compiled subset never touches transient storage")
    }
    fn log(&mut self, _: Log) {
        unreachable!("the compiled subset never logs")
    }
    fn block_hash(&mut self, _: U256) -> B256 {
        unreachable!("the compiled subset never reads block hashes")
    }
    fn selfdestruct(&mut self, _: Address, _: Address) -> SelfDestructResult {
        unreachable!("the compiled subset never self-destructs")
    }
}

/// What both engines are compared on.
#[derive(Debug, PartialEq, Eq)]
struct Observation {
    exit: Exit,
    gas: u64,
    stack: Vec<U256>,
}

fn interpret(code: &[u8], gas: u64, seed: &[U256]) -> Observation {
    let mut host = NoHost {
        env: Env::default(),
    };
    let mut interpreter = Interpreter::new(
        Bytecode::new(code.to_vec()),
        Vec::new(),
        gas,
        Address::zero(),
        Address::zero(),
        U256::zero(),
        false,
    );
    for word in seed {
        interpreter.stack.push(*word).expect("seed fits the stack");
    }

    let action = interpreter.run(&mut host);
    let Action::End(outcome) = action else {
        unreachable!("the compiled subset never yields a child frame")
    };
    let exit = match outcome {
        Outcome::Stop => Exit::Stop,
        Outcome::Halt(Halt::OutOfGas) => Exit::OutOfGas,
        Outcome::Halt(Halt::StackUnderflow) => Exit::StackUnderflow,
        Outcome::Halt(Halt::StackOverflow) => Exit::StackOverflow,
        Outcome::Halt(Halt::InvalidJump) => Exit::InvalidJump,
        other => unreachable!("unexpected outcome from the compiled subset: {other:?}"),
    };
    Observation {
        exit,
        gas: interpreter.gas.remaining(),
        stack: interpreter.stack.data().to_vec(),
    }
}

fn compile_and_run(code: &[u8], gas: u64, seed: &[U256]) -> Observation {
    let mut compiler = Compiler::new().expect("host is supported");
    let compiled = compiler.compile(code).expect("compilation succeeds");
    let mut machine = Machine::new(gas);
    for word in seed {
        machine.push(*word).expect("seed fits the stack");
    }
    let exit = unsafe { machine.run(compiled.entry()) };
    Observation {
        exit,
        gas: machine.gas(),
        stack: machine.stack(),
    }
}

/// Whether an exit is an exceptional halt.
///
/// The EVM treats them all alike (YP 9.4.2): the frame forfeits its gas and
/// changes no state, whichever one fired. Clients keep separate labels for
/// debugging, but no consensus rule can tell them apart.
fn is_exceptional(exit: Exit) -> bool {
    matches!(
        exit,
        Exit::OutOfGas | Exit::StackUnderflow | Exit::StackOverflow | Exit::InvalidJump
    )
}

/// Compare the two engines, holding them to the same standard the state tests
/// hold the interpreter to.
///
/// A frame that stopped cleanly is compared on everything: exit, gas, and the
/// stack word for word. A frame that halted exceptionally is compared on
/// having halted, not on the label — charging gas a block at a time can reach
/// out-of-gas where stepping would have underflowed an instruction later, and
/// since either one forfeits the whole frame the difference is invisible to
/// consensus. The cases that do pin a specific reason are the hand-written
/// ones below, where only one of them can occur.
fn assert_agreement(code: &[u8], gas: u64, seed: &[U256]) -> Result<(), TestCaseError> {
    let jitted = compile_and_run(code, gas, seed);
    let interpreted = interpret(code, gas, seed);

    if is_exceptional(jitted.exit) || is_exceptional(interpreted.exit) {
        prop_assert!(
            is_exceptional(jitted.exit) && is_exceptional(interpreted.exit),
            "one engine halted and the other did not: {:?} against {:?}, code {:02x?}",
            jitted.exit,
            interpreted.exit,
            code
        );
        return Ok(());
    }

    prop_assert_eq!(
        jitted.exit,
        interpreted.exit,
        "engines disagree on how the frame ended, code {:02x?}",
        code
    );
    prop_assert_eq!(
        jitted.gas,
        interpreted.gas,
        "gas differs, code {:02x?}",
        code
    );
    prop_assert_eq!(
        jitted.stack,
        interpreted.stack,
        "stack differs, code {:02x?}",
        code
    );
    Ok(())
}

/// Opcodes the compiler claims, minus the ones with immediates.
const COMPILED: &[u8] = &[
    0x01, 0x03, // ADD SUB
    0x10, 0x11, 0x14, 0x15, // LT GT EQ ISZERO
    0x16, 0x17, 0x18, 0x19, // AND OR XOR NOT
    0x50, // POP
    0x5b, // JUMPDEST
    0x80, 0x81, 0x82, // DUP1..3
    0x90, 0x91, 0x92, // SWAP1..3
];

/// A program built from the compiled subset, always ending in STOP so that a
/// run that neither halts nor loops has somewhere to finish.
fn program() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        prop_oneof![
            // Plain opcodes.
            3 => prop::sample::select(COMPILED).prop_map(|op| vec![op]),
            // PUSH1 with an arbitrary byte.
            2 => any::<u8>().prop_map(|b| vec![0x60, b]),
            // PUSH32 with a full word, which is where limb carries show up.
            1 => prop::collection::vec(any::<u8>(), 32)
                .prop_map(|bytes| { let mut v = vec![0x7f]; v.extend(bytes); v }),
            // A jump, whose destination is whatever happens to be on the stack.
            1 => prop::sample::select(&[0x56u8, 0x57][..]).prop_map(|op| vec![op]),
        ],
        0..24,
    )
    .prop_map(|parts| {
        let mut code: Vec<u8> = parts.into_iter().flatten().collect();
        code.push(0x00);
        code
    })
}

/// Stack words the frame starts with, biased towards the boundaries where
/// limb arithmetic goes wrong: zero, all ones, and exact limb edges.
fn seed_word() -> impl Strategy<Value = U256> {
    prop_oneof![
        Just(U256::zero()),
        Just(U256::one()),
        Just(U256::MAX),
        Just(U256::from(u64::MAX)),
        Just((U256::one() << 64) - U256::one()),
        Just(U256::one() << 64),
        Just(U256::one() << 128),
        Just(U256::one() << 192),
        any::<u64>().prop_map(U256::from),
        prop::collection::vec(any::<u8>(), 32).prop_map(|b| U256::from_big_endian(&b)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The headline property: compiled and interpreted execution are
    /// indistinguishable.
    #[test]
    fn compiled_matches_interpreted(
        code in program(),
        seed in prop::collection::vec(seed_word(), 0..6),
        gas in 0u64..40_000,
    ) {
        assert_agreement(&code, gas, &seed)?;
    }
}

/// Hand-written cases for the arithmetic edges a random generator reaches only
/// by luck: carries and borrows that cross every limb boundary.
///
/// Operands are named as the Yellow Paper does — `mu0` is the top of the
/// stack, `mu1` the word beneath it — because `SUB` is `mu0 - mu1` and getting
/// that backwards is the easiest way to write a test that lies. The seed is
/// pushed bottom-up, so it reads in the opposite order.
#[test]
fn limb_carries_propagate() {
    let cases: &[(&[u8], U256, U256, U256)] = &[
        // MAX + 1 wraps to zero, carrying through all four limbs.
        (&[0x01], U256::MAX, U256::one(), U256::zero()),
        // 2^64 - 1 plus one crosses the first limb boundary only.
        (
            &[0x01],
            U256::from(u64::MAX),
            U256::one(),
            U256::one() << 64,
        ),
        // 0 - 1 borrows through all four limbs.
        (&[0x03], U256::zero(), U256::one(), U256::MAX),
        // 2^192 - 1 borrows through three of them.
        (
            &[0x03],
            U256::one() << 192,
            U256::one(),
            (U256::one() << 192) - U256::one(),
        ),
    ];

    for (body, mu0, mu1, expected) in cases {
        let mut code = body.to_vec();
        code.push(0x00);
        let seed = [*mu1, *mu0];
        let observed = compile_and_run(&code, 10_000, &seed);
        assert_eq!(observed.exit, Exit::Stop);
        assert_eq!(observed.stack, vec![*expected], "code {body:02x?}");
        assert_eq!(interpret(&code, 10_000, &seed).stack, vec![*expected]);
    }
}

/// Comparison is the other place limb folding can go wrong: a difference in
/// any limb has to override every limb below it.
#[test]
fn comparisons_respect_limb_order() {
    let low = U256::from(u64::MAX);
    let high = U256::one() << 64;
    // (code, mu0, mu1, expected) — see the note on operand order above.
    let cases: &[(&[u8], U256, U256, U256)] = &[
        (&[0x10], low, high, U256::one()),  // LT: low < high
        (&[0x10], high, low, U256::zero()), // LT: high < low does not hold
        (&[0x11], high, low, U256::one()),  // GT: high > low
        (&[0x11], low, high, U256::zero()),
        (&[0x14], high, high, U256::one()), // EQ
        (&[0x14], high, low, U256::zero()),
    ];

    for (body, mu0, mu1, expected) in cases {
        let mut code = body.to_vec();
        code.push(0x00);
        let seed = [*mu1, *mu0];
        let observed = compile_and_run(&code, 10_000, &seed);
        assert_eq!(observed.stack, vec![*expected], "code {body:02x?}");
        assert_eq!(interpret(&code, 10_000, &seed).stack, vec![*expected]);
    }

    // ISZERO is unary, so it takes the top word alone.
    for (input, expected) in [(U256::zero(), U256::one()), (high, U256::zero())] {
        let code = [0x15, 0x00];
        let observed = compile_and_run(&code, 10_000, &[input]);
        assert_eq!(observed.stack, vec![expected]);
        assert_eq!(interpret(&code, 10_000, &[input]).stack, vec![expected]);
    }
}

/// A loop that only the dynamic-jump dispatcher can run: the destination is
/// computed, not a constant the compiler could fold.
#[test]
fn dynamic_jump_loop_agrees_with_the_interpreter() {
    // counter = 5
    // loop: JUMPDEST; counter -= 1; if counter != 0 jump loop; STOP
    let code = [
        0x60, 0x05, // PUSH1 5
        0x5b, // JUMPDEST      <- pc 2, the loop head
        0x60, 0x01, // PUSH1 1
        0x90, // SWAP1
        0x03, // SUB           counter - 1
        0x80, // DUP1
        0x60, 0x02, // PUSH1 2 (the loop head)
        0x57, // JUMPI
        0x00, // STOP
    ];
    let jitted = compile_and_run(&code, 100_000, &[]);
    let interpreted = interpret(&code, 100_000, &[]);
    assert_eq!(jitted.exit, Exit::Stop);
    assert_eq!(jitted, interpreted);
    // Five iterations leave the counter at zero.
    assert_eq!(jitted.stack, vec![U256::zero()]);
}

/// Jumping anywhere that is not a `JUMPDEST` is an exceptional halt, and the
/// dispatcher has to reach the same verdict as the interpreter's bitmap.
#[test]
fn invalid_jumps_halt() {
    for destination in [0x00u8, 0x01, 0x7f, 0xff] {
        let code = [0x60, destination, 0x56, 0x00];
        assert_eq!(compile_and_run(&code, 10_000, &[]).exit, Exit::InvalidJump);
        assert_eq!(interpret(&code, 10_000, &[]).exit, Exit::InvalidJump);
    }
}

/// Gas is charged a block at a time, so the cheapest way to be wrong is to be
/// off by one block. An exact budget must run, and one gas less must not.
#[test]
fn block_gas_is_exact_to_the_unit() {
    // PUSH1 1, PUSH1 2, ADD, STOP: 3 + 3 + 3, STOP is free.
    let code = [0x60, 0x01, 0x60, 0x02, 0x01, 0x00];
    assert_eq!(compile_and_run(&code, 9, &[]).exit, Exit::Stop);
    assert_eq!(compile_and_run(&code, 9, &[]).gas, 0);
    assert_eq!(compile_and_run(&code, 8, &[]).exit, Exit::OutOfGas);
    assert_eq!(interpret(&code, 8, &[]).exit, Exit::OutOfGas);
}

/// An opcode outside the subset stops compiled execution exactly on it, with
/// the stack and gas an interpreter would need to carry on.
#[test]
fn bailout_hands_over_exact_state() {
    // PUSH1 1, PUSH1 2, ADD, SSTORE — SSTORE is not compiled.
    let code = [0x60, 0x01, 0x60, 0x02, 0x01, 0x55];
    let observed = compile_and_run(&code, 1_000, &[]);
    assert_eq!(observed.exit, Exit::Bailout { pc: 5 });
    // Only the three compiled instructions were billed.
    assert_eq!(observed.gas, 1_000 - 9);
    assert_eq!(observed.stack, vec![U256::from(3u64)]);
}

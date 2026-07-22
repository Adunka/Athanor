//! Compiled against interpreted throughput, on identical bytecode.
//!
//! The workload is the same tight arithmetic loop athanor's own benchmark
//! uses, so the two numbers are directly comparable and the ratio means
//! something. Criterion is not used here for the same reason it is not used
//! there — it does not build on the 1.75 MSRV — so this is a plain
//! warmup-then-best-of-N wall clock, which is enough to separate a
//! two-times change from a ten-times one.
//!
//! Compilation is timed separately and reported as such. A JIT that pays for
//! itself only after a million iterations is a different tool from one that
//! pays for itself after a hundred, and averaging the two together would hide
//! exactly the fact worth knowing.

use std::time::Instant;

use athanor::host::{AccessResult, SStoreResult, SelfDestructResult};
use athanor::interpreter::Action;
use athanor::state::Log;
use athanor::{Address, Bytecode, Env, Host, Interpreter, B256, U256};
use athanor_jit::{Compiler, Exit, Machine};

struct NoHost {
    env: Env,
}

macro_rules! unreachable_host {
    ($($name:ident($($arg:ty),*) -> $ret:ty;)*) => {
        $(fn $name(&mut self, $(_: $arg),*) -> $ret {
            unreachable!("the benchmark workload never leaves the frame")
        })*
    };
}

impl Host for NoHost {
    fn env(&self) -> &Env {
        &self.env
    }
    unreachable_host! {
        balance(Address) -> AccessResult<U256>;
        code(Address) -> AccessResult<Bytecode>;
        code_hash(Address) -> AccessResult<B256>;
        sload(Address, U256) -> AccessResult<U256>;
        sstore(Address, U256, U256) -> SStoreResult;
        access_account(Address) -> bool;
        is_account_dead(Address) -> bool;
        tload(Address, U256) -> U256;
        tstore(Address, U256, U256) -> ();
        log(Log) -> ();
        block_hash(U256) -> B256;
        selfdestruct(Address, Address) -> SelfDestructResult;
    }
}

/// A countdown loop: `while (n -= 1) != 0 {}`.
///
/// Every iteration costs 26 gas and touches the paths a JIT is supposed to
/// win on — stack shuffling, one arithmetic op, a conditional jump — with no
/// host traffic to dilute the measurement.
fn countdown(iterations: u32) -> Vec<u8> {
    let n = iterations.to_be_bytes();
    vec![
        0x63, n[0], n[1], n[2], n[3], // PUSH4 iterations
        0x5b, // JUMPDEST        <- pc 5, loop head
        0x60, 0x01, // PUSH1 1
        0x90, // SWAP1
        0x03, // SUB             n - 1
        0x80, // DUP1
        0x60, 0x05, // PUSH1 5   loop head
        0x57, // JUMPI
        0x00, // STOP
    ]
}

const GAS_LIMIT: u64 = 1_000_000_000;

fn best_of<T>(rounds: usize, mut run: impl FnMut() -> T) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..rounds {
        let start = Instant::now();
        let result = run();
        let elapsed = start.elapsed().as_secs_f64();
        // Keep the result observable so the optimiser cannot discard the work.
        std::hint::black_box(result);
        best = best.min(elapsed);
    }
    best
}

fn main() {
    let iterations = 400_000u32;
    let code = countdown(iterations);

    // Warm the caches and confirm both engines agree before timing anything.
    let mut compiler = Compiler::new().expect("host is supported");
    let compile_start = Instant::now();
    let compiled = compiler.compile(&code).expect("compilation succeeds");
    let compile_time = compile_start.elapsed();

    let mut machine = Machine::new(GAS_LIMIT);
    let exit = unsafe { machine.run(compiled.entry()) };
    assert_eq!(exit, Exit::Stop, "compiled run did not finish cleanly");
    let jit_gas = GAS_LIMIT - machine.gas();

    let mut host = NoHost {
        env: Env::default(),
    };
    let mut interpreter = Interpreter::new(
        Bytecode::new(code.clone()),
        Vec::new(),
        GAS_LIMIT,
        Address::zero(),
        Address::zero(),
        U256::zero(),
        false,
    );
    let action = interpreter.run(&mut host);
    assert!(matches!(action, Action::End(_)));
    let interpreted_gas = GAS_LIMIT - interpreter.gas.remaining();

    // The two engines must charge identically, or the throughput figures
    // below would be measuring different amounts of work. The cost is then
    // taken from the run rather than assumed, so the harness cannot quietly
    // disagree with the fee schedule.
    assert_eq!(
        jit_gas, interpreted_gas,
        "engines disagree on gas; the comparison below would be meaningless"
    );
    let gas_used = jit_gas;

    let rounds = 5;
    let jit_seconds = best_of(rounds, || {
        let mut machine = Machine::new(GAS_LIMIT);
        unsafe { machine.run(compiled.entry()) }
    });
    let interpreter_seconds = best_of(rounds, || {
        let mut host = NoHost {
            env: Env::default(),
        };
        let mut interpreter = Interpreter::new(
            Bytecode::new(code.clone()),
            Vec::new(),
            GAS_LIMIT,
            Address::zero(),
            Address::zero(),
            U256::zero(),
            false,
        );
        interpreter.run(&mut host)
    });

    let mgas = |seconds: f64| gas_used as f64 / seconds / 1e6;
    println!("workload: {iterations} iterations, {gas_used} gas");
    println!(
        "compile:     {:>8.2} ms (once)",
        compile_time.as_secs_f64() * 1e3
    );
    println!(
        "interpreter: {:>8.1} Mgas/s  ({:.1} ms)",
        mgas(interpreter_seconds),
        interpreter_seconds * 1e3
    );
    println!(
        "jit:         {:>8.1} Mgas/s  ({:.1} ms)",
        mgas(jit_seconds),
        jit_seconds * 1e3
    );
    println!("speedup:     {:>8.2}x", interpreter_seconds / jit_seconds);

    // How much work it takes for compilation to pay for itself.
    let saved_per_gas = interpreter_seconds / gas_used as f64 - jit_seconds / gas_used as f64;
    if saved_per_gas > 0.0 {
        let breakeven = compile_time.as_secs_f64() / saved_per_gas;
        println!("break-even:  {:>8.0} gas of execution", breakeven);
    }
}

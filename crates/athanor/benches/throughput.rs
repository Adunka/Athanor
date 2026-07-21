//! A dependency-free throughput harness.
//!
//! `criterion` would be the usual choice, but its dependency tree does not
//! build on this crate's 1.75 MSRV, and pulling a statistics framework in to
//! print one number is a poor trade against the otherwise flat tree. So this
//! measures directly: warm up, then run each workload a handful of times and
//! keep the best wall-clock, which is the sample least polluted by scheduler
//! noise. Gas divided by that time is the interpreter's throughput.
//!
//! Numbers are only meaningful relative to each other and to the machine they
//! were taken on — run `cargo bench -p athanor` on your own hardware. What the
//! harness is really for is catching regressions and guiding optimisation:
//! a dispatch-table or allocation change should move these, and by how much
//! is the question worth having a number for.
//!
//! The workloads are tight bytecode loops, each burning tens of millions of
//! gas so fixed per-transaction overhead (intrinsic cost, account setup) is
//! lost in the noise:
//!   * `arithmetic` — PUSH/SWAP/SUB/DUP/JUMPI, the raw opcode-dispatch path.
//!   * `keccak256`  — hashing a memory word each iteration, a common hot path.

use std::hint::black_box;
use std::time::Instant;

use athanor::{Account, Address, Bytecode, Env, Evm, U256};

const CALLER: [u8; 20] = [0x11; 20];
const CONTRACT: [u8; 20] = [0xc0; 20];
const GAS_LIMIT: u64 = 2_000_000_000;

/// Seed a fresh machine whose transaction calls `code` on the contract.
fn machine(code: &[u8]) -> Evm {
    let mut evm = Evm::new(Env::default());
    evm.env.block.gas_limit = GAS_LIMIT;
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
            balance: U256::zero(),
            nonce: 0,
            code: Bytecode::new(code.to_vec()),
            storage: Default::default(),
        },
    );
    evm.env.tx.caller = Address::from_slice(&CALLER);
    evm.env.tx.to = Some(Address::from_slice(&CONTRACT));
    evm.env.tx.gas_limit = GAS_LIMIT;
    evm.env.tx.gas_price = U256::from(1u64);
    evm.env.tx.nonce = None;
    evm
}

fn measure(name: &str, code: Vec<u8>, samples: usize) {
    for _ in 0..3 {
        black_box(machine(&code).transact().unwrap());
    }
    let mut best = f64::INFINITY;
    let mut gas = 0;
    for _ in 0..samples {
        // A fresh machine each run — `transact` mutates state — but the clock
        // covers only execution, not the setup.
        let mut evm = machine(&code);
        let start = Instant::now();
        let result = evm.transact().unwrap();
        best = best.min(start.elapsed().as_secs_f64());
        gas = black_box(result).gas_used;
    }
    println!(
        "  {name:12} {:>7.1} Mgas/s   ({gas} gas, best {:.2} ms of {samples})",
        gas as f64 / best / 1e6,
        best * 1e3,
    );
}

/// `PUSH4 n; loop: PUSH1 1; SWAP1; SUB; DUP1; PUSH1 5; JUMPI; POP; STOP`.
fn arithmetic_loop(n: u32) -> Vec<u8> {
    let n = n.to_be_bytes();
    vec![
        0x63, n[0], n[1], n[2], n[3], // PUSH4 n
        0x5b, // JUMPDEST  (pc 5)
        0x60, 0x01, // PUSH1 1
        0x90, // SWAP1
        0x03, // SUB
        0x80, // DUP1
        0x60, 0x05, // PUSH1 5
        0x57, // JUMPI -> 5
        0x50, // POP
        0x00, // STOP
    ]
}

/// The arithmetic loop with a `KECCAK256` over `memory[0..32]` per iteration.
fn keccak_loop(n: u32) -> Vec<u8> {
    let n = n.to_be_bytes();
    vec![
        0x63, n[0], n[1], n[2], n[3], // PUSH4 n
        0x5b, // JUMPDEST  (pc 5)
        0x60, 0x20, // PUSH1 32
        0x60, 0x00, // PUSH1 0
        0x20, // KECCAK256
        0x50, // POP
        0x60, 0x01, // PUSH1 1
        0x90, // SWAP1
        0x03, // SUB
        0x80, // DUP1
        0x60, 0x05, // PUSH1 5
        0x57, // JUMPI -> 5
        0x50, // POP
        0x00, // STOP
    ]
}

fn main() {
    println!("athanor throughput (best of N, single-threaded):");
    measure("arithmetic", arithmetic_loop(3_000_000), 10);
    measure("keccak256", keccak_loop(1_000_000), 10);
}

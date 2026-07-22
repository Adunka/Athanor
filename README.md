<div align="center">

# athanor

**An Ethereum Virtual Machine, written from first principles in Rust.**

A Cancun-ruleset interpreter with its own journaled state, exact gas accounting,
and a non-recursive call-frame executor. Built to be *read*: the code follows the
shape of the protocol rather than any existing client, and every rule it
implements cites the EIP or Yellow Paper section it came from.

[![ci](https://github.com/Adunka/Athanor/actions/workflows/ci.yml/badge.svg)](https://github.com/Adunka/Athanor/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
[![ruleset](https://img.shields.io/badge/ruleset-cancun-8250df.svg)](#status)
[![rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

<sub><i>An athanor is the alchemist's slow furnace — a vessel that holds a
steady heat while base inputs are transmuted. This one transmutes transactions
into state.</i></sub>

</div>

---

## Architecture

```
             ┌────────────────────────────────────────────┐
             │ Evm (evm.rs)                               │
             │                                            │
             │  transaction validation · frame stack ·    │
             │  value transfer · create collisions ·      │
             │  code deposit · refund settlement          │
             └───────┬────────────────────────┬───────────┘
                     │ Action::{Call,Create}  │ Host
             ┌──────▼───────────┐   ┌──────▼────────────┐
             │ Interpreter      │   │ JournaledState    │
             │ (interpreter.rs) │   │ (state.rs)        │
             │  one frame ·     │   │  accounts · warm  │
             │  dispatch ·      │   │  sets · transient │
             │  jumpdest bitmap │   │  storage · logs · │
             └──────────────────┘   │  checkpoint/revert│
                                    └───────────────────┘
```

The interpreter **never calls itself**. A `CALL` or `CREATE` suspends the frame
and yields an `Action`; the executor pushes a child frame, runs it, and resumes
the parent with the outcome. EVM call depth (up to 1024) therefore costs O(1)
native stack. The same loop is what makes revert semantics cheap: every frame
owns a journal checkpoint, and unwinding is just replaying inverse operations.

## Status

Executes the full Cancun instruction set end-to-end — including the parts
that are usually the last to work.

| Area | Coverage |
| --- | --- |
| **Instructions** | All Cancun opcodes: arithmetic through `MCOPY`, `TLOAD`/`TSTORE`, `PUSH0`, `SELFDESTRUCT` per EIP-6780 |
| **Gas** | EIP-2929 warm/cold with journaled warm sets, full EIP-2200/3529 `SSTORE` matrix with refunds, EIP-150 63/64, EIP-3860 init-code metering, memory quadratic expansion |
| **Frames** | `CALL` / `CALLCODE` / `DELEGATECALL` / `STATICCALL`, `CREATE` / `CREATE2` with EIP-684 collisions, EIP-170/3541 deposit rules, EIP-211 return-data semantics |
| **Transactions** | Intrinsic gas (EIP-2028), EIP-3607 sender check, EIP-2681 nonce cap, optional declared-nonce validation, refund cap, sender reimbursement, EIP-3651 warm coinbase |
| **State** | Journal with checkpoint/revert covering balances, nonces, code, storage originals, transient storage, warm sets, logs, EIP-6780 deletion tracking; `state_root()` computes the real trie root over the accounts |
| **Bytecode** | Contract code behind an `Arc` with lazily-memoized `JUMPDEST` analysis and code hash — shared by frames and journal entries alike, so cloning code never copies bytes |
| **Precompiles** | 0x01–0x09: `ecrecover`, `sha256`, `ripemd160`, `identity`, `modexp` (EIP-2565 gas), bn256 add/mul/pairing (EIP-196/197), and `blake2f` (EIP-152), verified against go-ethereum's output-and-gas vectors (106 cases) |

**Roadmap**, in the order it is planned:

1. **State roots — done.** `JournaledState::state_root()` now computes the real
   Ethereum world-state root through [`athanor-trie`](crates/trie): accounts keyed
   by `keccak256(address)` over the RLP of `[nonce, balance, storageRoot,
   codeHash]`, each storage root a secure trie in its own right. The secure-trie
   key hashing is checked against Ethereum's official secure-`TrieTests` vectors.
2. **Consensus tests — 99.8% of the full official suite (19,690 / 19,732).**
   The directory-scanning harness in `crates/athanor/tests/state_tests.rs` runs
   Ethereum's official `GeneralStateTests` on Cancun end-to-end and reproduces
   each published post-state root. Legacy and EIP-1559 fees, EIP-2930 access
   lists, and coinbase fee payment are all handled. A committed 55-case slice is
   the CI regression gate; the same test widens to the whole suite when pointed
   at a full checkout. The remaining ~0.4% is blob transactions (EIP-4844,
   unsupported) and a handful of create/precompile edge cases.
3. **Differential fuzzing** against `revm`. Invariant fuzzing already runs
   (no-panic, determinism, gas-bound; see Conformance); the remaining piece
   is diffing output, gas, and state root against a reference EVM on random
   bytecode, which needs `revm` and so runs off the 1.75 MSRV.
4. **Precompiles — 0x01–0x09 done.** `ecrecover`, `sha256`, `ripemd160`,
   `identity`, `modexp` (EIP-2565 gas), the bn256 curve trio — point addition,
   scalar multiplication, and the optimal-ate **pairing** check (EIP-196/197) —
   and the `blake2f` compression (EIP-152) run for real in `src/precompile.rs`,
   checked against go-ethereum's own vectors for output *and* gas (106 cases in
   all). Only KZG point-eval (0x0a) remains; it needs a trusted setup, so it is
   its own milestone.
5. **Performance — a JIT, done.** [`athanor-jit`](crates/jit) compiles the
   arithmetic, stack and control-flow core to native code through Cranelift and
   runs it 8.6x faster than the interpreter on a tight loop, falling back to
   the interpreter for everything that touches the host (see below). The
   interpreter's own dispatch table, code caching and allocation audit remain
   open; the benchmark harness that would gate them exists, and guessing at
   performance is how interpreters get slower, so the numbers come first.

**Known simplifications**, stated so they do not read as oversights: EIP-161
touched-account clearing is not implemented (post-Spurious-Dragon chains rarely
exercise it); `BLOCKHASH` serves from a user-supplied map; EIP-4844 blob
transactions are not yet modelled.

## Conformance

The claims above are checked against Ethereum's own vectors, not asserted:

* **State tests.** athanor runs Ethereum's official `GeneralStateTests` on
  Cancun end-to-end — it rebuilds each fixture's pre-state, executes the
  transaction, and reproduces the published post-state root exactly. Against a
  full checkout it passes **19,690 of 19,732 cases (99.8%)**; a committed 55-case
  slice is the CI regression gate, and the same test covers the whole suite when
  `ATHANOR_STATETESTS_DIR` points at a `GeneralStateTests` directory. Coverage
  spans legacy and EIP-1559 fees, EIP-2930 access lists, value transfers,
  contract execution, nested `CALL`/`CALLCODE`, the full SSTORE gas-and-refund
  matrix, EIP-6780 `SELFDESTRUCT`, the 1024-deep call-stack limit, and
  gas-price-overflow rejection. A single mispriced opcode would shift a balance
  and break the root, so these passing is a statement about gas exactness as
  much as correctness. The remaining ~0.4% is blob transactions (EIP-4844,
  unsupported) plus a few create/precompile edge cases.

  Running the full suite surfaced four consensus bugs a fixed vector set never
  reached, all now fixed. modexp charged gas *after* sizing its output buffer, so
  a hostile declared length forced a multi-terabyte allocation ahead of the
  out-of-gas check — it is now priced from the header first, as go-ethereum does.
  The call-depth guard was off by one (`>=` where the consensus rule is `>`),
  cutting deep recursion one frame short; that alone moved 142 cases. A `CREATE`
  target was warmed *after* the revert checkpoint, so a failed create wrongly
  left the address cold — go-ethereum warms it before the snapshot precisely so
  a failed or colliding create leaves it warm (EIP-2929). And the create
  collision check missed the storage arm: a create onto an address that already
  holds nonzero storage must abort (EIP-7610), which athanor now enforces.
  Finally, EIP-1559 fee-market validity is enforced up front: a transaction
  whose gas price falls below the block base fee is rejected before any state
  change, and one whose priority fee exceeds its cap is rejected in the harness
  that assembles the fee-market fields.
* **Trie tests.** The trie reproduces every root in Ethereum's official
  `TrieTests` and secure-`TrieTests` (see below).
* **Precompiles.** `ecrecover`, `sha256`, `ripemd160`, `identity`, `modexp`,
  the bn256 add/mul/pairing trio, and `blake2f` are checked against
  go-ethereum's vectors for both output and gas — 106 cases, including the
  pairing check (`cargo test -p athanor --test precompile_vectors`).
* **Fuzzing.** Property tests drive both arbitrary bytes and stack-primed
  bytecode through the interpreter, asserting it never panics, stays
  deterministic, and never charges past its gas limit — the failure modes a
  fixed vector set cannot reach (`cargo test -p athanor --test fuzz`).

```
cargo test -p athanor --test state_tests   # committed slice (CI regression gate)
```

To run the whole suite, point the same test at a full `GeneralStateTests`
checkout (from
[`ethereum/tests`](https://github.com/ethereum/tests)); it reports the match
count and writes any misses to `statetests-failures.txt`:

```
ATHANOR_STATETESTS_DIR=/path/to/GeneralStateTests \
  cargo test --release -p athanor --test state_tests -- --nocapture
```

## Performance

There is a small dependency-free throughput harness (`benches/throughput.rs`)
that runs tight bytecode loops and reports gas per second — one for the raw
opcode-dispatch path, one dominated by `KECCAK256`. It exists less to publish a
headline number than to gate optimisation: a dispatch-table or allocation
change should move these, and it is worth knowing by how much before and after.

```
cargo bench -p athanor
```

Absolute figures are hardware-bound and only mean something relative to each
other and the machine they were taken on; on the build sandbox it lands around
340 Mgas/s on the arithmetic loop and 100 Mgas/s on the keccak loop, the gap
being exactly the hashing cost. No dispatch table, computed-goto, or unsafe
fast paths yet — that is deliberately future work, now that there is a way to
measure whether it helps.

## The JIT

The workspace's third crate, [`athanor-jit`](crates/jit), compiles bytecode to
native code with Cranelift and runs it over the same frame the interpreter
would have used. On a tight arithmetic loop it is **8.6x faster** — 4.0 Ggas/s
against the interpreter's 467 Mgas/s on the build sandbox — for 0.8 ms of
compilation, which pays for itself after roughly 440,000 gas of execution.

It compiles the arithmetic, comparison, bitwise, stack and control-flow core
and hands everything else back. The opcodes it declines are the ones that talk
to the host — storage, calls, memory expansion — where the win is small and the
surface for a consensus bug is not. Reaching one is not a failure: compiled
code writes the live stack and gas back, returns the offset it stopped at, and
an interpreter carries on from there.

Three things make it more than a bytecode-shaped `match`:

* **Gas is charged once per block, not once per instruction.** A block ends at
  the first opcode the compiler cannot handle, not merely at the first jump, so
  every instruction in one is known to execute — which is what makes it sound
  to front-load the cost, and to collapse the per-instruction underflow and
  overflow checks into one of each. An unaffordable block halts exceptionally
  and forfeits its gas anyway, so charging early cannot be observed.
* **Cranelift has no 256-bit integer.** A stack word is carried as four 64-bit
  limbs, least significant first, which is the layout `uint` already uses, so a
  word crosses the boundary as a copy rather than a conversion. Addition and
  subtraction become explicit carry and borrow chains; comparison folds from
  the low limb upward, each higher limb overriding the result below it unless
  the two tie. This is the price of not depending on an LLVM toolchain, and it
  is paid so that `cargo build` stays the whole story.
* **Dynamic jumps are dispatched by binary search.** A destination is only
  known at run time, so every `JUMP` funnels into one dispatcher that searches
  the `JUMPDEST` set the analysis already collected — `log2(n)` compares rather
  than a walk down a chain, which is the entire reason to know the destination
  set at compile time.

One deliberate divergence, stated so it does not read as an oversight: which
exceptional halt fires can differ from the interpreter, because charging gas a
block at a time reaches out-of-gas where stepping would have underflowed an
instruction later. The EVM draws no distinction — every exceptional halt
forfeits the frame's gas and changes no state (YP 9.4.2) — so the two engines
are held to agreeing that the frame failed, and compared exactly on gas and
stack whenever it did not.

Correctness is not argued, it is differentially tested. Random programs drawn
from the compiled subset are run twice, once compiled and once interpreted, and
the two must agree on how the frame ended, on the gas left, and on the stack
word for word. The reference is the interpreter that reproduces 19,690 of the
19,732 official Cancun state tests, so agreement is a strong statement rather
than a self-consistent one.

```
cargo test -p athanor-jit     # unit tests, plus differential agreement
cargo bench -p athanor-jit    # throughput against the interpreter
```


## The trie

The workspace's trie crate, [`athanor-trie`](crates/trie), is the Merkle
Patricia Trie that will give athanor real state roots. It stands on its own:

* the full node set — leaf, extension, and sixteen-way branch — with the
  hex-prefix path encoding and the *inline nodes under 32 bytes, hash the rest*
  reference rule that most hand-rolled tries get subtly wrong;
* its own RLP codec (encode and decode), since a node's hash is the keccak of
  its RLP and the bytes have to be exact;
* insert, get, and delete — the last with the branch- and extension-collapse
  that keeps the structure canonical, so deleting a key and re-inserting it
  returns to the identical root;
* Merkle proof generation and verification, including proofs of *absence*.

Correctness is not asserted, it is checked: the crate runs Ethereum's official
`TrieTests` vectors (embedded verbatim under `crates/trie/tests/fixtures/`) and
must reproduce every published root, the complex multi-node cases included.

```
cargo test -p athanor-trie   # unit tests + official TrieTests conformance
```

## Using it

```rust
use athanor::{Account, Env, Evm, U256};

let mut evm = Evm::new(Env::default());
evm.env.tx.caller = sender;
evm.env.tx.to = Some(contract);
evm.env.tx.gas_limit = 1_000_000;

evm.journal.seed(sender, Account { balance: U256::from(1u64) << 64, ..Default::default() });
evm.journal.seed(contract, Account { nonce: 1, code: bytecode, ..Default::default() });

let result = evm.transact()?;
println!("{:?} used {} gas", result.outcome, result.gas_used);
```

## Testing

The tests are the real specification.

The integration suite (`crates/athanor/tests/evm.rs`) hand-assembles bytecode and
asserts either exact state or exact gas — including the numbers you would
work out on paper: **21205** for a cold storage clear with its 4800 refund,
**49998** observed by a callee handed exactly 50000.

The property suite (`crates/athanor/tests/properties.rs`) holds one invariant
above the rest: arbitrary bytecode may fail any way it likes, but it may **never
panic the process**. Every byte string is a program, and hostile programs are the
normal case for a VM.

```
cargo test          # 132 tests: units, transactions, property fuzzing, JIT agreement
cargo clippy --all-targets
cargo fmt
```

## Design notes

Longer-form reasoning — why the executor is a loop, why dispatch is a
`match`, how the journal keeps EIP-2929 warm sets consistent under revert —
lives in **[docs/DESIGN.md](docs/DESIGN.md)**.

MSRV is **1.75**. The core is deliberately shallow: `uint` and `fixed-hash`
(no default features) provide the word types and `tiny-keccak` the hashing.
The one considered exception is the precompile layer, which leans on vetted
cryptography crates — `sha2`, `ripemd`, `secp256k1`, `num-bigint`, and
`substrate-bn` for the bn256 pairing — rather than hand-rolling SHA-256,
RIPEMD-160, secp256k1 recovery, bignum modexp, or an elliptic-curve pairing,
which is the right call for security-sensitive code. Dev-dependencies add
`proptest` for the fuzz layer. The JIT crate is the one place that reaches for
something large — Cranelift, for code generation — and it is isolated behind
its own crate so the EVM core keeps the shallow tree above. `Cargo.lock` is
committed: reproducing a build is the point of a lockfile, and CI runs
`--locked` against it.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your
option.

<div align="center">
<sub>Read the code. It cites its sources.</sub>
</div>

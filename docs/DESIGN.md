# Design notes

Decisions worth defending, and the reasoning behind them. The audience is
someone who has read an EVM implementation before and wants to know where
this one stands on the usual forks in the road.

## The executor is a loop, not recursion

The obvious way to implement `CALL` is to have the interpreter call itself.
It is also the way that couples native stack depth to EVM call depth
(bounded at 1024, but 1024 frames of interpreter state is real memory in
awkward places), and it threads a `&mut Host` borrow through every level
of recursion, which in Rust turns into lifetime gymnastics precisely where
the code least needs it.

Instead, `Interpreter::run` returns an `Action`:

```text
Action::Call(CallInputs)     — parsed operands, caller-side gas charged
Action::Create(CreateInputs)
Action::End(Outcome)
```

`Evm::run_frames` owns a `Vec<Frame>` and a loop. Entering a child pushes;
`Action::End` pops, settles the frame (revert-on-failure, code deposit for
creates), and resumes the parent through `resume_call`/`resume_create`.
The division of labor is strict: the interpreter knows operand order and
frame-local gas; the executor knows depth, balances, collisions, and
checkpoints. Neither can express the other's bugs. revm arrived at the
same split; that this design is re-derivable from the constraints is a
point in its favor.

One consequence worth naming: the depth-1024 and insufficient-balance
pre-checks produce `Outcome::Revert(empty)` rather than a bespoke failure
variant. A failed pre-check and an empty revert are observationally
identical to the caller — status 0, empty return buffer, forwarded gas
returned — so the type system carries one case instead of two.

## The journal is the source of truth for "undo"

Everything mutable during a transaction goes through `JournaledState`, and
every mutation appends an inverse entry. `REVERT`, exceptional halts, and
failed creates are all the same operation: replay inverses back to a
checkpoint.

The subtlety that justifies the design is the interaction between reverts
and *transaction-scoped* substate:

- **EIP-2929 warm sets are journaled.** If a frame warms an address and
  then reverts, the address is cold again — geth journals access-list
  additions the same way. Getting this wrong is invisible to almost every
  test and still a consensus split.
- **`SSTORE` originals** (EIP-2200's third operand) are recorded on first
  write per slot per transaction, and the journal remembers whether an
  entry was that first write so revert can erase the baseline too.
- **Refunds are per-frame and merge on success.** A reverted frame's
  refunds die with it. This falls out of keeping the counter in `Gas` and
  merging in `resume_*` only on success, which matches geth journaling its
  global counter — two mechanisms, same observable ledger.

`end_tx` is the only place transaction-scoped state dies: EIP-6780
deletions (self-destructed ∩ created-this-tx), transient storage, warm
sets, logs, originals.

## Code is shared; analysis is memoized

`Bytecode` wraps contract bytes in an `Arc` together with two lazily
computed companions — the `JUMPDEST` bitmap and the keccak code hash —
each behind an `Arc<OnceLock>` visible to every clone. Every consumer
that used to copy bytes (frame entry, `EXTCODE*`, journaling the old code
on `set_code`) now bumps a reference count. The observable consequences:

- a contract called N times in a transaction is analyzed once, not N
  times — the self-recursion test drives hundreds of frames through one
  shared table;
- `EXTCODEHASH` hashes a given code identity once, ever;
- out-of-range jump destinations are invalid *by construction* (padding
  bits in the bitmap are never set), so the bounds check implementations
  forget does not exist to forget.

`OnceLock` rather than eager work because most code paths never jump and
never ask for the hash; paying at first use keeps `CREATE`-heavy
workloads honest.

## Dispatch is a `match`

Instruction tables (256 function pointers) and threaded dispatch win
microbenchmarks. This crate uses one `match` in `Interpreter::step`
because the current bottleneck is *reviewability*: the dispatch arm for
`SSTORE` reads top-to-bottom as the EIP-2200 pseudocode, and a reviewer
can diff it against the spec without chasing indirection.

The plan for changing this is deliberately gated: build the criterion
harness first (snailtracer and a storage-heavy benchmark), measure, then
try the table. An interpreter is the canonical place where "obviously
faster" designs measure slower — dispatch prediction on modern branch
predictors is good, and the `match` compiles to a jump table anyway. No
performance claims until there are numbers.

## Memory charges before it allocates

`Memory::expand` computes the quadratic cost delta and records it against
the gas meter *before* touching the buffer, and a hard cap (2^32 bytes)
bounds the address arithmetic itself. The ordering means an absurd
`MLOAD` offset is an ordinary out-of-gas, never an allocation attempt —
the gas schedule is the DoS defense, and it only works if it is consulted
first.

## Two-phase `SSTORE` pricing

`Host::sstore` performs the journaled write and returns `(original,
current, cold)`; the interpreter then computes cost and refund from the
EIP-2200/2929/3529 matrix and charges. Charging *after* writing looks
backwards until revert enters the picture: on out-of-gas the frame halts,
the checkpoint unwinds, and the write vanishes — observationally the
charge-then-write order, without the state layer needing to understand
gas. The full matrix (all nine warm cases plus cold variants) is
unit-tested in `gas.rs` against the numbers in the EIPs.

## On `unsafe`

There is none. The word types come from `uint`/`fixed-hash` macro
instantiation, the hashing from `tiny-keccak`. If profiling ever argues
for `unsafe`, it argues to a benchmark, not to taste.

## Testing philosophy

Unit tests pin the sharp edges per module (i256 min/-1, the `SSTORE`
matrix, jumpdest-in-push-data, memory cost at the schedule's knee).
Integration tests run whole transactions with hand-assembled bytecode and
assert exact numbers — `gas_used == 21205`, address equality against the
EIP-1014 vectors fetched from the EIP text itself. Exactness is the
point: a gas assertion that says `> 21000` documents a hope, not a rule.

The next tier is `ethereum/execution-spec-tests` state tests wired into
CI, which replaces "the tests I thought to write" with "the tests the
protocol ships". Until that lands, coverage claims here should be read as
scoped to what the suite above exercises.

Property tests add the layer example-based tests cannot:
`arbitrary_bytecode_never_panics` feeds random byte strings through
`transact` and asserts only that the process survives. A VM's whole job
is executing adversarial input, so panic-freedom is a security property,
not a style preference. The remaining properties pin algebraic laws of
the signed arithmetic — division reconstruction including `MIN / -1`,
shift agreement on non-negative values, comparison trichotomy — across
the input space instead of hand-picked corners.

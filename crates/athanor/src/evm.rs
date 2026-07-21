//! The transaction executor.
//!
//! [`Evm`] owns the environment and the journaled state, implements
//! [`Host`] for the interpreter, and drives the frame stack. The
//! interpreter yields [`Action`]s; this module is where call depth, value
//! transfer, create collisions, code deposit and the refund cap live —
//! everything that spans more than one frame.
//!
//! Frame lifecycle: checkpoint the journal, transfer value, run. A frame
//! that reverts or halts has its checkpoint rolled back; its refund counter
//! dies with it (matching geth, where the refund is itself journaled). A
//! frame that succeeds merges gas and refunds into its parent.

use crate::bytecode::Bytecode;
use crate::gas::{self, cost, Gas};
use crate::host::{AccessResult, Env, Host, SStoreResult, SelfDestructResult};
use crate::interpreter::{
    Action, CallInputs, CallOutcome, CreateInputs, CreateOutcome, Interpreter,
};
use crate::precompile;
use crate::primitives::{create2_address, create_address, keccak256, Address, B256, U256};
use crate::result::{ExecutionResult, Halt, Outcome, TxError, TxKind};
use crate::state::{Checkpoint, JournaledState, Log};
use std::collections::HashMap;

/// The identity precompile; the only one implemented so far (see README
/// status table). Addresses 0x01..0x09 are still pre-warmed per EIP-2929.
const PRECOMPILE_COUNT: u64 = 9;

pub struct Evm {
    pub env: Env,
    pub journal: JournaledState,
    /// Hashes served to `BLOCKHASH`; anything absent reads as zero, which
    /// is also what the spec mandates outside the 256-block window.
    pub block_hashes: HashMap<U256, B256>,
}

struct Frame {
    interpreter: Interpreter,
    checkpoint: Checkpoint,
    kind: FrameKind,
}

enum FrameKind {
    Call {
        return_offset: usize,
        return_len: usize,
    },
    Create {
        address: Address,
    },
}

/// A frame either starts executing or resolves on the spot (no code to
/// run, precompile, depth or balance pre-check failure).
enum Entered {
    Frame(Box<Frame>),
    Immediate { outcome: Outcome, gas: Gas },
}

/// A popped frame, with what its parent needs to consume it.
enum Closed {
    Call {
        outcome: Outcome,
        gas: Gas,
        return_offset: usize,
        return_len: usize,
    },
    Create {
        outcome: Outcome,
        gas: Gas,
        address: Address,
    },
}

impl Evm {
    pub fn new(env: Env) -> Self {
        Self {
            env,
            journal: JournaledState::new(),
            block_hashes: HashMap::new(),
        }
    }

    /// Execute `self.env.tx` against the current state.
    ///
    /// `Err` means the transaction is invalid and nothing was charged;
    /// `Ok` means it was included, even if the execution itself reverted
    /// or halted — gas accounting in the result tells the story.
    pub fn transact(&mut self) -> Result<ExecutionResult, TxError> {
        let caller = self.env.tx.caller;
        let gas_limit = self.env.tx.gas_limit;
        let value = self.env.tx.value;
        let data = self.env.tx.data.clone();
        let is_create = self.env.tx.to.is_none();

        // --- up-front validation; state untouched on any Err ---
        // Ordering mirrors the checks a block builder performs: sender
        // eligibility first, then nonce, then size and price arithmetic.

        // EIP-3607: an account with code cannot originate transactions.
        if !self.journal.code(caller).is_empty() {
            return Err(TxError::SenderNotEoa);
        }
        let state_nonce = self.journal.nonce(caller);
        if let Some(tx_nonce) = self.env.tx.nonce {
            if tx_nonce != state_nonce {
                return Err(TxError::NonceMismatch {
                    state: state_nonce,
                    tx: tx_nonce,
                });
            }
        }
        // EIP-2681: the nonce increment below must not wrap.
        if state_nonce == u64::MAX {
            return Err(TxError::NonceOverflow);
        }
        if is_create && data.len() > cost::MAX_INITCODE_SIZE {
            return Err(TxError::InitCodeSizeLimit);
        }
        let intrinsic = intrinsic_gas(&data, is_create, &self.env.tx.access_list);
        if gas_limit < intrinsic {
            return Err(TxError::IntrinsicGas {
                intrinsic,
                limit: gas_limit,
            });
        }
        // EIP-1559: the effective gas price must cover the base fee, else the
        // transaction cannot pay the mandatory burn and is invalid. Caught
        // before any state change, so the pre-state stands.
        if self.env.tx.gas_price < self.env.block.basefee {
            return Err(TxError::GasPriceBelowBaseFee {
                gas_price: self.env.tx.gas_price,
                basefee: self.env.block.basefee,
            });
        }
        let upfront = U256::from(gas_limit)
            .checked_mul(self.env.tx.gas_price)
            .ok_or(TxError::Overflow)?;
        let required = upfront.checked_add(value).ok_or(TxError::Overflow)?;
        let available = self.journal.balance(caller);
        if available < required {
            return Err(TxError::InsufficientFunds {
                required,
                available,
            });
        }

        // --- charge the sender; these effects survive any outcome ---

        self.journal.set_balance(caller, available - upfront);
        let sender_nonce = self.journal.inc_nonce(caller);

        self.journal.prewarm_address(caller);
        self.journal.prewarm_address(self.env.block.coinbase); // EIP-3651
        for i in 1..=PRECOMPILE_COUNT {
            self.journal.prewarm_address(Address::from_low_u64_be(i));
        }
        if let Some(to) = self.env.tx.to {
            self.journal.prewarm_address(to);
        }

        // EIP-2930: everything the access list declared starts warm.
        let access_list = self.env.tx.access_list.clone();
        for (address, keys) in &access_list {
            self.journal.prewarm_address(*address);
            for key in keys {
                self.journal.prewarm_slot(*address, *key);
            }
        }

        let gas = Gas::new(gas_limit - intrinsic);

        // --- root frame ---

        let (entered, kind) = match self.env.tx.to {
            Some(to) => {
                let inputs = CallInputs {
                    scheme: crate::interpreter::CallScheme::Call,
                    code_address: to,
                    target: to,
                    caller,
                    value,
                    transfers_value: !value.is_zero(),
                    requires_balance: !value.is_zero(),
                    input: data,
                    gas_limit: gas.remaining(),
                    is_static: false,
                    return_offset: 0,
                    return_len: 0,
                };
                (self.enter_call(inputs, 0), TxKind::Call)
            }
            None => {
                let address = create_address(caller, sender_nonce);
                let inputs = CreateInputs {
                    creator: caller,
                    value,
                    init_code: data,
                    salt: None,
                    gas_limit: gas.remaining(),
                };
                // The root create reuses the frame path but derives its
                // address from the already-bumped sender nonce.
                (
                    self.enter_create_at(inputs, address, 0),
                    TxKind::Create(address),
                )
            }
        };

        let (outcome, frame_gas) = match entered {
            Entered::Immediate { outcome, gas } => (outcome, gas),
            Entered::Frame(frame) => self.run_frames(*frame),
        };

        // --- settle ---

        let spent = intrinsic + (gas_limit - intrinsic - frame_gas.remaining());
        let refund = if outcome.is_success() {
            let cap = spent / 5; // EIP-3529
            (frame_gas.refunded().max(0) as u64).min(cap)
        } else {
            0
        };
        let gas_used = spent - refund;

        let reimburse = U256::from(gas_limit - gas_used) * self.env.tx.gas_price;
        let balance = self.journal.balance(caller);
        self.journal.set_balance(caller, balance + reimburse);

        // Pay the coinbase the priority fee. The sender was charged the full
        // effective gas price; of that, the base fee (EIP-1559) is burned and
        // the remainder — the tip — goes to the block's beneficiary. A legacy
        // transaction on a zero-base-fee block tips the whole gas price.
        let priority = self.env.tx.gas_price.saturating_sub(self.env.block.basefee);
        if !priority.is_zero() {
            let fee = U256::from(gas_used) * priority;
            let coinbase = self.env.block.coinbase;
            let paid = self.journal.balance(coinbase) + fee;
            self.journal.set_balance(coinbase, paid);
        }

        let logs = self.journal.end_tx();
        let logs = if outcome.is_success() {
            logs
        } else {
            Vec::new()
        };

        Ok(ExecutionResult {
            kind: match kind {
                TxKind::Create(a) if outcome.is_success() => TxKind::Create(a),
                other => other,
            },
            outcome,
            gas_used,
            gas_refunded: refund,
            logs,
        })
    }

    /// Drive the frame stack until the root frame finishes.
    fn run_frames(&mut self, root: Frame) -> (Outcome, Gas) {
        let mut frames: Vec<Frame> = vec![root];
        loop {
            let depth = frames.len();
            let action = frames.last_mut().expect("nonempty").interpreter.run(self);
            match action {
                Action::Call(inputs) => {
                    let (ret_off, ret_len) = (inputs.return_offset, inputs.return_len);
                    match self.enter_call(inputs, depth) {
                        Entered::Frame(f) => frames.push(*f),
                        Entered::Immediate { outcome, gas } => {
                            let parent = &mut frames.last_mut().expect("caller").interpreter;
                            parent.resume_call(call_outcome(outcome, gas), ret_off, ret_len);
                        }
                    }
                }
                Action::Create(inputs) => match self.enter_create(inputs, depth) {
                    Entered::Frame(f) => frames.push(*f),
                    Entered::Immediate { outcome, gas } => {
                        let parent = &mut frames.last_mut().expect("caller").interpreter;
                        parent.resume_create(create_outcome(outcome, gas, None));
                    }
                },
                Action::End(outcome) => {
                    let frame = frames.pop().expect("nonempty");
                    let closed = self.close_frame(frame, outcome);
                    let Some(parent) = frames.last_mut() else {
                        return match closed {
                            Closed::Call { outcome, gas, .. }
                            | Closed::Create { outcome, gas, .. } => (outcome, gas),
                        };
                    };
                    match closed {
                        Closed::Call {
                            outcome,
                            gas,
                            return_offset,
                            return_len,
                        } => parent.interpreter.resume_call(
                            call_outcome(outcome, gas),
                            return_offset,
                            return_len,
                        ),
                        Closed::Create {
                            outcome,
                            gas,
                            address,
                        } => parent.interpreter.resume_create(create_outcome(
                            outcome,
                            gas,
                            Some(address),
                        )),
                    }
                }
            }
        }
    }

    /// Finish a frame: revert on failure, deposit code for creates, and
    /// hand back the pieces the parent needs.
    fn close_frame(&mut self, frame: Frame, outcome: Outcome) -> Closed {
        let mut gas = frame.interpreter.gas;
        match frame.kind {
            FrameKind::Call {
                return_offset,
                return_len,
            } => {
                if !outcome.is_success() {
                    self.journal.revert(frame.checkpoint);
                }
                Closed::Call {
                    outcome,
                    gas,
                    return_offset,
                    return_len,
                }
            }
            FrameKind::Create { address } => {
                let outcome = match outcome {
                    Outcome::Return(code) => match self.deposit_code(address, code, &mut gas) {
                        Ok(()) => Outcome::Return(Vec::new()),
                        Err(halt) => {
                            gas.consume_all();
                            Outcome::Halt(halt)
                        }
                    },
                    other => other,
                };
                if !outcome.is_success() {
                    self.journal.revert(frame.checkpoint);
                }
                Closed::Create {
                    outcome,
                    gas,
                    address,
                }
            }
        }
    }

    /// EIP-3541 (no 0xEF prefix), EIP-170 (24576-byte cap), and the
    /// 200-per-byte deposit charge, paid from the child's remaining gas.
    fn deposit_code(&mut self, address: Address, code: Vec<u8>, gas: &mut Gas) -> Result<(), Halt> {
        if code.first() == Some(&0xef) {
            return Err(Halt::InvalidCodeFirstByte);
        }
        if code.len() > cost::MAX_CODE_SIZE {
            return Err(Halt::CodeSizeLimit);
        }
        gas.record(cost::CODE_DEPOSIT_BYTE * code.len() as u64)?;
        self.journal.set_code(address, Bytecode::new(code));
        Ok(())
    }

    fn enter_call(&mut self, inputs: CallInputs, depth: usize) -> Entered {
        let gas = Gas::new(inputs.gas_limit);

        // Depth and balance pre-checks fail the call without running it:
        // status 0, empty return data, forwarded gas handed back — which
        // is exactly what an empty revert looks like to the caller.
        if depth > 1024 {
            return Entered::Immediate {
                outcome: Outcome::Revert(Vec::new()),
                gas,
            };
        }
        if inputs.requires_balance && self.journal.balance(inputs.caller) < inputs.value {
            return Entered::Immediate {
                outcome: Outcome::Revert(Vec::new()),
                gas,
            };
        }

        let checkpoint = self.journal.checkpoint();
        if inputs.transfers_value {
            self.journal
                .transfer(inputs.caller, inputs.target, inputs.value)
                .expect("balance verified above");
        }

        if is_precompile(inputs.code_address) {
            let outcome = run_precompile(inputs.code_address, &inputs.input, gas);
            if !outcome.0.is_success() {
                self.journal.revert(checkpoint);
            }
            return Entered::Immediate {
                outcome: outcome.0,
                gas: outcome.1,
            };
        }

        let code = self.journal.code(inputs.code_address);
        if code.is_empty() {
            // Plain transfer or ping into the void: trivially succeeds.
            return Entered::Immediate {
                outcome: Outcome::Stop,
                gas,
            };
        }

        let interpreter = Interpreter::new(
            code,
            inputs.input,
            inputs.gas_limit,
            inputs.target,
            inputs.caller,
            inputs.value,
            inputs.is_static,
        );
        Entered::Frame(Box::new(Frame {
            interpreter,
            checkpoint,
            kind: FrameKind::Call {
                return_offset: inputs.return_offset,
                return_len: inputs.return_len,
            },
        }))
    }

    fn enter_create(&mut self, inputs: CreateInputs, depth: usize) -> Entered {
        let gas = Gas::new(inputs.gas_limit);
        if depth > 1024 {
            return Entered::Immediate {
                outcome: Outcome::Revert(Vec::new()),
                gas,
            };
        }
        if self.journal.balance(inputs.creator) < inputs.value {
            return Entered::Immediate {
                outcome: Outcome::Revert(Vec::new()),
                gas,
            };
        }
        // EIP-2681: a creator at the nonce cap fails the create the same
        // way an underfunded one does — status zero, gas handed back.
        if self.journal.nonce(inputs.creator) == u64::MAX {
            return Entered::Immediate {
                outcome: Outcome::Revert(Vec::new()),
                gas,
            };
        }

        // The creator's nonce bumps as soon as the create proceeds, and
        // stays bumped even if the init code reverts (EIP-161).
        let nonce = self.journal.inc_nonce(inputs.creator);
        let address = match inputs.salt {
            Some(salt) => create2_address(inputs.creator, salt, keccak256(&inputs.init_code)),
            None => create_address(inputs.creator, nonce),
        };
        self.enter_create_at(inputs, address, depth)
    }

    /// Shared tail of nested and root creates: collision check, account
    /// birth, endowment, frame construction.
    fn enter_create_at(
        &mut self,
        inputs: CreateInputs,
        address: Address,
        _depth: usize,
    ) -> Entered {
        let gas = Gas::new(inputs.gas_limit);

        // EIP-2929: warm the target before the collision check and the
        // checkpoint. go-ethereum adds it to the access list ahead of the
        // snapshot precisely so a failed or colliding create still leaves the
        // address warm — the access-list change is not rolled back.
        self.journal.warm_address(address);

        // EIP-684 / EIP-7610: a nonzero nonce, nonempty code, or any nonzero
        // storage slot at the target aborts the create and consumes all
        // forwarded gas.
        let colliding = self.journal.nonce(address) != 0
            || !self.journal.code(address).is_empty()
            || self.journal.has_nonempty_storage(address);
        if colliding {
            let mut gas = gas;
            gas.consume_all();
            return Entered::Immediate {
                outcome: Outcome::Halt(Halt::CreateCollision),
                gas,
            };
        }

        let checkpoint = self.journal.checkpoint();
        self.journal.create_contract_account(address);
        if !inputs.value.is_zero() {
            self.journal
                .transfer(inputs.creator, address, inputs.value)
                .expect("balance verified above");
        }

        let interpreter = Interpreter::new(
            Bytecode::new(inputs.init_code),
            Vec::new(),
            inputs.gas_limit,
            address,
            inputs.creator,
            inputs.value,
            false,
        );
        Entered::Frame(Box::new(Frame {
            interpreter,
            checkpoint,
            kind: FrameKind::Create { address },
        }))
    }
}

/// Translate a finished child frame into what `resume_call` consumes.
fn call_outcome(outcome: Outcome, gas: Gas) -> CallOutcome {
    let success = outcome.is_success();
    CallOutcome {
        success,
        output: outcome.into_output(),
        gas_remaining: gas.remaining(),
        gas_refunded: if success { gas.refunded() } else { 0 },
    }
}

fn create_outcome(outcome: Outcome, gas: Gas, address: Option<Address>) -> CreateOutcome {
    let success = outcome.is_success();
    CreateOutcome {
        address: if success { address } else { None },
        output: outcome.into_output(),
        gas_remaining: gas.remaining(),
        gas_refunded: if success { gas.refunded() } else { 0 },
    }
}

fn is_precompile(address: Address) -> bool {
    let bytes = address.as_bytes();
    bytes[..12].iter().all(|&b| b == 0) && {
        let low = u64::from_be_bytes(bytes[12..20].try_into().unwrap());
        (1..=PRECOMPILE_COUNT).contains(&low)
    }
}

/// Dispatches to the precompiled contracts. Addresses 0x01–0x09 run for
/// real; only KZG point-eval (0x0a) is unimplemented, and is out of the
/// active range below.
///
/// Gas is charged *before* the body runs — mirroring go-ethereum's
/// `RequiredGas`/`Run` split. This matters for modexp, whose declared operand
/// lengths could otherwise force a ruinous allocation before the caller is
/// found to be out of gas. The bn256 and blake2f contracts can still
/// hard-fail on malformed input after the charge, consuming all gas.
fn run_precompile(address: Address, input: &[u8], mut gas: Gas) -> (Outcome, Gas) {
    let low = u64::from_be_bytes(address.as_bytes()[12..20].try_into().unwrap());

    let cost = match low {
        0x01 => cost::ECRECOVER,
        0x02 => cost::SHA256_BASE + gas::word_cost(input.len() as u64, cost::SHA256_WORD),
        0x03 => cost::RIPEMD160_BASE + gas::word_cost(input.len() as u64, cost::RIPEMD160_WORD),
        0x04 => cost::IDENTITY_BASE + gas::word_cost(input.len() as u64, cost::IDENTITY_WORD),
        0x05 => precompile::modexp_gas(input),
        0x06 => cost::BN_ADD,
        0x07 => cost::BN_MUL,
        0x08 => cost::BN_PAIRING_BASE + cost::BN_PAIRING_PER_PAIR * (input.len() / 192) as u64,
        0x09 if input.len() == 213 => u32::from_be_bytes(input[0..4].try_into().unwrap()) as u64,
        0x09 => 0, // wrong length: blake2f hard-fails below
        _ => return (Outcome::Stop, gas),
    };
    if let Err(halt) = gas.record(cost) {
        gas.consume_all();
        return (Outcome::Halt(halt), gas);
    }

    // The charge succeeded, so the operands are affordable and thus bounded;
    // now run the body for output. `.1` drops each precompile's own gas figure
    // (equal to `cost`); only the produced bytes are needed here.
    let output: Result<Vec<u8>, ()> = match low {
        0x01 => Ok(precompile::ecrecover(input).1),
        0x02 => Ok(precompile::sha256(input).1),
        0x03 => Ok(precompile::ripemd160(input).1),
        0x04 => Ok(precompile::identity(input).1),
        0x05 => Ok(precompile::modexp(input).1),
        0x06 => precompile::bn_add(input).1,
        0x07 => precompile::bn_mul(input).1,
        0x08 => precompile::bn_pairing(input).1,
        _ => precompile::blake2f(input).1,
    };
    match output {
        Ok(bytes) => (Outcome::Return(bytes), gas),
        Err(()) => {
            gas.consume_all();
            (Outcome::Halt(Halt::PrecompileError), gas)
        }
    }
}

/// YP eq. 60 with EIP-2028 data costs and EIP-3860 init-code words.
fn intrinsic_gas(data: &[u8], is_create: bool, access_list: &[(Address, Vec<U256>)]) -> u64 {
    let mut gas = cost::TX_BASE;
    for &byte in data {
        gas += if byte == 0 {
            cost::TX_DATA_ZERO
        } else {
            cost::TX_DATA_NONZERO
        };
    }
    if is_create {
        gas += cost::TX_CREATE + gas::word_cost(data.len() as u64, cost::INITCODE_WORD);
    }
    for (_, keys) in access_list {
        gas += cost::ACCESS_LIST_ADDRESS + keys.len() as u64 * cost::ACCESS_LIST_STORAGE_KEY;
    }
    gas
}

impl Host for Evm {
    fn env(&self) -> &Env {
        &self.env
    }

    fn balance(&mut self, address: Address) -> AccessResult<U256> {
        self.journal.load_balance(address)
    }

    fn code(&mut self, address: Address) -> AccessResult<Bytecode> {
        self.journal.load_code(address)
    }

    fn code_hash(&mut self, address: Address) -> AccessResult<B256> {
        self.journal.load_code_hash(address)
    }

    fn sload(&mut self, address: Address, key: U256) -> AccessResult<U256> {
        self.journal.sload(address, key)
    }

    fn sstore(&mut self, address: Address, key: U256, value: U256) -> SStoreResult {
        self.journal.sstore(address, key, value)
    }

    fn access_account(&mut self, address: Address) -> bool {
        self.journal.warm_address(address)
    }

    fn is_account_dead(&mut self, address: Address) -> bool {
        self.journal.is_dead(address)
    }

    fn tload(&mut self, address: Address, key: U256) -> U256 {
        self.journal.tload(address, key)
    }

    fn tstore(&mut self, address: Address, key: U256, value: U256) {
        self.journal.tstore(address, key, value)
    }

    fn log(&mut self, log: Log) {
        self.journal.log(log)
    }

    fn block_hash(&mut self, number: U256) -> B256 {
        self.block_hashes
            .get(&number)
            .copied()
            .unwrap_or_else(B256::zero)
    }

    fn selfdestruct(&mut self, address: Address, beneficiary: Address) -> SelfDestructResult {
        self.journal.selfdestruct(address, beneficiary)
    }
}

//! The bytecode interpreter: one call frame's worth of execution.
//!
//! The interpreter is deliberately *not* recursive. When it hits a
//! `CALL`-family or `CREATE`-family instruction it parses the operands,
//! charges the caller-side gas, and returns an [`Action`] — then suspends.
//! The executor in [`crate::evm`] owns the frame stack, runs the child, and
//! feeds the result back through [`Interpreter::resume_call`] /
//! [`Interpreter::resume_create`]. Two things fall out of this shape:
//! native stack depth stays O(1) regardless of EVM call depth, and the
//! borrow of the `Host` never has to thread through recursion.
//!
//! Dispatch is a single `match`. Instruction tables win benchmarks, but a
//! `match` reads like the Yellow Paper's appendix H, and correctness review
//! is the current bottleneck, not dispatch overhead (see docs/DESIGN.md for
//! the measurement plan before that changes).

use crate::bytecode::Bytecode;
use crate::gas::{self, cost, Gas};
use crate::host::Host;
use crate::i256;
use crate::memory::Memory;
use crate::opcode as op;
use crate::primitives::{
    address_to_u256, as_u64_saturated, as_usize_checked, h256_to_u256, keccak256, u256_to_address,
    u256_to_h256, Address, B256, U256,
};
use crate::result::{Halt, Outcome};
use crate::stack::Stack;
use crate::state::Log;

/// Which instruction produced a call frame. Decides whose code runs, whose
/// storage is touched, and what `CALLER`/`CALLVALUE` report inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallScheme {
    Call,
    /// Legacy `CALLCODE`: target's code, caller's storage, value passed but
    /// transferred self-to-self (i.e. not at all).
    CallCode,
    /// EIP-7 `DELEGATECALL`: target's code, caller's storage, and the
    /// parent's caller/value pass through unchanged.
    DelegateCall,
    /// EIP-214 `STATICCALL`: like `CALL` with zero value, state writes
    /// forbidden for the whole subtree.
    StaticCall,
}

#[derive(Debug, Clone)]
pub struct CallInputs {
    pub scheme: CallScheme,
    /// Account whose code executes.
    pub code_address: Address,
    /// Account whose storage/balance is the execution context (`ADDRESS`).
    pub target: Address,
    pub caller: Address,
    /// What `CALLVALUE` reports inside the frame.
    pub value: U256,
    /// Whether `value` actually moves between accounts (only plain `CALL`).
    pub transfers_value: bool,
    /// Whether the caller must have `value` available even without a
    /// transfer (`CALLCODE` requires the balance, then moves nothing).
    pub requires_balance: bool,
    pub input: Vec<u8>,
    /// Gas the child may spend, stipend already included.
    pub gas_limit: u64,
    pub is_static: bool,
    /// Parent memory region for the return data, already expanded and paid
    /// for at call time.
    pub return_offset: usize,
    pub return_len: usize,
}

#[derive(Debug, Clone)]
pub struct CreateInputs {
    pub creator: Address,
    pub value: U256,
    pub init_code: Vec<u8>,
    /// `Some` selects the `CREATE2` address formula.
    pub salt: Option<B256>,
    pub gas_limit: u64,
}

/// What a run of the interpreter produced: a finished frame, or a request
/// for the executor to enter a child frame.
#[derive(Debug)]
pub enum Action {
    Call(CallInputs),
    Create(CreateInputs),
    End(Outcome),
}

/// Result of a completed call, as the parent frame consumes it.
#[derive(Debug)]
pub struct CallOutcome {
    pub success: bool,
    /// Full child output (return or revert data), independent of the
    /// caller's `return_len` window.
    pub output: Vec<u8>,
    pub gas_remaining: u64,
    /// Refund counter accumulated by the child subtree; zero unless the
    /// child succeeded — refunds from reverted frames die with them.
    pub gas_refunded: i64,
}

/// Result of a completed create, as the parent frame consumes it.
#[derive(Debug)]
pub struct CreateOutcome {
    /// `Some` iff deployment succeeded.
    pub address: Option<Address>,
    /// Revert data if the init code reverted; empty otherwise (EIP-211:
    /// a successful create leaves the return buffer empty).
    pub output: Vec<u8>,
    pub gas_remaining: u64,
    pub gas_refunded: i64,
}

enum Flow {
    Continue,
    Yield(Action),
}

pub struct Interpreter {
    code: Bytecode,
    pc: usize,
    pub gas: Gas,
    pub stack: Stack,
    pub memory: Memory,

    // Frame context.
    pub address: Address,
    pub caller: Address,
    pub value: U256,
    pub input: Vec<u8>,
    pub is_static: bool,

    /// Output buffer of the most recent completed subcall (EIP-211).
    return_data: Vec<u8>,
}

impl Interpreter {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        code: Bytecode,
        input: Vec<u8>,
        gas_limit: u64,
        address: Address,
        caller: Address,
        value: U256,
        is_static: bool,
    ) -> Self {
        Self {
            code,
            pc: 0,
            gas: Gas::new(gas_limit),
            stack: Stack::new(),
            memory: Memory::new(),
            address,
            caller,
            value,
            input,
            is_static,
            return_data: Vec::new(),
        }
    }

    /// Run until the frame finishes or needs a child frame.
    pub fn run(&mut self, host: &mut dyn Host) -> Action {
        loop {
            match self.step(host) {
                Ok(Flow::Continue) => {}
                Ok(Flow::Yield(action)) => return action,
                Err(halt) => {
                    self.gas.consume_all();
                    return Action::End(Outcome::Halt(halt));
                }
            }
        }
    }

    fn step(&mut self, host: &mut dyn Host) -> Result<Flow, Halt> {
        let Some(&opcode) = self.code.bytes().get(self.pc) else {
            // Running off the end of code is an implicit STOP (YP §9.4.1).
            return Ok(Flow::Yield(Action::End(Outcome::Stop)));
        };
        if !op::DEFINED[opcode as usize] {
            return Err(Halt::InvalidOpcode(opcode));
        }
        self.gas.record(op::STATIC_GAS[opcode as usize] as u64)?;

        let pc = self.pc;
        self.pc += 1;

        match opcode {
            op::STOP => return Ok(Flow::Yield(Action::End(Outcome::Stop))),

            // --- arithmetic ---
            op::ADD => self.binop(|a, b| a.overflowing_add(b).0)?,
            op::MUL => self.binop(|a, b| a.overflowing_mul(b).0)?,
            op::SUB => self.binop(|a, b| a.overflowing_sub(b).0)?,
            op::DIV => self.binop(|a, b| if b.is_zero() { b } else { a / b })?,
            op::SDIV => self.binop(i256::sdiv)?,
            op::MOD => self.binop(|a, b| if b.is_zero() { b } else { a % b })?,
            op::SMOD => self.binop(i256::smod)?,
            op::ADDMOD => {
                let (a, b, n) = self.stack.pop3()?;
                let r = if n.is_zero() {
                    U256::zero()
                } else {
                    ((a.to_u512() + b.to_u512()) % n.to_u512()).low_u256()
                };
                self.stack.push(r)?;
            }
            op::MULMOD => {
                let (a, b, n) = self.stack.pop3()?;
                let r = if n.is_zero() {
                    U256::zero()
                } else {
                    ((a.to_u512() * b.to_u512()) % n.to_u512()).low_u256()
                };
                self.stack.push(r)?;
            }
            op::EXP => {
                let (base, exponent) = self.stack.pop2()?;
                self.gas.record(gas::exp_cost(exponent))?;
                self.stack.push(base.overflowing_pow(exponent).0)?;
            }
            op::SIGNEXTEND => self.binop(i256::signextend)?,

            // --- comparison and bitwise ---
            op::LT => self.binop(|a, b| bool_word(a < b))?,
            op::GT => self.binop(|a, b| bool_word(a > b))?,
            op::SLT => self.binop(|a, b| bool_word(i256::slt(a, b)))?,
            op::SGT => self.binop(|a, b| bool_word(i256::slt(b, a)))?,
            op::EQ => self.binop(|a, b| bool_word(a == b))?,
            op::ISZERO => {
                let a = self.stack.pop()?;
                self.stack.push(bool_word(a.is_zero()))?;
            }
            op::AND => self.binop(|a, b| a & b)?,
            op::OR => self.binop(|a, b| a | b)?,
            op::XOR => self.binop(|a, b| a ^ b)?,
            op::NOT => {
                let a = self.stack.pop()?;
                self.stack.push(!a)?;
            }
            op::BYTE => self.binop(|i, x| {
                if i >= U256::from(32) {
                    U256::zero()
                } else {
                    U256::from(x.byte(31 - i.as_usize()))
                }
            })?,
            op::SHL => self.binop(|shift, value| {
                if shift >= U256::from(256) {
                    U256::zero()
                } else {
                    value << shift.as_usize()
                }
            })?,
            op::SHR => self.binop(|shift, value| {
                if shift >= U256::from(256) {
                    U256::zero()
                } else {
                    value >> shift.as_usize()
                }
            })?,
            op::SAR => self.binop(i256::sar)?,

            op::KECCAK256 => {
                let (offset, len) = self.stack.pop2()?;
                self.gas
                    .record(gas::word_cost(as_u64_saturated(len), cost::KECCAK256_WORD))?;
                let off = self.memory.expand(&mut self.gas, offset, len)?;
                let hash = if len.is_zero() {
                    keccak256(&[])
                } else {
                    keccak256(self.memory.slice(off, len.as_usize()))
                };
                self.stack.push(h256_to_u256(hash))?;
            }

            // --- environment ---
            op::ADDRESS => self.stack.push(address_to_u256(self.address))?,
            op::BALANCE => {
                let a = u256_to_address(self.stack.pop()?);
                let r = host.balance(a);
                self.gas.record(access_cost(r.cold))?;
                self.stack.push(r.value)?;
            }
            op::ORIGIN => {
                let origin = host.env().tx.caller;
                self.stack.push(address_to_u256(origin))?;
            }
            op::CALLER => self.stack.push(address_to_u256(self.caller))?,
            op::CALLVALUE => self.stack.push(self.value)?,
            op::CALLDATALOAD => {
                let offset = self.stack.pop()?;
                let mut word = [0u8; 32];
                if let Some(o) = as_usize_checked(offset) {
                    if o < self.input.len() {
                        let n = 32.min(self.input.len() - o);
                        word[..n].copy_from_slice(&self.input[o..o + n]);
                    }
                }
                self.stack.push(U256::from_big_endian(&word))?;
            }
            op::CALLDATASIZE => self.stack.push(U256::from(self.input.len()))?,
            op::CALLDATACOPY => {
                let (dest, offset, len) = self.stack.pop3()?;
                self.copy_cost(len)?;
                let d = self.memory.expand(&mut self.gas, dest, len)?;
                if !len.is_zero() {
                    self.memory
                        .set_data_padded(d, &self.input, offset, len.as_usize());
                }
            }
            op::CODESIZE => self.stack.push(U256::from(self.code.len()))?,
            op::CODECOPY => {
                let (dest, offset, len) = self.stack.pop3()?;
                self.copy_cost(len)?;
                let d = self.memory.expand(&mut self.gas, dest, len)?;
                if !len.is_zero() {
                    self.memory
                        .set_data_padded(d, self.code.bytes(), offset, len.as_usize());
                }
            }
            op::GASPRICE => {
                let price = host.env().tx.gas_price;
                self.stack.push(price)?;
            }
            op::EXTCODESIZE => {
                let a = u256_to_address(self.stack.pop()?);
                let r = host.code(a);
                self.gas.record(access_cost(r.cold))?;
                self.stack.push(U256::from(r.value.len()))?;
            }
            op::EXTCODECOPY => {
                let a = u256_to_address(self.stack.pop()?);
                let (dest, offset, len) = self.stack.pop3()?;
                let r = host.code(a);
                self.gas.record(access_cost(r.cold))?;
                self.copy_cost(len)?;
                let d = self.memory.expand(&mut self.gas, dest, len)?;
                if !len.is_zero() {
                    self.memory
                        .set_data_padded(d, r.value.bytes(), offset, len.as_usize());
                }
            }
            op::RETURNDATASIZE => self.stack.push(U256::from(self.return_data.len()))?,
            op::RETURNDATACOPY => {
                let (dest, offset, len) = self.stack.pop3()?;
                self.copy_cost(len)?;
                // EIP-211: unlike every other copy, reading past the end of
                // the return buffer is an exceptional halt, not padding.
                let end = offset.checked_add(len).ok_or(Halt::ReturnDataOutOfBounds)?;
                if end > U256::from(self.return_data.len()) {
                    return Err(Halt::ReturnDataOutOfBounds);
                }
                let d = self.memory.expand(&mut self.gas, dest, len)?;
                if !len.is_zero() {
                    let o = offset.as_usize();
                    // Borrow dance: memory and return_data are both fields.
                    let data = std::mem::take(&mut self.return_data);
                    self.memory.set(d, &data[o..o + len.as_usize()]);
                    self.return_data = data;
                }
            }
            op::EXTCODEHASH => {
                let a = u256_to_address(self.stack.pop()?);
                let r = host.code_hash(a);
                self.gas.record(access_cost(r.cold))?;
                self.stack.push(h256_to_u256(r.value))?;
            }

            // --- block ---
            op::BLOCKHASH => {
                let number = self.stack.pop()?;
                let hash = host.block_hash(number);
                self.stack.push(h256_to_u256(hash))?;
            }
            op::COINBASE => {
                let coinbase = host.env().block.coinbase;
                self.stack.push(address_to_u256(coinbase))?;
            }
            op::TIMESTAMP => {
                let t = host.env().block.timestamp;
                self.stack.push(t)?;
            }
            op::NUMBER => {
                let n = host.env().block.number;
                self.stack.push(n)?;
            }
            op::PREVRANDAO => {
                let r = host.env().block.prevrandao;
                self.stack.push(h256_to_u256(r))?;
            }
            op::GASLIMIT => {
                let l = host.env().block.gas_limit;
                self.stack.push(U256::from(l))?;
            }
            op::CHAINID => {
                let id = host.env().cfg.chain_id;
                self.stack.push(U256::from(id))?;
            }
            op::SELFBALANCE => {
                // Own address is warm by construction; the access result's
                // temperature is irrelevant here (static cost 5, EIP-1884).
                let balance = host.balance(self.address).value;
                self.stack.push(balance)?;
            }
            op::BASEFEE => {
                let fee = host.env().block.basefee;
                self.stack.push(fee)?;
            }
            op::BLOBHASH => {
                let index = self.stack.pop()?;
                let hash = as_usize_checked(index)
                    .and_then(|i| host.env().tx.blob_hashes.get(i).copied())
                    .unwrap_or_default();
                self.stack.push(h256_to_u256(hash))?;
            }
            op::BLOBBASEFEE => {
                let fee = host.env().block.blob_basefee;
                self.stack.push(fee)?;
            }

            // --- stack, memory, storage, flow ---
            op::POP => {
                self.stack.pop()?;
            }
            op::MLOAD => {
                let offset = self.stack.pop()?;
                let o = self.memory.expand(&mut self.gas, offset, U256::from(32))?;
                let word = self.memory.get_u256(o);
                self.stack.push(word)?;
            }
            op::MSTORE => {
                let (offset, value) = self.stack.pop2()?;
                let o = self.memory.expand(&mut self.gas, offset, U256::from(32))?;
                self.memory.set_u256(o, value);
            }
            op::MSTORE8 => {
                let (offset, value) = self.stack.pop2()?;
                let o = self.memory.expand(&mut self.gas, offset, U256::from(1))?;
                self.memory.set_byte(o, value.byte(0));
            }
            op::SLOAD => {
                let key = self.stack.pop()?;
                let r = host.sload(self.address, key);
                self.gas.record(if r.cold {
                    cost::COLD_SLOAD
                } else {
                    cost::WARM_ACCESS
                })?;
                self.stack.push(r.value)?;
            }
            op::SSTORE => {
                if self.is_static {
                    return Err(Halt::StaticViolation);
                }
                // EIP-2200 sentry: refuse outright at or below the call
                // stipend, so a 2300-gas transfer callback can never write.
                if self.gas.remaining() <= cost::SSTORE_SENTRY {
                    return Err(Halt::OutOfGas);
                }
                let (key, value) = self.stack.pop2()?;
                let r = host.sstore(self.address, key, value);
                let (fee, refund) = gas::sstore(r.original, r.current, value, r.cold);
                self.gas.record(fee)?;
                self.gas.record_refund(refund);
            }
            op::JUMP => {
                let dest = self.stack.pop()?;
                self.jump_to(dest)?;
            }
            op::JUMPI => {
                let (dest, condition) = self.stack.pop2()?;
                if !condition.is_zero() {
                    self.jump_to(dest)?;
                }
            }
            op::PC => self.stack.push(U256::from(pc))?,
            op::MSIZE => self.stack.push(U256::from(self.memory.len()))?,
            op::GAS => self.stack.push(U256::from(self.gas.remaining()))?,
            op::JUMPDEST => {}
            op::TLOAD => {
                let key = self.stack.pop()?;
                let value = host.tload(self.address, key);
                self.stack.push(value)?;
            }
            op::TSTORE => {
                // EIP-1153 defines TSTORE as state-modifying for EIP-214
                // purposes even though nothing persists past the tx.
                if self.is_static {
                    return Err(Halt::StaticViolation);
                }
                let (key, value) = self.stack.pop2()?;
                host.tstore(self.address, key, value);
            }
            op::MCOPY => {
                let (dest, src, len) = self.stack.pop3()?;
                self.copy_cost(len)?;
                let d = self.memory.expand(&mut self.gas, dest, len)?;
                let s = self.memory.expand(&mut self.gas, src, len)?;
                if !len.is_zero() {
                    self.memory.copy_within(d, s, len.as_usize());
                }
            }

            op::PUSH0 => self.stack.push(U256::zero())?,
            o if (op::PUSH1..=op::PUSH32).contains(&o) => {
                let n = op::push_size(o);
                let mut word = [0u8; 32];
                for (i, slot) in word[32 - n..].iter_mut().enumerate() {
                    // Immediates past the end of code read as zero.
                    *slot = self.code.bytes().get(pc + 1 + i).copied().unwrap_or(0);
                }
                self.pc = pc + 1 + n;
                self.stack.push(U256::from_big_endian(&word))?;
            }
            o if (op::DUP1..=op::DUP16).contains(&o) => {
                self.stack.dup((o - op::DUP1 + 1) as usize)?;
            }
            o if (op::SWAP1..=op::SWAP16).contains(&o) => {
                self.stack.swap((o - op::SWAP1 + 1) as usize)?;
            }

            o if (op::LOG0..=op::LOG4).contains(&o) => {
                if self.is_static {
                    return Err(Halt::StaticViolation);
                }
                let topic_count = (o - op::LOG0) as usize;
                let (offset, len) = self.stack.pop2()?;
                self.gas
                    .record(as_u64_saturated(len).saturating_mul(cost::LOG_DATA))?;
                self.gas.record(cost::LOG_TOPIC * topic_count as u64)?;
                let d = self.memory.expand(&mut self.gas, offset, len)?;
                let mut topics = Vec::with_capacity(topic_count);
                for _ in 0..topic_count {
                    topics.push(u256_to_h256(self.stack.pop()?));
                }
                let data = if len.is_zero() {
                    Vec::new()
                } else {
                    self.memory.slice(d, len.as_usize()).to_vec()
                };
                host.log(Log {
                    address: self.address,
                    topics,
                    data,
                });
            }

            // --- system ---
            op::CREATE => return self.do_create(false),
            op::CREATE2 => return self.do_create(true),
            op::CALL => return self.do_call(host, CallScheme::Call),
            op::CALLCODE => return self.do_call(host, CallScheme::CallCode),
            op::DELEGATECALL => return self.do_call(host, CallScheme::DelegateCall),
            op::STATICCALL => return self.do_call(host, CallScheme::StaticCall),
            op::RETURN => {
                let (offset, len) = self.stack.pop2()?;
                let output = self.read_region(offset, len)?;
                return Ok(Flow::Yield(Action::End(Outcome::Return(output))));
            }
            op::REVERT => {
                let (offset, len) = self.stack.pop2()?;
                let output = self.read_region(offset, len)?;
                return Ok(Flow::Yield(Action::End(Outcome::Revert(output))));
            }
            op::INVALID => return Err(Halt::InvalidOpcode(op::INVALID)),
            op::SELFDESTRUCT => {
                if self.is_static {
                    return Err(Halt::StaticViolation);
                }
                let beneficiary = u256_to_address(self.stack.pop()?);
                let r = host.selfdestruct(self.address, beneficiary);
                let mut extra = if r.cold { cost::COLD_ACCOUNT_ACCESS } else { 0 };
                if r.had_value && !r.target_exists {
                    extra += cost::SELFDESTRUCT_NEW_ACCOUNT;
                }
                self.gas.record(extra)?;
                return Ok(Flow::Yield(Action::End(Outcome::SelfDestruct)));
            }

            _ => return Err(Halt::InvalidOpcode(opcode)),
        }
        Ok(Flow::Continue)
    }

    // --- call / create operand marshalling ---

    fn do_call(&mut self, host: &mut dyn Host, scheme: CallScheme) -> Result<Flow, Halt> {
        let gas_request = self.stack.pop()?;
        let to = u256_to_address(self.stack.pop()?);
        let value = match scheme {
            CallScheme::Call | CallScheme::CallCode => self.stack.pop()?,
            CallScheme::DelegateCall | CallScheme::StaticCall => U256::zero(),
        };
        let (in_offset, in_len) = self.stack.pop2()?;
        let (out_offset, out_len) = self.stack.pop2()?;

        if scheme == CallScheme::Call && self.is_static && !value.is_zero() {
            return Err(Halt::StaticViolation);
        }

        // Both memory regions are expanded and paid for up front; the
        // output region must exist even if the child fails.
        let in_off = self.memory.expand(&mut self.gas, in_offset, in_len)?;
        let out_off = self.memory.expand(&mut self.gas, out_offset, out_len)?;
        let input = if in_len.is_zero() {
            Vec::new()
        } else {
            self.memory.slice(in_off, in_len.as_usize()).to_vec()
        };

        let cold = host.access_account(to);
        self.gas.record(access_cost(cold))?;

        let has_value = !value.is_zero();
        let mut extra = 0u64;
        if has_value && matches!(scheme, CallScheme::Call | CallScheme::CallCode) {
            extra += cost::CALL_VALUE;
        }
        if scheme == CallScheme::Call && has_value && host.is_account_dead(to) {
            extra += cost::NEW_ACCOUNT;
        }
        self.gas.record(extra)?;

        // EIP-150: cap the request at 63/64 of what remains after the
        // charges above, then hand the callee its stipend on top.
        let cap = gas::all_but_one_64th(self.gas.remaining());
        let forwarded = as_u64_saturated(gas_request).min(cap);
        self.gas.record(forwarded)?;
        let stipend = if has_value && matches!(scheme, CallScheme::Call | CallScheme::CallCode) {
            cost::CALL_STIPEND
        } else {
            0
        };

        let inputs = CallInputs {
            scheme,
            code_address: to,
            target: match scheme {
                CallScheme::Call | CallScheme::StaticCall => to,
                CallScheme::CallCode | CallScheme::DelegateCall => self.address,
            },
            caller: match scheme {
                CallScheme::DelegateCall => self.caller,
                _ => self.address,
            },
            value: match scheme {
                CallScheme::DelegateCall => self.value,
                _ => value,
            },
            transfers_value: scheme == CallScheme::Call && has_value,
            requires_balance: has_value
                && matches!(scheme, CallScheme::Call | CallScheme::CallCode),
            input,
            gas_limit: forwarded + stipend,
            is_static: self.is_static || scheme == CallScheme::StaticCall,
            return_offset: out_off,
            return_len: if out_len.is_zero() {
                0
            } else {
                out_len.as_usize()
            },
        };
        Ok(Flow::Yield(Action::Call(inputs)))
    }

    fn do_create(&mut self, is_create2: bool) -> Result<Flow, Halt> {
        if self.is_static {
            return Err(Halt::StaticViolation);
        }
        let value = self.stack.pop()?;
        let (offset, len) = self.stack.pop2()?;
        let salt = if is_create2 {
            Some(u256_to_h256(self.stack.pop()?))
        } else {
            None
        };

        let init_code = self.read_region(offset, len)?;
        // EIP-3860: oversized init code is exceptional, before any
        // per-word charge.
        if init_code.len() > cost::MAX_INITCODE_SIZE {
            return Err(Halt::InitCodeSizeLimit);
        }
        let words_cost = gas::word_cost(init_code.len() as u64, cost::INITCODE_WORD);
        self.gas.record(words_cost)?;
        if is_create2 {
            // The address derivation hashes the init code (EIP-1014).
            self.gas
                .record(gas::word_cost(init_code.len() as u64, cost::KECCAK256_WORD))?;
        }

        let gas_limit = gas::all_but_one_64th(self.gas.remaining());
        self.gas.record(gas_limit)?;

        Ok(Flow::Yield(Action::Create(CreateInputs {
            creator: self.address,
            value,
            init_code,
            salt,
            gas_limit,
        })))
    }

    // --- executor re-entry points ---

    /// Consume a finished call: write the output into the caller's return
    /// window (recorded by the executor when the call was made), refill
    /// gas, set the return buffer, push the status word.
    pub fn resume_call(&mut self, outcome: CallOutcome, return_offset: usize, return_len: usize) {
        let n = outcome.output.len().min(return_len);
        if n > 0 {
            self.memory.set(return_offset, &outcome.output[..n]);
        }
        self.gas.credit(outcome.gas_remaining);
        self.gas.record_refund(outcome.gas_refunded);
        self.return_data = outcome.output;
        // Push must succeed: the call popped at least 6 operands.
        self.stack
            .push(bool_word(outcome.success))
            .expect("stack has room after call");
    }

    pub fn resume_create(&mut self, outcome: CreateOutcome) {
        self.gas.credit(outcome.gas_remaining);
        self.gas.record_refund(outcome.gas_refunded);
        self.return_data = outcome.output;
        let word = match outcome.address {
            Some(a) => address_to_u256(a),
            None => U256::zero(),
        };
        self.stack.push(word).expect("stack has room after create");
    }

    // --- helpers ---

    #[inline]
    fn binop(&mut self, f: impl FnOnce(U256, U256) -> U256) -> Result<(), Halt> {
        let (a, b) = self.stack.pop2()?;
        self.stack.push(f(a, b))
    }

    /// Copy-family per-word charge, saturating on absurd lengths.
    #[inline]
    fn copy_cost(&mut self, len: U256) -> Result<(), Halt> {
        self.gas
            .record(gas::word_cost(as_u64_saturated(len), cost::COPY_WORD))
    }

    /// Expand and snapshot a memory region (RETURN/REVERT/CREATE payloads).
    fn read_region(&mut self, offset: U256, len: U256) -> Result<Vec<u8>, Halt> {
        let o = self.memory.expand(&mut self.gas, offset, len)?;
        Ok(if len.is_zero() {
            Vec::new()
        } else {
            self.memory.slice(o, len.as_usize()).to_vec()
        })
    }

    fn jump_to(&mut self, dest: U256) -> Result<(), Halt> {
        let dest = as_usize_checked(dest).ok_or(Halt::InvalidJump)?;
        if self.code.jump_table().is_valid(dest) {
            self.pc = dest;
            Ok(())
        } else {
            Err(Halt::InvalidJump)
        }
    }
}

#[inline]
fn bool_word(b: bool) -> U256 {
    if b {
        U256::one()
    } else {
        U256::zero()
    }
}

#[inline]
fn access_cost(cold: bool) -> u64 {
    if cold {
        cost::COLD_ACCOUNT_ACCESS
    } else {
        cost::WARM_ACCESS
    }
}

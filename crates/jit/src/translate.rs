//! Lowering EVM basic blocks to Cranelift IR.
//!
//! Two things dominate the shape of this module.
//!
//! **There is no 256-bit integer.** Cranelift stops at `I128`, so a stack word
//! is carried as four 64-bit limbs, least significant first — the layout
//! `uint` already gives `U256`, which is why a word crosses the ABI as a copy.
//! Addition and subtraction become explicit carry and borrow chains;
//! comparison becomes a fold from the low limb up, each higher limb overriding
//! the result below it unless the two limbs are equal. This is the price of
//! not depending on an LLVM toolchain, and it is paid here so that the rest of
//! the compiler can stay ordinary.
//!
//! **The stack lives in memory, addressed at static offsets.** Entry height is
//! a run-time value, so the block prologue computes one base pointer from it
//! and every access inside the block is that pointer plus a constant the
//! analysis already knows. Cranelift's alias analysis then keeps the hot words
//! in registers on its own. The alternative — keeping the whole stack in SSA
//! values — is only possible when entry height is static, which for a
//! `JUMPDEST` reachable from several call sites it is not.

use std::collections::HashMap;

use athanor::opcode as op;
use cranelift_codegen::ir::{
    condcodes::IntCC, types::I32, types::I64, AbiParam, InstBuilder, MemFlags, Value,
};
use cranelift_codegen::settings::Configurable;
use cranelift_codegen::{ir, settings, Context};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Variable};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{Linkage, Module};

use crate::analysis::{self, Instruction, Program, Terminator, STACK_LIMIT};
use crate::frame::{offset, status, LIMBS, WORD};

/// Anything that stops a program from being compiled.
#[derive(Debug)]
pub enum CompileError {
    /// The host CPU is not one Cranelift can target.
    UnsupportedHost(String),
    /// Cranelift rejected the generated IR or failed to lower it. Reaching
    /// this means a bug in this crate, not in the input bytecode.
    Codegen(String),
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompileError::UnsupportedHost(m) => write!(f, "unsupported host: {m}"),
            CompileError::Codegen(m) => write!(f, "code generation failed: {m}"),
        }
    }
}

impl std::error::Error for CompileError {}

/// A compiled program's entry point.
///
/// The pointer is owned by the [`Compiler`] that produced it and stays valid
/// for as long as that compiler lives, which is what the borrow encodes.
pub struct Compiled<'a> {
    entry: *const u8,
    _owner: std::marker::PhantomData<&'a Compiler>,
}

impl Compiled<'_> {
    pub fn entry(&self) -> *const u8 {
        self.entry
    }
}

/// Compiles EVM bytecode to native code and keeps it mapped.
pub struct Compiler {
    module: JITModule,
    ctx: Context,
    builder_ctx: FunctionBuilderContext,
    compiled: usize,
}

impl Compiler {
    pub fn new() -> Result<Self, CompileError> {
        let mut flags = settings::builder();
        // Speed, and no position-independent code: these functions are called
        // through a pointer we hold, never relocated or shared.
        for (name, value) in [("opt_level", "speed"), ("is_pic", "false")] {
            flags
                .set(name, value)
                .map_err(|e| CompileError::Codegen(e.to_string()))?;
        }
        let isa = cranelift_native::builder()
            .map_err(|e| CompileError::UnsupportedHost(e.to_string()))?
            .finish(settings::Flags::new(flags))
            .map_err(|e| CompileError::Codegen(e.to_string()))?;
        let module = JITModule::new(JITBuilder::with_isa(
            isa,
            cranelift_module::default_libcall_names(),
        ));
        Ok(Self {
            ctx: module.make_context(),
            builder_ctx: FunctionBuilderContext::new(),
            module,
            compiled: 0,
        })
    }

    /// Compile `code` into a native function.
    pub fn compile(&mut self, code: &[u8]) -> Result<Compiled<'_>, CompileError> {
        let program = analysis::analyse(code);
        let ptr_type = self.module.target_config().pointer_type();

        self.ctx.func.signature.params.push(AbiParam::new(ptr_type));
        self.ctx.func.signature.returns.push(AbiParam::new(I32));

        {
            let mut builder = FunctionBuilder::new(&mut self.ctx.func, &mut self.builder_ctx);
            Translator::new(&mut builder, ptr_type).emit(&program);
            builder.finalize();
        }

        // Names only have to be distinct; nothing resolves them by symbol.
        self.compiled += 1;
        let name = format!("evm_{}", self.compiled);
        let id = self
            .module
            .declare_function(&name, Linkage::Export, &self.ctx.func.signature)
            .map_err(|e| CompileError::Codegen(e.to_string()))?;
        self.module
            .define_function(id, &mut self.ctx)
            .map_err(|e| CompileError::Codegen(e.to_string()))?;
        self.module.clear_context(&mut self.ctx);
        self.module
            .finalize_definitions()
            .map_err(|e| CompileError::Codegen(e.to_string()))?;

        Ok(Compiled {
            entry: self.module.get_finalized_function(id),
            _owner: std::marker::PhantomData,
        })
    }
}

/// Cranelift variables. Only the two that change across blocks need to be
/// variables at all; the frame and stack pointers are loop invariants that
/// Cranelift's SSA construction will keep in registers regardless.
fn v_frame() -> Variable {
    Variable::from_u32(0)
}
fn v_base() -> Variable {
    Variable::from_u32(1)
}
fn v_len() -> Variable {
    Variable::from_u32(2)
}
fn v_gas() -> Variable {
    Variable::from_u32(3)
}

struct Translator<'a, 'b> {
    b: &'a mut FunctionBuilder<'b>,
    ptr_type: ir::Type,
    /// Where each EVM block begins, as a Cranelift block.
    blocks: HashMap<usize, ir::Block>,
    /// Shared landing pads, so the epilogue is emitted once per status word
    /// rather than once per site.
    halt: HashMap<i32, ir::Block>,
}

impl<'a, 'b> Translator<'a, 'b> {
    fn new(b: &'a mut FunctionBuilder<'b>, ptr_type: ir::Type) -> Self {
        Self {
            b,
            ptr_type,
            blocks: HashMap::new(),
            halt: HashMap::new(),
        }
    }

    fn emit(mut self, program: &Program) {
        let entry = self.b.create_block();
        self.b.append_block_params_for_function_params(entry);
        self.b.switch_to_block(entry);

        self.b.declare_var(v_frame(), self.ptr_type);
        self.b.declare_var(v_base(), self.ptr_type);
        self.b.declare_var(v_len(), I64);
        self.b.declare_var(v_gas(), I64);

        let frame = self.b.block_params(entry)[0];
        self.b.def_var(v_frame(), frame);
        let trusted = MemFlags::trusted();
        let base = self
            .b
            .ins()
            .load(self.ptr_type, trusted, frame, offset::STACK);
        self.b.def_var(v_base(), base);
        let len = self.b.ins().load(I64, trusted, frame, offset::LEN);
        self.b.def_var(v_len(), len);
        let gas = self.b.ins().load(I64, trusted, frame, offset::GAS);
        self.b.def_var(v_gas(), gas);

        for block in &program.blocks {
            let cl = self.b.create_block();
            self.blocks.insert(block.start, cl);
        }

        // Empty code, or code that is nothing but data, halts immediately.
        match program.blocks.first() {
            Some(first) => {
                let target = self.blocks[&first.start];
                self.b.ins().jump(target, &[]);
            }
            None => self.exit(status::STOP, 0),
        }
        self.emit_halt_pads();

        // A single dispatcher serves every JUMP and JUMPI. Sites hand it the
        // low limb of the destination; it either lands on a JUMPDEST block or
        // falls into the invalid-jump pad.
        let dispatch = self.b.create_block();
        self.b.append_block_param(dispatch, I64);

        for block in &program.blocks {
            self.emit_block(block, dispatch);
        }

        self.b.switch_to_block(dispatch);
        let target = self.b.block_params(dispatch)[0];
        let table: Vec<(u64, ir::Block)> = program
            .jumpdests
            .iter()
            .map(|&pc| (pc as u64, self.blocks[&pc]))
            .collect();
        let invalid = self.halt_block(status::INVALID_JUMP);
        emit_jump_search(self.b, &table, target, invalid);

        self.b.seal_all_blocks();
    }

    /// Prologue, body, epilogue and terminator of one EVM block.
    fn emit_block(&mut self, block: &analysis::Block, dispatch: ir::Block) {
        let cl = self.blocks[&block.start];
        self.b.switch_to_block(cl);

        let len = self.b.use_var(v_len());

        // The three checks the analysis proved could be hoisted. Each guards
        // the whole block, which is sound only because every instruction in
        // the block is known to execute — see the module docs in `analysis`.
        //
        // Gas goes first because that is the order the Yellow Paper deducts
        // in: a cost is taken before the instruction runs, so an instruction
        // that is both unaffordable and underfed reports running out of gas.
        // Hoisting cannot reproduce that ordering in every case — a block
        // whose first instruction is affordable but whose total is not will
        // reach out-of-gas where stepping would have underflowed first — but
        // the two are the same exceptional halt to consensus, forfeiting the
        // frame's gas and changing no state either way.
        if block.gas > 0 {
            let gas = self.b.use_var(v_gas());
            let cost = self.b.ins().iconst(I64, block.gas as i64);
            let short = self.b.ins().icmp(IntCC::UnsignedLessThan, gas, cost);
            self.guard(short, status::OUT_OF_GAS);
            let left = self.b.ins().isub(gas, cost);
            self.b.def_var(v_gas(), left);
        }
        if block.min_height > 0 {
            let need = self.b.ins().iconst(I64, block.min_height as i64);
            let short = self.b.ins().icmp(IntCC::UnsignedLessThan, len, need);
            self.guard(short, status::STACK_UNDERFLOW);
        }
        if block.max_growth > 0 {
            let growth = self.b.ins().iconst(I64, block.max_growth);
            let peak = self.b.ins().iadd(len, growth);
            let limit = self.b.ins().iconst(I64, STACK_LIMIT as i64);
            let over = self.b.ins().icmp(IntCC::UnsignedGreaterThan, peak, limit);
            self.guard(over, status::STACK_OVERFLOW);
        }

        // One address computation for the whole block: everything below is a
        // constant displacement from here.
        let scale = self.b.ins().iconst(I64, WORD as i64);
        let bytes = self.b.ins().imul(len, scale);
        let base = self.b.use_var(v_base());
        let top = self.b.ins().iadd(base, bytes);

        let mut delta = 0i64;
        let mut jump_operands = None;
        for ins in &block.instructions {
            if matches!(ins.op, op::JUMP | op::JUMPI) {
                jump_operands = Some(self.read_jump_operands(top, delta, ins.op));
            } else {
                self.emit_instruction(ins, top, delta);
            }
            delta += analysis::growth(ins.op);
        }

        // Height moves once, on the way out.
        if block.net_growth != 0 {
            let shift = self.b.ins().iconst(I64, block.net_growth);
            let updated = self.b.ins().iadd(len, shift);
            self.b.def_var(v_len(), updated);
        }

        match block.terminator {
            Terminator::Stop => self.exit(status::STOP, block.start),
            Terminator::Bail { pc } => self.exit(status::BAILOUT, pc),
            Terminator::Fallthrough(pc) => {
                let target = self.blocks[&pc];
                self.b.ins().jump(target, &[]);
            }
            Terminator::Jump => {
                let (dest, _) = jump_operands.expect("JUMP terminator without operands");
                self.branch_to_dispatch(dest, dispatch);
            }
            Terminator::JumpI { fallthrough } => {
                let (dest, cond) = jump_operands.expect("JUMPI terminator without operands");
                let cond = cond.expect("JUMPI without a condition");
                let taken = self.b.create_block();
                let skipped = self.blocks[&fallthrough];
                let is_set = self.is_nonzero(cond);
                self.b.ins().brif(is_set, taken, &[], skipped, &[]);
                self.b.switch_to_block(taken);
                self.branch_to_dispatch(dest, dispatch);
            }
        }
    }

    /// Read a jump's operands while they are still on the stack, before the
    /// block's height update moves the top.
    #[allow(clippy::type_complexity)]
    fn read_jump_operands(
        &mut self,
        top: Value,
        delta: i64,
        opcode: u8,
    ) -> ([Value; LIMBS], Option<[Value; LIMBS]>) {
        let dest = self.load_word(top, slot(delta, 0));
        let cond = if opcode == op::JUMPI {
            Some(self.load_word(top, slot(delta, 1)))
        } else {
            None
        };
        (dest, cond)
    }

    /// A destination is only reachable if it fits in 64 bits; anything wider
    /// cannot be a code offset, so it goes straight to the invalid pad.
    fn branch_to_dispatch(&mut self, dest: [Value; LIMBS], dispatch: ir::Block) {
        let high = self.b.ins().bor(dest[1], dest[2]);
        let high = self.b.ins().bor(high, dest[3]);
        let zero = self.b.ins().iconst(I64, 0);
        let fits = self.b.ins().icmp(IntCC::Equal, high, zero);
        let invalid = self.halt_block(status::INVALID_JUMP);
        self.b.ins().brif(fits, dispatch, &[dest[0]], invalid, &[]);
    }

    fn emit_instruction(&mut self, ins: &Instruction, top: Value, delta: i64) {
        match ins.op {
            op::STOP | op::JUMPDEST | op::POP => {}
            op::PUSH0 | op::PUSH1..=op::PUSH32 => {
                let value = ins.push.expect("push instruction without an immediate");
                let limbs = [
                    self.b.ins().iconst(I64, value.0[0] as i64),
                    self.b.ins().iconst(I64, value.0[1] as i64),
                    self.b.ins().iconst(I64, value.0[2] as i64),
                    self.b.ins().iconst(I64, value.0[3] as i64),
                ];
                self.store_word(top, push_slot(delta), limbs);
            }
            op::DUP1..=op::DUP16 => {
                let depth = (ins.op - op::DUP1) as i64;
                let word = self.load_word(top, slot(delta, depth));
                self.store_word(top, push_slot(delta), word);
            }
            op::SWAP1..=op::SWAP16 => {
                let depth = (ins.op - op::SWAP1) as i64 + 1;
                let a = self.load_word(top, slot(delta, 0));
                let b = self.load_word(top, slot(delta, depth));
                self.store_word(top, slot(delta, 0), b);
                self.store_word(top, slot(delta, depth), a);
            }
            op::ISZERO | op::NOT => {
                let a = self.load_word(top, slot(delta, 0));
                let result = match ins.op {
                    op::ISZERO => {
                        let flag = self.is_zero(a);
                        self.widen_flag(flag)
                    }
                    _ => [
                        self.b.ins().bnot(a[0]),
                        self.b.ins().bnot(a[1]),
                        self.b.ins().bnot(a[2]),
                        self.b.ins().bnot(a[3]),
                    ],
                };
                self.store_word(top, slot(delta, 0), result);
            }
            _ => {
                // The remaining compiled opcodes are binary: the second
                // operand sits one deeper, and the result replaces it.
                let a = self.load_word(top, slot(delta, 0));
                let b = self.load_word(top, slot(delta, 1));
                let result = self.binary(ins.op, a, b);
                self.store_word(top, slot(delta, 1), result);
            }
        }
    }

    fn binary(&mut self, opcode: u8, a: [Value; LIMBS], b: [Value; LIMBS]) -> [Value; LIMBS] {
        match opcode {
            op::ADD => self.add(a, b),
            op::SUB => self.sub(a, b),
            op::AND => self.bitwise(a, b, |bb, x, y| bb.ins().band(x, y)),
            op::OR => self.bitwise(a, b, |bb, x, y| bb.ins().bor(x, y)),
            op::XOR => self.bitwise(a, b, |bb, x, y| bb.ins().bxor(x, y)),
            op::EQ => {
                let flag = self.equal(a, b);
                self.widen_flag(flag)
            }
            op::LT => {
                let flag = self.less_than(a, b);
                self.widen_flag(flag)
            }
            op::GT => {
                // Strictly greater is the same relation with the operands
                // swapped, so one comparison routine serves both.
                let flag = self.less_than(b, a);
                self.widen_flag(flag)
            }
            other => unreachable!("opcode {other:#04x} reached the translator without a lowering"),
        }
    }

    /// 256-bit addition as a carry chain. Each limb can carry for two
    /// independent reasons — the operands themselves overflowing, and the
    /// incoming carry pushing the sum over — and either one sets the carry
    /// out. The two cannot both fire, since a sum that wrapped is at most
    /// `u64::MAX - 1` before the carry is folded in.
    fn add(&mut self, a: [Value; LIMBS], b: [Value; LIMBS]) -> [Value; LIMBS] {
        let mut out = [a[0]; LIMBS];
        let mut carry: Option<Value> = None;
        for i in 0..LIMBS {
            let partial = self.b.ins().iadd(a[i], b[i]);
            let wrapped = self.b.ins().icmp(IntCC::UnsignedLessThan, partial, a[i]);
            let (sum, wrapped_again) = match carry {
                None => (partial, None),
                Some(c) => {
                    let sum = self.b.ins().iadd(partial, c);
                    let again = self.b.ins().icmp(IntCC::UnsignedLessThan, sum, c);
                    (sum, Some(again))
                }
            };
            out[i] = sum;
            if i + 1 < LIMBS {
                let carried = match wrapped_again {
                    None => wrapped,
                    Some(again) => self.b.ins().bor(wrapped, again),
                };
                carry = Some(self.b.ins().uextend(I64, carried));
            }
        }
        out
    }

    /// 256-bit subtraction as a borrow chain, mirroring [`Translator::add`].
    fn sub(&mut self, a: [Value; LIMBS], b: [Value; LIMBS]) -> [Value; LIMBS] {
        let mut out = [a[0]; LIMBS];
        let mut borrow: Option<Value> = None;
        for i in 0..LIMBS {
            let partial = self.b.ins().isub(a[i], b[i]);
            let under = self.b.ins().icmp(IntCC::UnsignedLessThan, a[i], b[i]);
            let (diff, under_again) = match borrow {
                None => (partial, None),
                Some(br) => {
                    let diff = self.b.ins().isub(partial, br);
                    let again = self.b.ins().icmp(IntCC::UnsignedLessThan, partial, br);
                    (diff, Some(again))
                }
            };
            out[i] = diff;
            if i + 1 < LIMBS {
                let borrowed = match under_again {
                    None => under,
                    Some(again) => self.b.ins().bor(under, again),
                };
                borrow = Some(self.b.ins().uextend(I64, borrowed));
            }
        }
        out
    }

    fn bitwise(
        &mut self,
        a: [Value; LIMBS],
        b: [Value; LIMBS],
        mut f: impl FnMut(&mut FunctionBuilder<'b>, Value, Value) -> Value,
    ) -> [Value; LIMBS] {
        let mut out = [a[0]; LIMBS];
        for (slot, (x, y)) in out.iter_mut().zip(a.iter().zip(b.iter())) {
            *slot = f(self.b, *x, *y);
        }
        out
    }

    /// Unsigned 256-bit `<`, folded from the low limb upward: a higher limb
    /// decides the comparison outright unless it ties, in which case the
    /// result accumulated from below stands.
    fn less_than(&mut self, a: [Value; LIMBS], b: [Value; LIMBS]) -> Value {
        let mut result = self.b.ins().icmp(IntCC::UnsignedLessThan, a[0], b[0]);
        for (x, y) in a.iter().zip(b.iter()).skip(1) {
            let here = self.b.ins().icmp(IntCC::UnsignedLessThan, *x, *y);
            let tie = self.b.ins().icmp(IntCC::Equal, *x, *y);
            result = self.b.ins().select(tie, result, here);
        }
        result
    }

    fn equal(&mut self, a: [Value; LIMBS], b: [Value; LIMBS]) -> Value {
        let mut result = self.b.ins().icmp(IntCC::Equal, a[0], b[0]);
        for (x, y) in a.iter().zip(b.iter()).skip(1) {
            let here = self.b.ins().icmp(IntCC::Equal, *x, *y);
            result = self.b.ins().band(result, here);
        }
        result
    }

    fn is_zero(&mut self, a: [Value; LIMBS]) -> Value {
        let mut folded = self.b.ins().bor(a[0], a[1]);
        folded = self.b.ins().bor(folded, a[2]);
        folded = self.b.ins().bor(folded, a[3]);
        let zero = self.b.ins().iconst(I64, 0);
        self.b.ins().icmp(IntCC::Equal, folded, zero)
    }

    fn is_nonzero(&mut self, a: [Value; LIMBS]) -> Value {
        let mut folded = self.b.ins().bor(a[0], a[1]);
        folded = self.b.ins().bor(folded, a[2]);
        folded = self.b.ins().bor(folded, a[3]);
        folded
    }

    /// Widen a comparison flag into a stack word holding 0 or 1.
    fn widen_flag(&mut self, flag: Value) -> [Value; LIMBS] {
        let low = self.b.ins().uextend(I64, flag);
        let zero = self.b.ins().iconst(I64, 0);
        [low, zero, zero, zero]
    }

    fn load_word(&mut self, top: Value, byte_offset: i32) -> [Value; LIMBS] {
        let flags = MemFlags::trusted();
        let mut out = [top; LIMBS];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = self
                .b
                .ins()
                .load(I64, flags, top, byte_offset + (i * 8) as i32);
        }
        out
    }

    fn store_word(&mut self, top: Value, byte_offset: i32, word: [Value; LIMBS]) {
        let flags = MemFlags::trusted();
        for (i, limb) in word.iter().enumerate() {
            self.b
                .ins()
                .store(flags, *limb, top, byte_offset + (i * 8) as i32);
        }
    }

    /// Branch to a halt pad when `condition` holds, and carry on otherwise.
    fn guard(&mut self, condition: Value, code: i32) {
        let pad = self.halt_block(code);
        let carry_on = self.b.create_block();
        self.b.ins().brif(condition, pad, &[], carry_on, &[]);
        self.b.switch_to_block(carry_on);
    }

    /// Emit one landing pad per exceptional status.
    ///
    /// They are built here, in one pass, rather than on first use: Cranelift
    /// requires the block being left to be terminated already, so a pad
    /// created halfway through translating some other block would abandon it
    /// unfinished. Sharing pads also keeps the generated code compact —
    /// exceptional halts are indistinguishable from the frame's point of view,
    /// since the gas is gone and the stack no longer matters.
    fn emit_halt_pads(&mut self) {
        for code in [
            status::OUT_OF_GAS,
            status::STACK_UNDERFLOW,
            status::STACK_OVERFLOW,
            status::INVALID_JUMP,
        ] {
            let pad = self.b.create_block();
            self.b.switch_to_block(pad);
            let frame = self.b.use_var(v_frame());
            let flags = MemFlags::trusted();
            let zero = self.b.ins().iconst(I64, 0);
            // An exceptional halt forfeits the frame's gas (YP 9.4.2).
            // Writing it here keeps that invariant in a single place.
            self.b.ins().store(flags, zero, frame, offset::GAS);
            let status_value = self.b.ins().iconst(I32, code as i64);
            self.b.ins().return_(&[status_value]);
            self.halt.insert(code, pad);
        }
    }

    fn halt_block(&mut self, code: i32) -> ir::Block {
        self.halt[&code]
    }

    /// Write the live state back and return `code`. Used for the paths where
    /// the frame's stack and gas survive: a clean stop, and a bailout.
    fn exit(&mut self, code: i32, pc: usize) {
        let frame = self.b.use_var(v_frame());
        let flags = MemFlags::trusted();
        let len = self.b.use_var(v_len());
        self.b.ins().store(flags, len, frame, offset::LEN);
        let gas = self.b.use_var(v_gas());
        self.b.ins().store(flags, gas, frame, offset::GAS);
        let pc_value = self.b.ins().iconst(I64, pc as i64);
        self.b.ins().store(flags, pc_value, frame, offset::PC);
        let status_value = self.b.ins().iconst(I32, code as i64);
        self.b.ins().return_(&[status_value]);
    }
}

/// Byte displacement of the word `depth` below the top, given the block's
/// current height offset.
fn slot(delta: i64, depth: i64) -> i32 {
    ((delta - 1 - depth) * WORD as i64) as i32
}

/// Byte displacement of the word a push is about to occupy.
fn push_slot(delta: i64) -> i32 {
    (delta * WORD as i64) as i32
}

/// Binary search over the valid jump destinations, emitted as branches.
///
/// A linear chain would be simpler, but jump-heavy contracts have hundreds of
/// `JUMPDEST`s and every dynamic jump would then walk them all. This costs
/// `log2(n)` compares instead, which is the whole reason to know the
/// destination set at compile time.
fn emit_jump_search(
    b: &mut FunctionBuilder,
    targets: &[(u64, ir::Block)],
    value: Value,
    invalid: ir::Block,
) {
    let Some((pivot_pc, pivot_block)) = targets.get(targets.len() / 2).copied() else {
        b.ins().jump(invalid, &[]);
        return;
    };
    let mid = targets.len() / 2;

    let key = b.ins().iconst(I64, pivot_pc as i64);
    let hit = b.ins().icmp(IntCC::Equal, value, key);
    let miss = b.create_block();
    b.ins().brif(hit, pivot_block, &[], miss, &[]);
    b.switch_to_block(miss);

    if targets.len() == 1 {
        b.ins().jump(invalid, &[]);
        return;
    }

    let lower = b.create_block();
    let upper = b.create_block();
    let below = b.ins().icmp(IntCC::UnsignedLessThan, value, key);
    b.ins().brif(below, lower, &[], upper, &[]);

    b.switch_to_block(lower);
    emit_jump_search(b, &targets[..mid], value, invalid);
    b.switch_to_block(upper);
    emit_jump_search(b, &targets[mid + 1..], value, invalid);
}

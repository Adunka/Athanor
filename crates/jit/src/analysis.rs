//! Splitting bytecode into basic blocks and proving what each one needs.
//!
//! Everything the code generator is allowed to hoist out of a block rests on
//! one property established here: **every instruction in a block runs, or none
//! of them do.** A block therefore ends at the first opcode the translator
//! cannot compile, not merely at the first jump. That is stricter than the
//! usual definition of a basic block, and it is what makes the prologue sound.
//!
//! Given that property, three per-instruction checks collapse into three
//! per-block ones:
//!
//! * **Gas.** The static costs of the whole block are charged up front. Should
//!   the block turn out to be unaffordable, the frame halts exceptionally and
//!   forfeits all its gas anyway (YP 9.4.2), so charging early cannot be
//!   observed. On the bailout path the interpreter resumes with exactly the
//!   gas left after the instructions that actually ran — the block stopped at
//!   the unsupported opcode, so no unspent remainder is owed back.
//! * **Underflow.** Each instruction's depth requirement is expressed relative
//!   to the entry height and the deepest one wins, giving a single
//!   `len >= min_height` test.
//! * **Overflow.** Likewise, the tallest point the block reaches gives a
//!   single `len + max_growth <= 1024` test.
//!
//! Entry height is *not* a static property — a `JUMPDEST` can be reached from
//! call sites with different stack depths — so both bounds stay relative and
//! are checked against the live height at run time.

use athanor::opcode as op;
use athanor::U256;

/// The stack limit from the Yellow Paper; exceeding it is an exceptional halt.
pub const STACK_LIMIT: u64 = 1024;

/// One instruction the translator will emit code for.
#[derive(Debug, Clone)]
pub struct Instruction {
    pub pc: usize,
    pub op: u8,
    /// Immediate operand of a `PUSH`, already widened to a stack word.
    pub push: Option<U256>,
}

/// How control leaves a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terminator {
    /// `STOP`: the frame ends successfully with no output.
    Stop,
    /// `JUMP`: the destination is on the stack and only known at run time.
    Jump,
    /// `JUMPI`: dynamic destination, or `fallthrough` when the condition is
    /// zero.
    JumpI { fallthrough: usize },
    /// The block ran into a `JUMPDEST`, which always starts a block of its own.
    Fallthrough(usize),
    /// An opcode outside the compiled subset. The frame's live state is
    /// written back and the interpreter takes over from `pc`.
    Bail { pc: usize },
}

/// A straight-line run of compilable instructions plus the bounds its
/// prologue has to check.
#[derive(Debug, Clone)]
pub struct Block {
    pub start: usize,
    pub instructions: Vec<Instruction>,
    pub terminator: Terminator,
    /// Sum of the static costs of `instructions` and, where it has one, the
    /// terminator.
    pub gas: u64,
    /// Entry height the block needs to avoid underflow.
    pub min_height: u64,
    /// Tallest point reached relative to entry; negative if the block only
    /// ever consumes.
    pub max_growth: i64,
    /// Height change from entry to exit, applied once on the way out.
    pub net_growth: i64,
}

/// The program carved into blocks, indexed by the program counter each one
/// starts at.
#[derive(Debug)]
pub struct Program {
    pub blocks: Vec<Block>,
    /// `JUMPDEST` offsets in ascending order — the only legal jump targets,
    /// and the search space the dynamic-jump dispatcher is built from.
    pub jumpdests: Vec<usize>,
}

impl Program {
    pub fn block_at(&self, pc: usize) -> Option<&Block> {
        self.blocks.iter().find(|b| b.start == pc)
    }
}

/// Stack effect of an opcode in the compiled subset: how deep it reads, and
/// how the height changes.
///
/// `reads` is a depth requirement rather than a pop count, which is what
/// `DUP`/`SWAP` need — `DUP3` removes nothing but is still invalid on a stack
/// of two.
struct Effect {
    reads: u64,
    growth: i64,
}

fn effect(opcode: u8) -> Option<Effect> {
    let e = |reads, growth| Some(Effect { reads, growth });
    match opcode {
        op::STOP => e(0, 0),
        // Binary arithmetic, comparison and bitwise ops: two operands in, one
        // result out.
        op::ADD | op::SUB | op::LT | op::GT | op::EQ | op::AND | op::OR | op::XOR => e(2, -1),
        // Unary.
        op::ISZERO | op::NOT => e(1, 0),
        op::POP => e(1, -1),
        op::JUMPDEST => e(0, 0),
        op::PUSH0 => e(0, 1),
        op::PUSH1..=op::PUSH32 => e(0, 1),
        op::DUP1..=op::DUP16 => e((opcode - op::DUP1) as u64 + 1, 1),
        op::SWAP1..=op::SWAP16 => e((opcode - op::SWAP1) as u64 + 2, 0),
        op::JUMP => e(1, -1),
        op::JUMPI => e(2, -2),
        _ => None,
    }
}

/// Height change an opcode causes, or zero if it is not compiled.
///
/// The translator walks the same deltas these bounds were derived from, so it
/// reads them from here rather than keeping a second table: two tables obliged
/// to agree is one table too many.
pub fn growth(opcode: u8) -> i64 {
    match effect(opcode) {
        Some(e) => e.growth,
        None => 0,
    }
}

/// Whether an opcode ends its block by transferring control.
fn is_terminator(opcode: u8) -> bool {
    matches!(opcode, op::STOP | op::JUMP | op::JUMPI)
}

/// Decode `code` into blocks.
///
/// The scan is linear and skips `PUSH` immediates, so bytes that merely look
/// like `JUMPDEST` inside push data are never mistaken for one — the same
/// reason the interpreter builds its jump table by decoding rather than by
/// searching.
pub fn analyse(code: &[u8]) -> Program {
    let mut blocks = Vec::new();
    let mut jumpdests = Vec::new();

    let mut pc = 0;
    while pc < code.len() {
        let (block, next) = scan_block(code, pc);
        for ins in &block.instructions {
            if ins.op == op::JUMPDEST {
                jumpdests.push(ins.pc);
            }
        }
        blocks.push(block);
        pc = next;
    }

    jumpdests.sort_unstable();
    Program { blocks, jumpdests }
}

/// Scan one block starting at `start`, returning it and the offset where the
/// next block begins.
fn scan_block(code: &[u8], start: usize) -> (Block, usize) {
    let mut instructions = Vec::new();
    let mut gas = 0u64;
    let mut min_height = 0i64;
    let mut max_growth = 0i64;
    let mut delta = 0i64;

    let mut pc = start;
    let terminator = loop {
        if pc >= code.len() {
            // Running off the end of the code is an implicit STOP (YP 9.4.1).
            break Terminator::Stop;
        }
        let opcode = code[pc];

        // A JUMPDEST opens a block, so seeing one after the first instruction
        // closes the current block and leaves the JUMPDEST to the next.
        if opcode == op::JUMPDEST && pc != start {
            break Terminator::Fallthrough(pc);
        }

        let Some(eff) = effect(opcode) else {
            break Terminator::Bail { pc };
        };

        // Depth is demanded before the instruction's own effect applies, so
        // the requirement is measured against the height on the way in.
        min_height = min_height.max(eff.reads as i64 - delta);
        delta += eff.growth;
        max_growth = max_growth.max(delta);
        gas += op::STATIC_GAS[opcode as usize] as u64;

        let push = if (op::PUSH1..=op::PUSH32).contains(&opcode) {
            let n = (opcode - op::PUSH1) as usize + 1;
            // Immediates that run past the end of the code are zero-extended
            // on the right, matching how the interpreter reads them.
            let mut buf = [0u8; 32];
            let available = code.len().saturating_sub(pc + 1).min(n);
            buf[32 - n..32 - n + available].copy_from_slice(&code[pc + 1..pc + 1 + available]);
            Some(U256::from_big_endian(&buf))
        } else if opcode == op::PUSH0 {
            Some(U256::zero())
        } else {
            None
        };

        instructions.push(Instruction {
            pc,
            op: opcode,
            push,
        });

        let width = if (op::PUSH1..=op::PUSH32).contains(&opcode) {
            1 + (opcode - op::PUSH1) as usize + 1
        } else {
            1
        };
        pc += width;

        if is_terminator(opcode) {
            break match opcode {
                op::STOP => Terminator::Stop,
                op::JUMP => Terminator::Jump,
                _ => Terminator::JumpI { fallthrough: pc },
            };
        }
    };

    // The bailing instruction is not part of the block, so the next scan must
    // start on it rather than after it.
    let next = match terminator {
        Terminator::Bail { pc } => pc.max(start + 1),
        Terminator::Fallthrough(at) => at,
        _ => pc,
    };

    let block = Block {
        start,
        instructions,
        terminator,
        gas,
        min_height: min_height.max(0) as u64,
        max_growth,
        net_growth: delta,
    };
    (block, next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_immediates_are_not_decoded_as_opcodes() {
        // PUSH2 0x5b5b — the operand bytes spell JUMPDEST but are data.
        let program = analyse(&[0x61, 0x5b, 0x5b, op::STOP]);
        assert!(program.jumpdests.is_empty());
        assert_eq!(program.blocks.len(), 1);
        assert_eq!(program.blocks[0].instructions.len(), 2);
    }

    #[test]
    fn truncated_push_is_zero_extended() {
        // PUSH4 with only two bytes left: 0x0102 becomes 0x01020000.
        let program = analyse(&[0x63, 0x01, 0x02]);
        let imm = program.blocks[0].instructions[0].push.unwrap();
        assert_eq!(imm, U256::from(0x0102_0000u64));
    }

    #[test]
    fn jumpdest_opens_a_block() {
        // PUSH1 1, JUMPDEST, POP
        let program = analyse(&[0x60, 0x01, op::JUMPDEST, op::POP]);
        assert_eq!(program.blocks.len(), 2);
        assert_eq!(program.blocks[0].terminator, Terminator::Fallthrough(2));
        assert_eq!(program.blocks[1].start, 2);
        assert_eq!(program.jumpdests, vec![2]);
    }

    #[test]
    fn unsupported_opcode_ends_the_block_without_consuming_it() {
        // PUSH1 1, SSTORE — SSTORE is outside the subset.
        let program = analyse(&[0x60, 0x01, 0x55]);
        let first = &program.blocks[0];
        assert_eq!(first.terminator, Terminator::Bail { pc: 2 });
        assert_eq!(first.instructions.len(), 1);
        // Its gas must not have been billed to the block: the interpreter will
        // charge it when it takes over.
        assert_eq!(first.gas, op::STATIC_GAS[0x60] as u64);
    }

    #[test]
    fn depth_requirement_accounts_for_dup_reach() {
        // DUP3 on an empty relative stack needs three words below it.
        let program = analyse(&[0x82, op::STOP]);
        assert_eq!(program.blocks[0].min_height, 3);
        assert_eq!(program.blocks[0].max_growth, 1);
    }

    #[test]
    fn bounds_track_the_deepest_and_tallest_points() {
        // ADD ADD: the first needs two words, and after it consumes one the
        // second needs one more still below the entry height.
        let program = analyse(&[op::ADD, op::ADD, op::STOP]);
        let b = &program.blocks[0];
        assert_eq!(b.min_height, 3);
        assert_eq!(b.net_growth, -2);
        assert_eq!(b.gas, 3 + 3);
    }

    #[test]
    fn running_off_the_end_stops() {
        let program = analyse(&[op::ADD]);
        assert_eq!(program.blocks[0].terminator, Terminator::Stop);
    }
}

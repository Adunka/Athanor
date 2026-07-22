//! The boundary between compiled code and Rust.
//!
//! Compiled functions take one argument, a pointer to [`Frame`], and return a
//! status word. Everything the two sides share passes through that struct, so
//! its layout is load-bearing: `translate` emits loads and stores against the
//! byte offsets in [`offset`], and they have to agree with what the Rust
//! compiler lays out here. `repr(C)` is what makes that agreement stable, and
//! a test at the bottom of this file checks the offsets rather than trusting
//! them.
//!
//! The stack lives in a flat array of 64-bit limbs, four to a word, least
//! significant first — the representation `uint`'s `U256` already uses
//! internally, so moving a word across the boundary is a copy and not a
//! conversion.

use athanor::U256;

/// Words a frame's stack can hold (YP 9.4.2).
pub const STACK_LIMIT: usize = 1024;

/// Limbs per stack word.
pub const LIMBS: usize = 4;

/// Bytes per stack word.
pub const WORD: i32 = (LIMBS * 8) as i32;

/// State shared with compiled code for the duration of one call.
///
/// Compiled code reads `stack`, `len` and `gas` on entry and writes all four
/// fields back before returning, so the struct is both the argument and the
/// result.
#[repr(C)]
pub struct Frame {
    /// Base of the limb array; `STACK_LIMIT * LIMBS` elements live here.
    pub stack: *mut u64,
    /// Live height in words.
    pub len: u64,
    /// Gas remaining.
    pub gas: u64,
    /// Where execution stopped. Only meaningful for [`Exit::Bailout`], where
    /// it is the offset of the opcode the compiler declined.
    pub pc: u64,
}

/// Byte offsets into [`Frame`], as the code generator needs them.
pub mod offset {
    pub const STACK: i32 = 0;
    pub const LEN: i32 = 8;
    pub const GAS: i32 = 16;
    pub const PC: i32 = 24;
}

/// Status words returned by compiled code.
///
/// These are part of the ABI: `translate` emits the integers directly, so the
/// discriminants are fixed rather than incidental.
pub mod status {
    pub const STOP: i32 = 0;
    pub const OUT_OF_GAS: i32 = 1;
    pub const STACK_UNDERFLOW: i32 = 2;
    pub const STACK_OVERFLOW: i32 = 3;
    pub const INVALID_JUMP: i32 = 4;
    pub const BAILOUT: i32 = 5;
}

/// Why compiled code returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Normal end of the frame.
    Stop,
    /// Exceptional halt; the frame has forfeited its gas.
    OutOfGas,
    StackUnderflow,
    StackOverflow,
    InvalidJump,
    /// An opcode outside the compiled subset was reached. The machine's stack
    /// and gas are live and exact as of `pc`, which is where an interpreter
    /// would pick the frame up.
    Bailout {
        pc: usize,
    },
}

impl Exit {
    fn from_status(code: i32, pc: u64) -> Self {
        match code {
            status::STOP => Exit::Stop,
            status::OUT_OF_GAS => Exit::OutOfGas,
            status::STACK_UNDERFLOW => Exit::StackUnderflow,
            status::STACK_OVERFLOW => Exit::StackOverflow,
            status::INVALID_JUMP => Exit::InvalidJump,
            status::BAILOUT => Exit::Bailout { pc: pc as usize },
            other => unreachable!("compiled code returned an unknown status {other}"),
        }
    }
}

/// The stack already holds [`STACK_LIMIT`] words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackFull;

impl std::fmt::Display for StackFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "stack is full at {STACK_LIMIT} words")
    }
}

impl std::error::Error for StackFull {}

/// Owns the stack backing a run and hands compiled code a [`Frame`] over it.
///
/// The limb array is boxed once and never reallocated, so the pointer handed
/// across the boundary stays valid for the machine's whole life — the reason
/// this is a `Box<[u64]>` and not a `Vec` that could move under a `push`.
pub struct Machine {
    limbs: Box<[u64]>,
    len: u64,
    gas: u64,
    pc: u64,
}

impl Machine {
    pub fn new(gas: u64) -> Self {
        Self {
            limbs: vec![0u64; STACK_LIMIT * LIMBS].into_boxed_slice(),
            len: 0,
            gas,
            pc: 0,
        }
    }

    /// Seed the stack bottom-up, as a caller would leave it.
    pub fn push(&mut self, value: U256) -> Result<(), StackFull> {
        if self.len as usize >= STACK_LIMIT {
            return Err(StackFull);
        }
        let base = self.len as usize * LIMBS;
        self.limbs[base..base + LIMBS].copy_from_slice(&value.0);
        self.len += 1;
        Ok(())
    }

    /// Snapshot of the live stack, bottom first.
    pub fn stack(&self) -> Vec<U256> {
        (0..self.len as usize)
            .map(|i| {
                let base = i * LIMBS;
                let mut limbs = [0u64; LIMBS];
                limbs.copy_from_slice(&self.limbs[base..base + LIMBS]);
                U256(limbs)
            })
            .collect()
    }

    pub fn gas(&self) -> u64 {
        self.gas
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Call `entry` with a frame over this machine's state.
    ///
    /// # Safety
    ///
    /// `entry` must be a function produced by this crate's compiler for the
    /// current ISA: the contract on offsets, status words and stack layout is
    /// not checkable here.
    pub unsafe fn run(&mut self, entry: *const u8) -> Exit {
        let mut frame = Frame {
            stack: self.limbs.as_mut_ptr(),
            len: self.len,
            gas: self.gas,
            pc: self.pc,
        };
        let compiled: extern "C" fn(*mut Frame) -> i32 = std::mem::transmute(entry);
        let status = compiled(&mut frame);
        self.len = frame.len;
        self.gas = frame.gas;
        self.pc = frame.pc;
        Exit::from_status(status, frame.pc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The code generator hardcodes these; if the layout ever drifts, the
    /// failure would otherwise be a wild pointer rather than a test.
    #[test]
    fn frame_offsets_match_the_generated_code() {
        let frame = Frame {
            stack: std::ptr::null_mut(),
            len: 0,
            gas: 0,
            pc: 0,
        };
        let base = std::ptr::addr_of!(frame) as usize;
        let at = |p: *const u8| p as usize - base;
        assert_eq!(
            at(std::ptr::addr_of!(frame.stack).cast()),
            offset::STACK as usize
        );
        assert_eq!(
            at(std::ptr::addr_of!(frame.len).cast()),
            offset::LEN as usize
        );
        assert_eq!(
            at(std::ptr::addr_of!(frame.gas).cast()),
            offset::GAS as usize
        );
        assert_eq!(at(std::ptr::addr_of!(frame.pc).cast()), offset::PC as usize);
    }

    #[test]
    fn words_round_trip_through_the_limb_array() {
        let mut machine = Machine::new(0);
        let value = U256::from_big_endian(&[0xab; 32]);
        machine.push(value).unwrap();
        machine.push(U256::from(7u64)).unwrap();
        assert_eq!(machine.stack(), vec![value, U256::from(7u64)]);
    }

    #[test]
    fn stack_cannot_grow_past_the_limit() {
        let mut machine = Machine::new(0);
        for _ in 0..STACK_LIMIT {
            machine.push(U256::zero()).unwrap();
        }
        assert!(machine.push(U256::zero()).is_err());
    }
}

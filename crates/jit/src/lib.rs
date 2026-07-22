//! A JIT compiler for EVM bytecode, backed by Cranelift.
//!
//! The compiler covers the arithmetic, stack and control-flow core of the
//! instruction set and hands everything else back to an interpreter. That
//! split is deliberate: the opcodes it declines are the ones that talk to the
//! host — storage, calls, memory expansion — where the win would be small and
//! the surface for a consensus bug large. What is left is where a frame
//! actually spends its time, and where removing per-instruction dispatch, gas
//! accounting and stack bounds checks pays.
//!
//! Correctness rests on two things. The block analysis proves what may be
//! hoisted, and a differential test drives random programs through both this
//! compiler and athanor's interpreter, comparing gas, stack and halt reason —
//! the interpreter is the reference, and it is one that already reproduces
//! 19,690 of the official Cancun state tests.

pub mod analysis;
pub mod frame;
pub mod translate;

pub use analysis::{analyse, Block, Program, Terminator};
pub use frame::{Exit, Machine, StackFull};
pub use translate::{CompileError, Compiled, Compiler};

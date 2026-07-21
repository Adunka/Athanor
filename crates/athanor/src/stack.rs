//! The operand stack: 1024 words, underflow and overflow are exceptional
//! halts (YP §9.4.2). Backed by a `Vec` pre-sized to the limit so pushes
//! never reallocate.

use crate::primitives::U256;
use crate::result::Halt;

pub const STACK_LIMIT: usize = 1024;

#[derive(Debug, Clone, Default)]
pub struct Stack {
    data: Vec<U256>,
}

impl Stack {
    pub fn new() -> Self {
        Self {
            data: Vec::with_capacity(STACK_LIMIT),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn data(&self) -> &[U256] {
        &self.data
    }

    #[inline]
    pub fn push(&mut self, value: U256) -> Result<(), Halt> {
        if self.data.len() >= STACK_LIMIT {
            return Err(Halt::StackOverflow);
        }
        self.data.push(value);
        Ok(())
    }

    #[inline]
    pub fn pop(&mut self) -> Result<U256, Halt> {
        self.data.pop().ok_or(Halt::StackUnderflow)
    }

    /// Pop two operands; the first returned value was on top. Every binary
    /// instruction takes its operands in this order (`SUB` computes
    /// `top - second`).
    #[inline]
    pub fn pop2(&mut self) -> Result<(U256, U256), Halt> {
        let a = self.pop()?;
        let b = self.pop()?;
        Ok((a, b))
    }

    #[inline]
    pub fn pop3(&mut self) -> Result<(U256, U256, U256), Halt> {
        let a = self.pop()?;
        let b = self.pop()?;
        let c = self.pop()?;
        Ok((a, b, c))
    }

    /// Item `n` positions below the top, `peek(0)` being the top itself.
    #[inline]
    pub fn peek(&self, n: usize) -> Result<U256, Halt> {
        if n >= self.data.len() {
            return Err(Halt::StackUnderflow);
        }
        Ok(self.data[self.data.len() - 1 - n])
    }

    #[inline]
    pub fn top_mut(&mut self) -> Result<&mut U256, Halt> {
        self.data.last_mut().ok_or(Halt::StackUnderflow)
    }

    /// `DUPn`, `n` in `1..=16`: copy the n-th item onto the top.
    #[inline]
    pub fn dup(&mut self, n: usize) -> Result<(), Halt> {
        let value = self.peek(n - 1)?;
        self.push(value)
    }

    /// `SWAPn`, `n` in `1..=16`: exchange the top with the (n+1)-th item.
    #[inline]
    pub fn swap(&mut self, n: usize) -> Result<(), Halt> {
        let len = self.data.len();
        if n >= len {
            return Err(Halt::StackUnderflow);
        }
        self.data.swap(len - 1, len - 1 - n);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_pop_order() {
        let mut s = Stack::new();
        s.push(U256::from(1)).unwrap();
        s.push(U256::from(2)).unwrap();
        let (a, b) = s.pop2().unwrap();
        assert_eq!((a, b), (U256::from(2), U256::from(1)));
        assert_eq!(s.pop(), Err(Halt::StackUnderflow));
    }

    #[test]
    fn overflow_at_limit() {
        let mut s = Stack::new();
        for i in 0..STACK_LIMIT {
            s.push(U256::from(i as u64)).unwrap();
        }
        assert_eq!(s.push(U256::zero()), Err(Halt::StackOverflow));
        assert_eq!(s.len(), STACK_LIMIT);
    }

    #[test]
    fn dup_and_swap() {
        let mut s = Stack::new();
        for i in 1..=4u64 {
            s.push(U256::from(i)).unwrap();
        }
        // Stack (bottom -> top): 1 2 3 4
        s.dup(4).unwrap(); // copies the 1
        assert_eq!(s.peek(0).unwrap(), U256::from(1));
        s.pop().unwrap();
        s.swap(3).unwrap(); // 4 <-> 1
        assert_eq!(s.peek(0).unwrap(), U256::from(1));
        assert_eq!(s.peek(3).unwrap(), U256::from(4));
        assert_eq!(s.swap(4), Err(Halt::StackUnderflow));
        assert_eq!(s.dup(5), Err(Halt::StackUnderflow));
    }
}

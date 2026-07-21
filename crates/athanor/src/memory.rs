//! Linear memory. Grows in 32-byte words; the quadratic term of the
//! expansion cost (YP eq. 326: `C_mem(a) = G_mem * a + a^2 / 512`) is what
//! actually bounds its size, so gas is charged *before* any allocation
//! happens — the allocation itself must never be the failure point.

use crate::gas::Gas;
use crate::primitives::{u256_to_be, U256};
use crate::result::Halt;

/// Hard ceiling on addressable memory, independent of gas. Any offset the
/// gas schedule could ever admit sits far below this; the cap only exists
/// so hostile gas limits cannot turn into hostile allocations.
const MEMORY_HARD_CAP: u64 = 1 << 32;

#[derive(Debug, Default)]
pub struct Memory {
    data: Vec<u8>,
}

impl Memory {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Current size in bytes. Always a multiple of 32; this is what
    /// `MSIZE` reports.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Charge for and perform expansion so that `[offset, offset + len)` is
    /// addressable, returning `offset` as a `usize`. A zero `len` ignores
    /// the offset entirely and costs nothing — the spec treats every
    /// `(offset, 0)` range as empty, even at absurd offsets.
    pub fn expand(&mut self, gas: &mut Gas, offset: U256, len: U256) -> Result<usize, Halt> {
        if len.is_zero() {
            return Ok(0);
        }
        let offset = to_u64(offset)?;
        let len = to_u64(len)?;
        let end = offset.checked_add(len).ok_or(Halt::MemoryLimit)?;
        if end > MEMORY_HARD_CAP {
            return Err(Halt::MemoryLimit);
        }

        let new_words = end.div_ceil(32);
        let old_words = self.data.len() as u64 / 32;
        if new_words > old_words {
            let cost = expansion_gas(new_words)
                .and_then(|n| Some(n - expansion_gas(old_words)?))
                .ok_or(Halt::OutOfGas)?;
            gas.record(cost)?;
            self.data.resize((new_words * 32) as usize, 0);
        }
        Ok(offset as usize)
    }

    #[inline]
    pub fn slice(&self, offset: usize, len: usize) -> &[u8] {
        &self.data[offset..offset + len]
    }

    #[inline]
    pub fn set(&mut self, offset: usize, data: &[u8]) {
        self.data[offset..offset + data.len()].copy_from_slice(data);
    }

    #[inline]
    pub fn set_byte(&mut self, offset: usize, byte: u8) {
        self.data[offset] = byte;
    }

    #[inline]
    pub fn set_u256(&mut self, offset: usize, value: U256) {
        self.set(offset, &u256_to_be(value));
    }

    #[inline]
    pub fn get_u256(&self, offset: usize) -> U256 {
        U256::from_big_endian(self.slice(offset, 32))
    }

    /// `MCOPY` backing: overlapping ranges are fine, `copy_within` has
    /// memmove semantics.
    #[inline]
    pub fn copy_within(&mut self, dst: usize, src: usize, len: usize) {
        self.data.copy_within(src..src + len, dst);
    }

    /// Copy `len` bytes into memory at `mem_offset` from `data[data_offset..]`,
    /// zero-filling everything past the end of `data`. This is the shared
    /// shape of `CALLDATACOPY`, `CODECOPY` and `EXTCODECOPY`, which pad
    /// instead of failing on out-of-range reads.
    pub fn set_data_padded(
        &mut self,
        mem_offset: usize,
        data: &[u8],
        data_offset: U256,
        len: usize,
    ) {
        let dst = &mut self.data[mem_offset..mem_offset + len];
        // An offset beyond the source means the copy is all padding.
        let start = if data_offset > U256::from(data.len()) {
            data.len()
        } else {
            data_offset.as_usize()
        };
        let available = data.len() - start;
        let copied = len.min(available);
        dst[..copied].copy_from_slice(&data[start..start + copied]);
        dst[copied..].fill(0);
    }
}

#[inline]
fn to_u64(v: U256) -> Result<u64, Halt> {
    if v.bits() > 64 {
        Err(Halt::MemoryLimit)
    } else {
        Ok(v.as_u64())
    }
}

/// Total cost of a memory of `words` words: `3w + w^2 / 512`.
fn expansion_gas(words: u64) -> Option<u64> {
    let linear = words.checked_mul(3)?;
    let quad = (words as u128).checked_mul(words as u128)? / 512;
    let quad: u64 = quad.try_into().ok()?;
    linear.checked_add(quad)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gas() -> Gas {
        Gas::new(10_000_000)
    }

    #[test]
    fn expansion_cost_schedule() {
        // One word: 3. 32 words (1 KiB): 3*32 + 32^2/512 = 96 + 2 = 98.
        let mut m = Memory::new();
        let mut g = gas();
        m.expand(&mut g, U256::zero(), U256::from(1)).unwrap();
        assert_eq!(g.spent(), 3);
        assert_eq!(m.len(), 32);

        let mut m = Memory::new();
        let mut g = gas();
        m.expand(&mut g, U256::zero(), U256::from(1024)).unwrap();
        assert_eq!(g.spent(), 98);
        assert_eq!(m.len(), 1024);
    }

    #[test]
    fn expansion_charges_only_delta() {
        let mut m = Memory::new();
        let mut g = gas();
        m.expand(&mut g, U256::zero(), U256::from(32)).unwrap();
        let after_first = g.spent();
        // Same range again: no growth, no charge.
        m.expand(&mut g, U256::zero(), U256::from(32)).unwrap();
        assert_eq!(g.spent(), after_first);
        // Growing to two words costs exactly one more word.
        m.expand(&mut g, U256::from(32), U256::from(1)).unwrap();
        assert_eq!(g.spent(), after_first + 3);
    }

    #[test]
    fn zero_length_ignores_offset() {
        let mut m = Memory::new();
        let mut g = gas();
        m.expand(&mut g, U256::MAX, U256::zero()).unwrap();
        assert_eq!(g.spent(), 0);
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn huge_offset_is_out_of_gas_not_panic() {
        let mut m = Memory::new();
        let mut g = gas();
        let e = m.expand(&mut g, U256::from(u64::MAX), U256::from(1));
        assert!(matches!(e, Err(Halt::MemoryLimit)));
        let e = m.expand(&mut g, U256::from(1u64 << 40), U256::from(1));
        assert!(matches!(e, Err(Halt::MemoryLimit) | Err(Halt::OutOfGas)));
    }

    #[test]
    fn padded_copy() {
        let mut m = Memory::new();
        let mut g = gas();
        m.expand(&mut g, U256::zero(), U256::from(32)).unwrap();
        m.set(0, &[0xaa; 32]);
        m.set_data_padded(0, &[1, 2, 3], U256::from(1), 8);
        assert_eq!(m.slice(0, 8), &[2, 3, 0, 0, 0, 0, 0, 0]);
        // Source offset entirely past the data: pure padding.
        m.set_data_padded(8, &[1, 2, 3], U256::MAX, 4);
        assert_eq!(m.slice(8, 4), &[0, 0, 0, 0]);
    }
}

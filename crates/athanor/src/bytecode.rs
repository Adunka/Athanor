//! Immutable contract code with memoized analysis.
//!
//! [`Bytecode`] is the unit the executor and interpreter pass around: the
//! bytes behind an `Arc`, plus two lazily-computed companions — the
//! `JUMPDEST` table and the code hash — each in an `Arc<OnceLock>` shared
//! by every clone. The consequences are worth spelling out:
//!
//! * cloning (which frames do constantly) is reference-count bumps, never
//!   a byte copy;
//! * a contract called a thousand times in one transaction is analyzed
//!   and hashed at most once — the self-recursion integration test drives
//!   hundreds of frames through a single shared jump table;
//! * the state layer stores `Bytecode` directly, so journaling the old
//!   code on a `CodeChange` is O(1).

use std::fmt;
use std::sync::{Arc, OnceLock};

use crate::opcode as op;
use crate::primitives::{keccak256, B256, KECCAK_EMPTY};

#[derive(Clone)]
pub struct Bytecode {
    bytes: Arc<[u8]>,
    jump_table: Arc<OnceLock<JumpTable>>,
    hash: Arc<OnceLock<B256>>,
}

impl Bytecode {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: bytes.into(),
            jump_table: Arc::new(OnceLock::new()),
            hash: Arc::new(OnceLock::new()),
        }
    }

    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// keccak256 of the bytes ([`KECCAK_EMPTY`] for empty code), computed
    /// on first use and visible to every clone thereafter.
    pub fn hash(&self) -> B256 {
        *self.hash.get_or_init(|| {
            if self.bytes.is_empty() {
                KECCAK_EMPTY
            } else {
                keccak256(&self.bytes)
            }
        })
    }

    /// The valid-`JUMPDEST` table, computed on the first jump and shared
    /// by every clone.
    pub fn jump_table(&self) -> &JumpTable {
        self.jump_table
            .get_or_init(|| JumpTable::analyze(&self.bytes))
    }
}

impl Default for Bytecode {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl From<Vec<u8>> for Bytecode {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl PartialEq for Bytecode {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for Bytecode {}

impl fmt::Debug for Bytecode {
    /// Code bodies are long and binary; identify, don't dump. Deliberately
    /// avoids touching the lazy fields — `Debug` must not have side
    /// effects.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bytecode")
            .field("len", &self.len())
            .finish()
    }
}

/// Bitmap of valid jump destinations: positions holding `JUMPDEST` (0x5b)
/// *outside* push immediates (YP §9.4.3, D_J). One linear scan that steps
/// over push data.
pub struct JumpTable(Box<[u8]>);

impl JumpTable {
    fn analyze(code: &[u8]) -> Self {
        let mut bitmap = vec![0u8; code.len().div_ceil(8)].into_boxed_slice();
        let mut i = 0;
        while i < code.len() {
            let opcode = code[i];
            if opcode == op::JUMPDEST {
                bitmap[i / 8] |= 1 << (i % 8);
            }
            i += 1 + op::push_size(opcode);
        }
        Self(bitmap)
    }

    /// Out-of-range destinations are invalid by construction: padding bits
    /// in the last byte are never set, so no separate bounds check exists
    /// to forget.
    #[inline]
    pub fn is_valid(&self, dest: usize) -> bool {
        self.0
            .get(dest / 8)
            .is_some_and(|byte| byte & (1 << (dest % 8)) != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_data_is_not_a_destination() {
        // PUSH1 0x5b, JUMPDEST — only offset 2 is real.
        let code = Bytecode::new(vec![op::PUSH1, 0x5b, op::JUMPDEST]);
        let table = code.jump_table();
        assert!(!table.is_valid(0));
        assert!(!table.is_valid(1), "0x5b inside an immediate is data");
        assert!(table.is_valid(2));
        assert!(!table.is_valid(3), "past the end");
        assert!(!table.is_valid(usize::MAX / 2), "far past the end");
    }

    #[test]
    fn lazy_fields_are_shared_across_clones() {
        let a = Bytecode::new(vec![op::JUMPDEST]);
        let b = a.clone();
        assert!(b.hash.get().is_none());
        let h = a.hash();
        assert_eq!(b.hash.get(), Some(&h), "clone sees the memoized hash");
        assert!(Arc::ptr_eq(&a.jump_table, &b.jump_table));
    }

    #[test]
    fn empty_code_hashes_to_the_empty_constant() {
        assert_eq!(Bytecode::default().hash(), KECCAK_EMPTY);
    }
}

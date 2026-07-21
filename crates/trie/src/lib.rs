//! A Merkle Patricia Trie with Ethereum-compatible roots and proofs.
//!
//! Keys map to values through a radix-16 trie whose every node is committed
//! by hashing its RLP encoding; the root hash is the same 32-byte value
//! Ethereum uses to commit to account and storage state. See [`Trie`] for
//! the entry point.

pub mod nibbles;
pub mod node;
pub mod proof;
pub mod rlp;
pub mod trie;

pub use trie::Trie;

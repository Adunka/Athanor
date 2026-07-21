//! Trie nodes and the encoding that gives them their hashes.
//!
//! Four node shapes cover the whole structure: the empty node, a leaf
//! holding a key remainder and a value, an extension sharing a run of
//! nibbles above a child, and a sixteen-way branch (optionally carrying a
//! value for a key that ends exactly at the branch).
//!
//! The one rule everything hinges on is how a node is *referenced* by its
//! parent: encode the node as RLP, and if that encoding is 32 bytes or
//! longer, the parent stores its keccak hash; if shorter, the parent inlines
//! the RLP verbatim. This "inline small nodes" rule is what keeps the trie
//! compact, and it is exactly the detail that makes hand-rolled tries
//! disagree with the reference — so it lives in one place, [`Node::reference`].

use tiny_keccak::{Hasher, Keccak};

use crate::nibbles;
use crate::rlp;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Node {
    #[default]
    Empty,
    Leaf {
        path: Vec<u8>,
        value: Vec<u8>,
    },
    Extension {
        path: Vec<u8>,
        child: Box<Node>,
    },
    Branch {
        children: Box<[Node; 16]>,
        value: Option<Vec<u8>>,
    },
}

impl Node {
    /// An all-empty branch, ready to have children or a value attached.
    pub fn empty_branch() -> Node {
        Node::Branch {
            children: Box::new(std::array::from_fn(|_| Node::Empty)),
            value: None,
        }
    }

    /// RLP encoding of this node.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            // An empty node serializes to the empty string; it only ever
            // appears inlined in a branch slot.
            Node::Empty => rlp::encode_bytes(&[]),
            Node::Leaf { path, value } => {
                let compact = nibbles::compact_encode(path, true);
                rlp::encode_list(&[rlp::encode_bytes(&compact), rlp::encode_bytes(value)])
            }
            Node::Extension { path, child } => {
                let compact = nibbles::compact_encode(path, false);
                rlp::encode_list(&[rlp::encode_bytes(&compact), child.reference()])
            }
            Node::Branch { children, value } => {
                let mut items: Vec<Vec<u8>> = children.iter().map(Node::reference).collect();
                items.push(match value {
                    Some(v) => rlp::encode_bytes(v),
                    None => rlp::encode_bytes(&[]),
                });
                rlp::encode_list(&items)
            }
        }
    }

    /// What a parent stores for this node: the RLP inlined if it is under
    /// 32 bytes, otherwise the keccak hash as an RLP string.
    pub fn reference(&self) -> Vec<u8> {
        let encoded = self.encode();
        if encoded.len() < 32 {
            encoded
        } else {
            rlp::encode_bytes(&keccak256(&encoded))
        }
    }

    /// The trie root: always the keccak of the root node's encoding, even
    /// when that encoding would otherwise be inlined.
    pub fn hash(&self) -> [u8; 32] {
        keccak256(&self.encode())
    }
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_trie_root_is_the_canonical_constant() {
        // keccak256(rlp("")) == keccak256(0x80): the well-known empty root.
        let root = Node::Empty.hash();
        assert_eq!(
            hex::encode(root),
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
    }

    #[test]
    fn single_leaf_reference_is_inlined_when_small() {
        // A short leaf encodes to well under 32 bytes, so a parent would
        // inline it rather than hash it.
        let leaf = Node::Leaf {
            path: vec![1, 2],
            value: b"x".to_vec(),
        };
        assert!(leaf.encode().len() < 32);
        assert_eq!(leaf.reference(), leaf.encode(), "small node is inlined");
    }
}

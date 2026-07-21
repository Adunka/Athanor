//! Merkle proofs: what makes this trie an *authenticated* structure.
//!
//! A proof for a key is the set of node encodings along the path from the
//! root to that key. A verifier holding only the 32-byte root hash can
//! replay the walk — resolving each reference either by looking a hash up
//! among the proof nodes or by reading an inlined child directly — and end
//! up with the value, or with a proof that the key is *absent*. This is the
//! mechanism a light client uses to trust state it never stored.

use std::collections::HashMap;

use crate::nibbles;
use crate::node::{keccak256, Node};
use crate::rlp::{self, Item};
use crate::Trie;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    /// A referenced node was not supplied in the proof.
    MissingNode,
    /// A proof entry was not valid RLP.
    BadRlp,
    /// A node had a shape that is not a leaf, extension, or branch.
    MalformedNode,
    /// A child reference was neither empty, a 32-byte hash, nor inline.
    BadReference,
}

impl Trie {
    /// Produce a proof for `key`: the encodings of the nodes on its path.
    ///
    /// The root node is always included (a verifier starts from the root
    /// hash); deeper nodes are included when they are hash-referenced.
    /// Inlined children need no entry of their own — they travel inside
    /// their parent's encoding.
    pub fn prove(&self, key: &[u8]) -> Vec<Vec<u8>> {
        let mut proof = Vec::new();
        collect(self.root(), &nibbles::from_bytes(key), true, &mut proof);
        proof
    }
}

fn collect(node: &Node, path: &[u8], is_root: bool, proof: &mut Vec<Vec<u8>>) {
    let encoded = node.encode();
    if (is_root || encoded.len() >= 32) && !proof.contains(&encoded) {
        proof.push(encoded);
    }
    match node {
        Node::Extension {
            path: ext_path,
            child,
        } if path.starts_with(ext_path) => {
            collect(child, &path[ext_path.len()..], false, proof);
        }
        Node::Branch { children, .. } if !path.is_empty() => {
            collect(&children[path[0] as usize], &path[1..], false, proof);
        }
        _ => {}
    }
}

/// Verify a proof against a trusted root. Returns the value on membership,
/// `None` on a valid proof of absence, and an error if the proof does not
/// hang together.
pub fn verify_proof(
    root_hash: [u8; 32],
    key: &[u8],
    proof: &[Vec<u8>],
) -> Result<Option<Vec<u8>>, ProofError> {
    let mut nodes = HashMap::with_capacity(proof.len());
    for entry in proof {
        let decoded = rlp::decode(entry).map_err(|_| ProofError::BadRlp)?;
        nodes.insert(keccak256(entry), decoded);
    }

    let path = nibbles::from_bytes(key);
    let root = match nodes.get(&root_hash) {
        Some(node) => node.clone(),
        // An empty-trie root proves absence of everything.
        None if root_hash == Node::Empty.hash() => return Ok(None),
        None => return Err(ProofError::MissingNode),
    };
    walk(&root, &path, &nodes)
}

fn walk(
    node: &Item,
    path: &[u8],
    nodes: &HashMap<[u8; 32], Item>,
) -> Result<Option<Vec<u8>>, ProofError> {
    let items = node.as_list().ok_or(ProofError::MalformedNode)?;
    match items.len() {
        2 => {
            let compact = items[0].as_bytes().ok_or(ProofError::MalformedNode)?;
            let (node_path, is_leaf) = nibbles::compact_decode(compact);
            if is_leaf {
                // The key is present only if the leaf's path is exactly what
                // remains of it.
                if path == node_path {
                    Ok(Some(
                        items[1]
                            .as_bytes()
                            .ok_or(ProofError::MalformedNode)?
                            .to_vec(),
                    ))
                } else {
                    Ok(None)
                }
            } else if path.starts_with(&node_path) {
                match resolve(&items[1], nodes)? {
                    Some(child) => walk(&child, &path[node_path.len()..], nodes),
                    None => Ok(None),
                }
            } else {
                Ok(None)
            }
        }
        17 => {
            if path.is_empty() {
                let value = items[16].as_bytes().ok_or(ProofError::MalformedNode)?;
                Ok((!value.is_empty()).then(|| value.to_vec()))
            } else {
                match resolve(&items[path[0] as usize], nodes)? {
                    Some(child) => walk(&child, &path[1..], nodes),
                    None => Ok(None),
                }
            }
        }
        _ => Err(ProofError::MalformedNode),
    }
}

/// Follow a child reference to the next node: an empty slot yields `None`
/// (absence), a 32-byte hash is looked up, and an inline list is the node
/// itself.
fn resolve(reference: &Item, nodes: &HashMap<[u8; 32], Item>) -> Result<Option<Item>, ProofError> {
    match reference {
        Item::Bytes(bytes) if bytes.is_empty() => Ok(None),
        Item::Bytes(bytes) if bytes.len() == 32 => {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(bytes);
            nodes
                .get(&hash)
                .cloned()
                .map(Some)
                .ok_or(ProofError::MissingNode)
        }
        Item::Bytes(_) => Err(ProofError::BadReference),
        Item::List(_) => Ok(Some(reference.clone())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Trie {
        let mut trie = Trie::new();
        for (k, v) in [
            (b"do".as_slice(), b"verb".as_slice()),
            (b"dog", b"puppy"),
            (b"doge", b"coin"),
            (b"horse", b"stallion"),
            (b"cattle", b"moo"),
        ] {
            trie.insert(k, v);
        }
        trie
    }

    #[test]
    fn membership_proof_verifies() {
        let trie = sample();
        let root = trie.root_hash();
        for key in [b"do".as_slice(), b"dog", b"doge", b"horse", b"cattle"] {
            let proof = trie.prove(key);
            let recovered = verify_proof(root, key, &proof).unwrap();
            assert_eq!(recovered.as_deref(), trie.get(key), "key {key:?}");
        }
    }

    #[test]
    fn absence_proof_verifies() {
        let trie = sample();
        let root = trie.root_hash();
        for absent in [b"cat".as_slice(), b"dogs", b"ho", b"zzz"] {
            let proof = trie.prove(absent);
            assert_eq!(
                verify_proof(root, absent, &proof).unwrap(),
                None,
                "key {absent:?}"
            );
        }
    }

    #[test]
    fn tampered_proof_is_rejected_or_wrong() {
        let trie = sample();
        let root = trie.root_hash();
        let mut proof = trie.prove(b"doge");
        // Corrupt the last node: verification must not still return the
        // real value under the genuine root.
        if let Some(last) = proof.last_mut() {
            if let Some(byte) = last.last_mut() {
                *byte ^= 0xff;
            }
        }
        let result = verify_proof(root, b"doge", &proof);
        assert!(
            !matches!(result, Ok(Some(ref v)) if v.as_slice() == b"coin"),
            "tampered proof must not verify the true value"
        );
    }
}

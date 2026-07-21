//! The trie itself: insert, get, delete, and the root hash.
//!
//! Keys are walked as nibbles. Insertion splits leaves and extensions when
//! a new key diverges from an existing path; deletion is the harder
//! direction, because removing a key can leave a branch with a single
//! surviving child or an extension pointing straight at another extension,
//! and those degenerate shapes must be collapsed back into canonical form
//! or the root hash will not match. The collapse rules live in
//! [`collapse_branch`] and [`collapse_extension`].

use crate::nibbles;
use crate::node::Node;

/// An in-memory Merkle Patricia Trie.
#[derive(Debug, Default, Clone)]
pub struct Trie {
    root: Node,
}

impl Trie {
    pub fn new() -> Self {
        Trie { root: Node::Empty }
    }

    /// Insert or overwrite `key`. An empty value deletes the key, matching
    /// Ethereum trie semantics (there is no way to store "empty").
    pub fn insert(&mut self, key: &[u8], value: &[u8]) {
        if value.is_empty() {
            self.remove(key);
            return;
        }
        let path = nibbles::from_bytes(key);
        let root = std::mem::take(&mut self.root);
        self.root = insert(root, &path, value.to_vec());
    }

    /// Remove `key` if present; a no-op otherwise.
    pub fn remove(&mut self, key: &[u8]) {
        let path = nibbles::from_bytes(key);
        let root = std::mem::take(&mut self.root);
        self.root = delete(root, &path);
    }

    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        get(&self.root, &nibbles::from_bytes(key))
    }

    /// The 32-byte root hash — the trie's cryptographic commitment.
    pub fn root_hash(&self) -> [u8; 32] {
        self.root.hash()
    }

    pub(crate) fn root(&self) -> &Node {
        &self.root
    }
}

fn insert(node: Node, path: &[u8], value: Vec<u8>) -> Node {
    match node {
        Node::Empty => Node::Leaf {
            path: path.to_vec(),
            value,
        },

        Node::Leaf {
            path: leaf_path,
            value: leaf_value,
        } => {
            let shared = nibbles::common_prefix(path, &leaf_path);
            if shared == leaf_path.len() && shared == path.len() {
                // Same key: overwrite.
                return Node::Leaf {
                    path: leaf_path,
                    value,
                };
            }
            // Diverge: build a branch holding the old leaf and the new
            // value, under an extension for any shared prefix.
            let branch = branch_of_two(&leaf_path[shared..], leaf_value, &path[shared..], value);
            with_prefix(&path[..shared], branch)
        }

        Node::Extension {
            path: ext_path,
            child,
        } => {
            let shared = nibbles::common_prefix(path, &ext_path);
            if shared == ext_path.len() {
                // The whole extension is consumed; descend into the child.
                let new_child = insert(*child, &path[shared..], value);
                return Node::Extension {
                    path: ext_path,
                    child: Box::new(new_child),
                };
            }
            // The extension splits. The part beyond the shared prefix
            // becomes a branch entry; a one-nibble remainder collapses the
            // extension away entirely.
            let ext_remainder = &ext_path[shared..];
            let mut branch = Node::empty_branch();
            let branched_child = if ext_remainder.len() == 1 {
                *child
            } else {
                Node::Extension {
                    path: ext_remainder[1..].to_vec(),
                    child,
                }
            };
            set_branch_child(&mut branch, ext_remainder[0], branched_child);
            let branch = insert(branch, &path[shared..], value);
            with_prefix(&path[..shared], branch)
        }

        Node::Branch {
            mut children,
            value: branch_value,
        } => {
            if path.is_empty() {
                return Node::Branch {
                    children,
                    value: Some(value),
                };
            }
            let slot = path[0] as usize;
            let child = std::mem::replace(&mut children[slot], Node::Empty);
            children[slot] = insert(child, &path[1..], value);
            Node::Branch {
                children,
                value: branch_value,
            }
        }
    }
}

fn get<'a>(node: &'a Node, path: &[u8]) -> Option<&'a [u8]> {
    match node {
        Node::Empty => None,
        Node::Leaf {
            path: leaf_path,
            value,
        } => (leaf_path == path).then_some(value.as_slice()),
        Node::Extension {
            path: ext_path,
            child,
        } => path
            .starts_with(ext_path)
            .then(|| get(child, &path[ext_path.len()..]))?,
        Node::Branch { children, value } => {
            if path.is_empty() {
                value.as_deref()
            } else {
                get(&children[path[0] as usize], &path[1..])
            }
        }
    }
}

fn delete(node: Node, path: &[u8]) -> Node {
    match node {
        Node::Empty => Node::Empty,

        Node::Leaf {
            path: leaf_path,
            value,
        } => {
            if leaf_path == path {
                Node::Empty
            } else {
                Node::Leaf {
                    path: leaf_path,
                    value,
                }
            }
        }

        Node::Extension {
            path: ext_path,
            child,
        } => {
            if !path.starts_with(&ext_path) {
                return Node::Extension {
                    path: ext_path,
                    child,
                };
            }
            let new_child = delete(*child, &path[ext_path.len()..]);
            collapse_extension(ext_path, new_child)
        }

        Node::Branch {
            mut children,
            value,
        } => {
            let value = if path.is_empty() {
                None
            } else {
                let slot = path[0] as usize;
                let child = std::mem::replace(&mut children[slot], Node::Empty);
                children[slot] = delete(child, &path[1..]);
                value
            };
            collapse_branch(children, value)
        }
    }
}

// --- construction and collapse helpers ---

/// Build a branch holding two (remainder, value) pairs that share no first
/// nibble. Each pair with an empty remainder becomes the branch's own
/// value; otherwise it becomes a leaf under the slot of its first nibble.
fn branch_of_two(rem_a: &[u8], val_a: Vec<u8>, rem_b: &[u8], val_b: Vec<u8>) -> Node {
    let mut branch = Node::empty_branch();
    place_in_branch(&mut branch, rem_a, val_a);
    place_in_branch(&mut branch, rem_b, val_b);
    branch
}

fn place_in_branch(branch: &mut Node, remainder: &[u8], value: Vec<u8>) {
    if let Node::Branch {
        children,
        value: branch_value,
    } = branch
    {
        match remainder.split_first() {
            None => *branch_value = Some(value),
            Some((&first, rest)) => {
                children[first as usize] = Node::Leaf {
                    path: rest.to_vec(),
                    value,
                };
            }
        }
    }
}

fn set_branch_child(branch: &mut Node, nibble: u8, child: Node) {
    if let Node::Branch { children, .. } = branch {
        children[nibble as usize] = child;
    }
}

/// Prepend a shared prefix to a node, as an extension — or nothing if the
/// prefix is empty.
fn with_prefix(prefix: &[u8], node: Node) -> Node {
    if prefix.is_empty() {
        node
    } else {
        Node::Extension {
            path: prefix.to_vec(),
            child: Box::new(node),
        }
    }
}

/// Restore a branch to canonical form after a deletion. A branch with a
/// single remaining entry is not a valid branch and must collapse into the
/// node below it, absorbing the branch's slot nibble.
fn collapse_branch(children: Box<[Node; 16]>, value: Option<Vec<u8>>) -> Node {
    let occupied: Vec<usize> = (0..16)
        .filter(|&i| !matches!(children[i], Node::Empty))
        .collect();

    match (occupied.as_slice(), &value) {
        // Nothing left at all.
        ([], None) => Node::Empty,
        // Only a value: a key that ends here, now a leaf with empty path.
        ([], Some(_)) => Node::Leaf {
            path: Vec::new(),
            value: value.unwrap(),
        },
        // Exactly one child and no value: fold the slot nibble into it.
        ([only], None) => {
            let only = *only;
            let mut children = children;
            let child = std::mem::replace(&mut children[only], Node::Empty);
            prepend_nibble(only as u8, child)
        }
        // Still a genuine branch.
        _ => Node::Branch { children, value },
    }
}

/// Fold a single leading nibble into the node it points to.
fn prepend_nibble(nibble: u8, node: Node) -> Node {
    match node {
        Node::Leaf { path, value } => Node::Leaf {
            path: prepend(nibble, &path),
            value,
        },
        Node::Extension { path, child } => Node::Extension {
            path: prepend(nibble, &path),
            child,
        },
        // A branch below cannot merge; it hangs off a one-nibble extension.
        branch => Node::Extension {
            path: vec![nibble],
            child: Box::new(branch),
        },
    }
}

/// Restore an extension to canonical form after its child changed. An
/// extension must never point at another extension or a leaf — those merge
/// into a single node — and an extension over an empty child disappears.
fn collapse_extension(path: Vec<u8>, child: Node) -> Node {
    match child {
        Node::Empty => Node::Empty,
        Node::Extension {
            path: child_path,
            child: grandchild,
        } => Node::Extension {
            path: concat(&path, &child_path),
            child: grandchild,
        },
        Node::Leaf {
            path: child_path,
            value,
        } => Node::Leaf {
            path: concat(&path, &child_path),
            value,
        },
        branch => Node::Extension {
            path,
            child: Box::new(branch),
        },
    }
}

fn prepend(nibble: u8, rest: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(rest.len() + 1);
    out.push(nibble);
    out.extend_from_slice(rest);
    out
}

fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(a.len() + b.len());
    out.extend_from_slice(a);
    out.extend_from_slice(b);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_after_insert() {
        let mut trie = Trie::new();
        trie.insert(b"do", b"verb");
        trie.insert(b"dog", b"puppy");
        trie.insert(b"doge", b"coin");
        trie.insert(b"horse", b"stallion");

        assert_eq!(trie.get(b"do"), Some(b"verb".as_slice()));
        assert_eq!(trie.get(b"dog"), Some(b"puppy".as_slice()));
        assert_eq!(trie.get(b"doge"), Some(b"coin".as_slice()));
        assert_eq!(trie.get(b"horse"), Some(b"stallion".as_slice()));
        assert_eq!(trie.get(b"dogs"), None);
        assert_eq!(trie.get(b"cat"), None);
    }

    #[test]
    fn overwrite_updates_value() {
        let mut trie = Trie::new();
        trie.insert(b"key", b"first");
        trie.insert(b"key", b"second");
        assert_eq!(trie.get(b"key"), Some(b"second".as_slice()));
    }

    #[test]
    fn delete_removes_and_collapses() {
        let mut trie = Trie::new();
        trie.insert(b"do", b"verb");
        trie.insert(b"dog", b"puppy");
        trie.insert(b"doge", b"coin");

        let full_root = trie.root_hash();
        trie.remove(b"doge");
        assert_eq!(trie.get(b"doge"), None);
        assert_eq!(trie.get(b"do"), Some(b"verb".as_slice()));
        assert_eq!(trie.get(b"dog"), Some(b"puppy".as_slice()));

        // Re-inserting the deleted key must return to the exact same root:
        // the collapse on delete and the split on insert are inverses.
        trie.insert(b"doge", b"coin");
        assert_eq!(trie.root_hash(), full_root);
    }

    #[test]
    fn delete_to_empty_restores_empty_root() {
        let empty = Trie::new().root_hash();
        let mut trie = Trie::new();
        trie.insert(b"a", b"1");
        trie.insert(b"ab", b"2");
        trie.remove(b"a");
        trie.remove(b"ab");
        assert_eq!(trie.root_hash(), empty);
    }
}

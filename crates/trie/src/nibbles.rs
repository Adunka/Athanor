//! Nibble paths and their hex-prefix ("compact") encoding.
//!
//! A trie key is walked one *nibble* (4 bits) at a time — that is why a
//! branch node has sixteen slots. Leaf and extension nodes store a run of
//! shared nibbles, and to serialize that run back into whole bytes the trie
//! uses hex-prefix encoding, which packs two things into a leading nibble:
//! whether the node is a leaf (a terminator) and whether the nibble count
//! is odd. Getting the odd/even padding wrong shifts every subsequent
//! nibble and changes the hash, so this is written out explicitly.

/// Expand a byte slice into its nibbles, high nibble first.
pub fn from_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0f);
    }
    nibbles
}

/// Length of the shared prefix of two nibble slices.
pub fn common_prefix(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

/// Hex-prefix encode a nibble path, tagging it as a leaf or an extension.
///
/// The leading nibble is `flag`, where bit `0b10` marks a leaf and bit
/// `0b01` marks an odd nibble count. An odd path folds its first nibble
/// into the leading byte; an even path gets a full padding byte so the
/// remaining nibbles stay byte-aligned.
pub fn compact_encode(path: &[u8], is_leaf: bool) -> Vec<u8> {
    let flag = if is_leaf { 2u8 } else { 0u8 };
    let mut out = Vec::with_capacity(path.len() / 2 + 1);
    let rest = if path.len() % 2 == 1 {
        out.push((flag + 1) << 4 | path[0]);
        &path[1..]
    } else {
        out.push(flag << 4);
        path
    };
    for pair in rest.chunks_exact(2) {
        out.push(pair[0] << 4 | pair[1]);
    }
    out
}

/// Inverse of [`compact_encode`]: recover the nibble path and whether the
/// node was a leaf. Used when interpreting a node handed to a proof
/// verifier as raw bytes.
pub fn compact_decode(data: &[u8]) -> (Vec<u8>, bool) {
    let first = data[0];
    let flag = first >> 4;
    let is_leaf = flag & 0b10 != 0;
    let odd = flag & 0b01 != 0;

    let mut nibbles = Vec::with_capacity(data.len() * 2);
    if odd {
        nibbles.push(first & 0x0f);
    }
    for &byte in &data[1..] {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0f);
    }
    (nibbles, is_leaf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_expansion() {
        assert_eq!(from_bytes(&[0x12, 0xab]), vec![1, 2, 0xa, 0xb]);
        assert_eq!(from_bytes(&[]), Vec::<u8>::new());
    }

    #[test]
    fn prefix_length() {
        assert_eq!(common_prefix(&[1, 2, 3], &[1, 2, 9]), 2);
        assert_eq!(common_prefix(&[1, 2], &[3, 4]), 0);
        assert_eq!(common_prefix(&[1, 2], &[1, 2, 3]), 2);
    }

    #[test]
    fn hex_prefix_reference_vectors() {
        // The canonical examples from the trie spec.
        // Extension, even: [0,1,2,3,4,5] -> 0x00 012345
        assert_eq!(
            compact_encode(&[0, 1, 2, 3, 4, 5], false),
            vec![0x00, 0x01, 0x23, 0x45]
        );
        // Extension, odd: [1,2,3,4,5] -> 0x11 2345
        assert_eq!(
            compact_encode(&[1, 2, 3, 4, 5], false),
            vec![0x11, 0x23, 0x45]
        );
        // Leaf, odd: [f,1,c,b,8] -> 0x3f 1cb8
        assert_eq!(
            compact_encode(&[0xf, 1, 0xc, 0xb, 8], true),
            vec![0x3f, 0x1c, 0xb8]
        );
        // Leaf, even: [0,f,1,c,b,8] -> 0x20 0f1cb8
        assert_eq!(
            compact_encode(&[0, 0xf, 1, 0xc, 0xb, 8], true),
            vec![0x20, 0x0f, 0x1c, 0xb8]
        );
    }

    #[test]
    fn compact_round_trips() {
        for (path, leaf) in [
            (vec![0u8, 1, 2, 3, 4, 5], false),
            (vec![1u8, 2, 3, 4, 5], false),
            (vec![0xfu8, 1, 0xc, 0xb, 8], true),
            (vec![0u8, 0xf, 1, 0xc, 0xb, 8], true),
            (vec![], true),
        ] {
            let (decoded, is_leaf) = compact_decode(&compact_encode(&path, leaf));
            assert_eq!((decoded, is_leaf), (path, leaf));
        }
    }
}

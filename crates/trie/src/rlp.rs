//! Recursive Length Prefix encoding, the serialization the trie hashes.
//!
//! RLP encodes exactly two shapes — byte strings and lists of items — and
//! that minimalism is the whole point: the trie's node references, and the
//! state root itself, are keccak hashes of RLP, so the encoding has to be
//! byte-exact against the spec. The rules (Yellow Paper, appendix B):
//!
//! * a single byte `< 0x80` is itself;
//! * a string of length `n <= 55` is `0x80 + n` then the bytes;
//! * a longer string is `0xb7 + len(n)` then `n` big-endian then the bytes;
//! * lists mirror the string rules with the base offsets `0xc0` / `0xf7`,
//!   wrapping the concatenation of their already-encoded items.

/// Encode a byte string.
pub fn encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        // A lone low byte is its own encoding — no header.
        return vec![data[0]];
    }
    let mut out = header(data.len(), 0x80);
    out.extend_from_slice(data);
    out
}

/// Wrap already-encoded items into a list.
///
/// The items must themselves be valid RLP fragments — this only prepends
/// the list header to their concatenation. Trie nodes compose this way: a
/// leaf is a two-item list, a branch a seventeen-item list, and each item
/// is either an encoded string or an inlined child node (itself a list).
pub fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let body_len: usize = items.iter().map(Vec::len).sum();
    let mut out = header(body_len, 0xc0);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// The length prefix for a payload of `len` bytes, given the short-form
/// base offset (`0x80` for strings, `0xc0` for lists).
fn header(len: usize, base: u8) -> Vec<u8> {
    if len <= 55 {
        vec![base + len as u8]
    } else {
        let len_be = big_endian(len);
        let mut out = Vec::with_capacity(1 + len_be.len());
        // base + 55 is the long-form marker; + how many length bytes follow.
        out.push(base + 55 + len_be.len() as u8);
        out.extend_from_slice(&len_be);
        out
    }
}

/// Minimal big-endian byte representation of a length (no leading zeros).
fn big_endian(mut n: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    while n > 0 {
        bytes.push((n & 0xff) as u8);
        n >>= 8;
    }
    bytes.reverse();
    bytes
}

/// A decoded RLP item: either a byte string or a list of items. Proof
/// verification needs this to reinterpret a node it was handed as bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    Bytes(Vec<u8>),
    List(Vec<Item>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Empty,
    Truncated,
    Trailing,
    LeadingZero,
}

impl Item {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Item::Bytes(b) => Some(b),
            Item::List(_) => None,
        }
    }

    pub fn as_list(&self) -> Option<&[Item]> {
        match self {
            Item::List(items) => Some(items),
            Item::Bytes(_) => None,
        }
    }
}

/// Decode a complete RLP value, rejecting trailing bytes.
pub fn decode(data: &[u8]) -> Result<Item, DecodeError> {
    let (item, rest) = decode_one(data)?;
    if rest.is_empty() {
        Ok(item)
    } else {
        Err(DecodeError::Trailing)
    }
}

fn decode_one(data: &[u8]) -> Result<(Item, &[u8]), DecodeError> {
    let &first = data.first().ok_or(DecodeError::Empty)?;
    match first {
        // A single low byte stands for itself.
        0x00..=0x7f => Ok((Item::Bytes(vec![first]), &data[1..])),
        // Short string.
        0x80..=0xb7 => {
            let len = (first - 0x80) as usize;
            let body = data.get(1..1 + len).ok_or(DecodeError::Truncated)?;
            Ok((Item::Bytes(body.to_vec()), &data[1 + len..]))
        }
        // Long string: length-of-length, then length, then bytes.
        0xb8..=0xbf => {
            let (len, consumed) = read_length(data, first - 0xb7)?;
            let body = data
                .get(consumed..consumed + len)
                .ok_or(DecodeError::Truncated)?;
            Ok((Item::Bytes(body.to_vec()), &data[consumed + len..]))
        }
        // Short list.
        0xc0..=0xf7 => {
            let len = (first - 0xc0) as usize;
            let body = data.get(1..1 + len).ok_or(DecodeError::Truncated)?;
            Ok((Item::List(decode_items(body)?), &data[1 + len..]))
        }
        // Long list.
        0xf8..=0xff => {
            let (len, consumed) = read_length(data, first - 0xf7)?;
            let body = data
                .get(consumed..consumed + len)
                .ok_or(DecodeError::Truncated)?;
            Ok((Item::List(decode_items(body)?), &data[consumed + len..]))
        }
    }
}

/// Read a big-endian length that follows a long-form marker; returns the
/// value and the offset just past it.
fn read_length(data: &[u8], len_of_len: u8) -> Result<(usize, usize), DecodeError> {
    let len_bytes = data
        .get(1..1 + len_of_len as usize)
        .ok_or(DecodeError::Truncated)?;
    if len_bytes.first() == Some(&0) {
        return Err(DecodeError::LeadingZero);
    }
    let mut len = 0usize;
    for &b in len_bytes {
        len = (len << 8) | b as usize;
    }
    Ok((len, 1 + len_of_len as usize))
}

fn decode_items(mut body: &[u8]) -> Result<Vec<Item>, DecodeError> {
    let mut items = Vec::new();
    while !body.is_empty() {
        let (item, rest) = decode_one(body)?;
        items.push(item);
        body = rest;
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_bytes() {
        assert_eq!(encode_bytes(&[0x00]), vec![0x00]);
        assert_eq!(encode_bytes(&[0x7f]), vec![0x7f]);
        // 0x80 is no longer "small enough" to be bare.
        assert_eq!(encode_bytes(&[0x80]), vec![0x81, 0x80]);
    }

    #[test]
    fn empty_and_short_strings() {
        assert_eq!(encode_bytes(&[]), vec![0x80]);
        assert_eq!(encode_bytes(b"dog"), vec![0x83, b'd', b'o', b'g']);
    }

    #[test]
    fn long_string_uses_length_of_length() {
        let data = vec![b'a'; 56];
        let encoded = encode_bytes(&data);
        // 0xb7 + 1 length byte, then 56, then the payload.
        assert_eq!(&encoded[..2], &[0xb8, 56]);
        assert_eq!(encoded.len(), 58);
    }

    #[test]
    fn lists() {
        // ["cat", "dog"] from the RLP spec.
        let encoded = encode_list(&[encode_bytes(b"cat"), encode_bytes(b"dog")]);
        assert_eq!(
            encoded,
            vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']
        );
        // The empty list.
        assert_eq!(encode_list(&[]), vec![0xc0]);
    }

    #[test]
    fn nested_length_boundary() {
        // A 55-byte payload encodes to a 56-byte item, so the list body is
        // 56 bytes — one past the short-form limit, into long form.
        let item = encode_bytes(&[0u8; 55]); // 0xb7 + 55 bytes = 56 bytes
        let encoded = encode_list(&[item]);
        assert_eq!(encoded[0], 0xf8, "long-form list marker");
        assert_eq!(encoded[1], 56);
    }

    #[test]
    fn decode_round_trips_encoding() {
        // A branch-shaped list: seventeen items, mixing short and long
        // strings, exercises both string forms and list nesting.
        let items: Vec<Vec<u8>> = (0..16)
            .map(|i| encode_bytes(&[i as u8; 1]))
            .chain(std::iter::once(encode_bytes(&[0xabu8; 40])))
            .collect();
        let encoded = encode_list(&items);

        let decoded = decode(&encoded).unwrap();
        let list = decoded.as_list().unwrap();
        assert_eq!(list.len(), 17);
        assert_eq!(list[16].as_bytes().unwrap(), &[0xabu8; 40][..]);
    }

    #[test]
    fn decode_rejects_trailing_and_truncation() {
        assert_eq!(decode(&[0x83, b'a', b'b']), Err(DecodeError::Truncated));
        assert_eq!(
            decode(&[0x82, b'a', b'b', 0x00]),
            Err(DecodeError::Trailing)
        );
    }
}

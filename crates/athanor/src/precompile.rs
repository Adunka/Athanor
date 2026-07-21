//! The precompiled contracts living at addresses `0x01..=0x09`.
//!
//! Each contract takes the raw call input and returns `(gas_cost, output)`.
//! The caller (the frame executor in [`crate::evm`]) is responsible for
//! charging the gas — if the frame cannot afford it the call fails and all
//! gas is consumed. Precompiles never touch state, so they need no journal.
//!
//! Where a precompile's input is malformed, the yellow paper distinguishes
//! two behaviours. Most (ecrecover) *soft-fail*: they return empty output and
//! the surrounding `CALL` still reports success. A few (bn256 pairing,
//! blake2f) *hard-fail*, consuming all gas; those are not yet implemented
//! here. The ones below only ever fail for lack of gas.

use crate::gas::{cost, word_cost};
use crate::primitives::keccak256;

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// What a fallible precompile returns: its gas cost, and either the output
/// bytes or a hard failure (`Err`), on which the call fails and all gas is
/// consumed. The infallible precompiles just return `(gas, output)`.
pub type PrecompileResult = (u64, Result<Vec<u8>, ()>);

/// 0x02 — SHA-256. Output is the 32-byte digest.
pub fn sha256(input: &[u8]) -> (u64, Vec<u8>) {
    let gas = cost::SHA256_BASE + word_cost(input.len() as u64, cost::SHA256_WORD);
    (gas, Sha256::digest(input).to_vec())
}

/// 0x03 — RIPEMD-160. The 20-byte digest is left-padded to a 32-byte word.
pub fn ripemd160(input: &[u8]) -> (u64, Vec<u8>) {
    let gas = cost::RIPEMD160_BASE + word_cost(input.len() as u64, cost::RIPEMD160_WORD);
    let digest = Ripemd160::digest(input);
    let mut out = vec![0u8; 32];
    out[12..].copy_from_slice(&digest);
    (gas, out)
}

/// 0x04 — identity: return the input verbatim.
pub fn identity(input: &[u8]) -> (u64, Vec<u8>) {
    let gas = cost::IDENTITY_BASE + word_cost(input.len() as u64, cost::IDENTITY_WORD);
    (gas, input.to_vec())
}

/// Address recovered from a signature, as a 32-byte left-padded word — the
/// shared tail of [`ecrecover`] and, later, other signature checks.
fn address_word(pubkey_uncompressed: &[u8; 65]) -> Vec<u8> {
    // Drop the 0x04 tag byte; hash the 64-byte public key; take the low 20.
    let digest = keccak256(&pubkey_uncompressed[1..]);
    let mut out = vec![0u8; 32];
    out[12..].copy_from_slice(&digest.as_bytes()[12..]);
    out
}

/// 0x01 — ecrecover. Input is right-padded to 128 bytes: `hash | v | r | s`,
/// each a 32-byte word, where `v` is 27 or 28. On any malformed field or
/// unrecoverable signature the output is empty and the *call still succeeds*
/// (a soft failure, per the yellow paper). The fee is flat.
pub fn ecrecover(input: &[u8]) -> (u64, Vec<u8>) {
    use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
    use secp256k1::{Message, Secp256k1};

    let gas = cost::ECRECOVER;

    let mut buf = [0u8; 128];
    let n = input.len().min(128);
    buf[..n].copy_from_slice(&input[..n]);
    let (hash, rest) = buf.split_at(32);
    let (v, rs) = rest.split_at(32);
    let (r, s) = rs.split_at(32);

    // v is a full word holding 27 or 28.
    if v[..31].iter().any(|&b| b != 0) || (v[31] != 27 && v[31] != 28) {
        return (gas, Vec::new());
    }

    let recover = || -> Option<[u8; 65]> {
        let message = Message::from_digest_slice(hash).ok()?;
        let recovery_id = RecoveryId::from_i32((v[31] - 27) as i32).ok()?;
        let mut compact = [0u8; 64];
        compact[..32].copy_from_slice(r);
        compact[32..].copy_from_slice(s);
        let signature = RecoverableSignature::from_compact(&compact, recovery_id).ok()?;
        let pubkey = Secp256k1::new().recover_ecdsa(&message, &signature).ok()?;
        Some(pubkey.serialize_uncompressed())
    };

    match recover() {
        Some(pubkey) => (gas, address_word(&pubkey)),
        None => (gas, Vec::new()),
    }
}

/// Parse modexp's three 32-byte length headers, each saturated into `usize`.
fn modexp_lengths(input: &[u8]) -> (usize, usize, usize) {
    let header = |offset: usize| -> usize {
        (0..32).fold(0usize, |acc, k| {
            let byte = input.get(offset.saturating_add(k)).copied().unwrap_or(0);
            acc.saturating_mul(256).saturating_add(byte as usize)
        })
    };
    (header(0), header(32), header(64))
}

/// EIP-2565 gas — computed from the header and only the exponent's leading
/// bytes, so it never allocates the (possibly enormous) declared operands.
/// Charging this *before* [`modexp`] runs is what stops a hostile length from
/// forcing a huge allocation ahead of the caller's out-of-gas check.
pub fn modexp_gas(input: &[u8]) -> u64 {
    let (base_len, exp_len, mod_len) = modexp_lengths(input);

    // The leading up-to-32 bytes of the exponent, read straight from input.
    let exp_start = 96usize.saturating_add(base_len);
    let head_len = exp_len.min(32);
    let mut head = [0u8; 32];
    for (k, slot) in head.iter_mut().take(head_len).enumerate() {
        *slot = input.get(exp_start.saturating_add(k)).copied().unwrap_or(0);
    }

    let words = (base_len.max(mod_len) as u64).div_ceil(8);
    let mult_complexity = words.saturating_mul(words);
    let iterations = iteration_count(exp_len, &head[..head_len]);
    (mult_complexity.saturating_mul(iterations) / 3).max(cost::MODEXP_MIN)
}

/// 0x05 — modular exponentiation `base**exp mod modulus` (EIP-198), priced by
/// EIP-2565. Always succeeds; the result is `mod_len` bytes, big-endian,
/// left-padded. A zero modulus yields all-zero output.
pub fn modexp(input: &[u8]) -> (u64, Vec<u8>) {
    use num_bigint::BigUint;

    let gas = modexp_gas(input);
    let (base_len, exp_len, mod_len) = modexp_lengths(input);
    if mod_len == 0 {
        return (gas, Vec::new());
    }

    // A big-endian slice, zero-padded on the right if the input is truncated.
    let slice = |start: usize, len: usize| -> Vec<u8> {
        (0..len)
            .map(|k| input.get(start.saturating_add(k)).copied().unwrap_or(0))
            .collect()
    };
    let base = slice(96, base_len);
    let exp = slice(96usize.saturating_add(base_len), exp_len);
    let modulus = slice(
        96usize.saturating_add(base_len).saturating_add(exp_len),
        mod_len,
    );

    let modulus = BigUint::from_bytes_be(&modulus);
    let result = if modulus.bits() == 0 {
        BigUint::from(0u32)
    } else {
        BigUint::from_bytes_be(&base).modpow(&BigUint::from_bytes_be(&exp), &modulus)
    };

    // Right-align the big-endian result into a `mod_len`-wide field.
    let raw = result.to_bytes_be();
    let mut out = vec![0u8; mod_len];
    let tail = raw.len().min(mod_len);
    out[mod_len - tail..].copy_from_slice(&raw[raw.len() - tail..]);
    (gas, out)
}

/// The EIP-2565 iteration count from the exponent length and its leading
/// (up-to-32) bytes: eight bits for every byte past the leading 32, plus the
/// index of the most significant set bit within them. Floored at one — this
/// reads the *high* bytes, matching client behaviour rather than the
/// `& (2**256-1)` in the EIP's prose.
fn iteration_count(exp_len: usize, head: &[u8]) -> u64 {
    use num_bigint::BigUint;

    let head_bits = BigUint::from_bytes_be(head).bits();
    let msb = head_bits.saturating_sub(1);
    let count = if exp_len <= 32 {
        msb
    } else {
        8 * (exp_len as u64 - 32) + msb
    };
    count.max(1)
}

// --- bn256 (alt_bn128) curve precompiles, EIP-196/197 --------------------
//
// These delegate the elliptic-curve arithmetic and the optimal-ate pairing
// to `substrate-bn`. Unlike the precompiles above they can *hard-fail*: a
// coordinate that is not a canonical field element, or a point off the curve,
// makes the call fail with all gas consumed (signalled by `Err(())`).

use substrate_bn::{AffineG1, AffineG2, Fq, Fq2, Fr, Group, Gt, G1, G2};

/// Parse a G1 point from 64 bytes (`x || y`). All-zero is the point at
/// infinity; anything else must be a canonical, on-curve point.
fn parse_g1(bytes: &[u8]) -> Option<G1> {
    if bytes.iter().all(|&b| b == 0) {
        return Some(G1::zero());
    }
    let x = Fq::from_slice(&bytes[0..32]).ok()?;
    let y = Fq::from_slice(&bytes[32..64]).ok()?;
    AffineG1::new(x, y).ok().map(Into::into)
}

/// Parse a G2 point from 128 bytes. Per EIP-197 each Fq2 coordinate arrives
/// imaginary-part first: `x_i || x_r || y_i || y_r`.
fn parse_g2(bytes: &[u8]) -> Option<G2> {
    if bytes.iter().all(|&b| b == 0) {
        return Some(G2::zero());
    }
    let x_i = Fq::from_slice(&bytes[0..32]).ok()?;
    let x_r = Fq::from_slice(&bytes[32..64]).ok()?;
    let y_i = Fq::from_slice(&bytes[64..96]).ok()?;
    let y_r = Fq::from_slice(&bytes[96..128]).ok()?;
    let x = Fq2::new(x_r, x_i);
    let y = Fq2::new(y_r, y_i);
    AffineG2::new(x, y).ok().map(Into::into)
}

/// Serialise a G1 point to 64 bytes; the point at infinity is all zeros.
fn encode_g1(point: G1) -> Vec<u8> {
    let mut out = vec![0u8; 64];
    if let Some(affine) = AffineG1::from_jacobian(point) {
        affine.x().to_big_endian(&mut out[0..32]).unwrap();
        affine.y().to_big_endian(&mut out[32..64]).unwrap();
    }
    out
}

/// Right-pad the input to `len` bytes so short calldata reads as zeros.
fn padded<const N: usize>(input: &[u8]) -> [u8; N] {
    let mut buf = [0u8; N];
    let n = input.len().min(N);
    buf[..n].copy_from_slice(&input[..n]);
    buf
}

/// 0x06 — bn256 point addition (EIP-196).
pub fn bn_add(input: &[u8]) -> PrecompileResult {
    let buf = padded::<128>(input);
    let out = (|| {
        let p = parse_g1(&buf[0..64])?;
        let q = parse_g1(&buf[64..128])?;
        Some(encode_g1(p + q))
    })();
    (cost::BN_ADD, out.ok_or(()))
}

/// 0x07 — bn256 scalar multiplication (EIP-196).
pub fn bn_mul(input: &[u8]) -> PrecompileResult {
    let buf = padded::<96>(input);
    let out = (|| {
        let p = parse_g1(&buf[0..64])?;
        let scalar = Fr::from_slice(&buf[64..96]).ok()?;
        Some(encode_g1(p * scalar))
    })();
    (cost::BN_MUL, out.ok_or(()))
}

/// 0x08 — bn256 pairing check (EIP-197). Input is `k` chunks of 192 bytes,
/// each a (G1, G2) pair; the result is 1 iff the product of pairings is the
/// identity. An empty input yields 1. A non-multiple-of-192 length fails.
pub fn bn_pairing(input: &[u8]) -> PrecompileResult {
    let k = input.len() / 192;
    let gas = cost::BN_PAIRING_BASE + cost::BN_PAIRING_PER_PAIR * k as u64;
    if input.len() % 192 != 0 {
        return (gas, Err(()));
    }
    let out = (|| {
        let mut pairs = Vec::with_capacity(k);
        for chunk in input.chunks_exact(192) {
            pairs.push((parse_g1(&chunk[0..64])?, parse_g2(&chunk[64..192])?));
        }
        let identity = substrate_bn::pairing_batch(&pairs) == Gt::one();
        let mut word = vec![0u8; 32];
        word[31] = identity as u8;
        Some(word)
    })();
    (gas, out.ok_or(()))
}

// --- blake2f compression precompile, EIP-152 -----------------------------
//
// Unlike the curve precompiles this is hand-written: the BLAKE2b `F`
// compression is a fully specified permutation (RFC 7693), not key-handling
// cryptography, so implementing it directly is reasonable and keeps the
// arbitrary-round variant EIP-152 needs. Input is a fixed 213-byte frame;
// a wrong length or an out-of-range final-block flag hard-fails the call.

/// 0x09 — the BLAKE2b `F` compression (EIP-152). Gas is one per round.
pub fn blake2f(input: &[u8]) -> PrecompileResult {
    if input.len() != 213 {
        return (0, Err(()));
    }
    let rounds = u32::from_be_bytes(input[0..4].try_into().unwrap());
    let gas = rounds as u64; // GFROUND = 1

    let flag = input[212];
    if flag > 1 {
        return (gas, Err(()));
    }

    let mut h = [0u64; 8];
    for (word, chunk) in h.iter_mut().zip(input[4..68].chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    let mut m = [0u64; 16];
    for (word, chunk) in m.iter_mut().zip(input[68..196].chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    let t = [
        u64::from_le_bytes(input[196..204].try_into().unwrap()),
        u64::from_le_bytes(input[204..212].try_into().unwrap()),
    ];

    blake2b_f(&mut h, &m, t, flag == 1, rounds);

    let mut out = vec![0u8; 64];
    for (chunk, word) in out.chunks_exact_mut(8).zip(h) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    (gas, Ok(out))
}

/// The compression itself: mix the 16-word working vector `rounds` times and
/// fold it back into the state `h`.
fn blake2b_f(h: &mut [u64; 8], m: &[u64; 16], t: [u64; 2], final_block: bool, rounds: u32) {
    const IV: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
    // The message schedule. EIP-152 allows any round count, cycling these
    // ten permutations by `round mod 10`.
    const SIGMA: [[usize; 16]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ];

    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t[0];
    v[13] ^= t[1];
    if final_block {
        v[14] ^= u64::MAX;
    }

    for round in 0..rounds as usize {
        let s = &SIGMA[round % 10];
        mix(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        mix(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        mix(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        mix(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        mix(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        mix(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        mix(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        mix(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for (i, hi) in h.iter_mut().enumerate() {
        *hi ^= v[i] ^ v[i + 8];
    }
}

/// The BLAKE2b `G` mixing function on four words of the working vector.
#[allow(clippy::too_many_arguments)]
fn mix(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256(b""),
            (
                60,
                h("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            )
        );
        // "abc" is one word: base 60 + one 12-gas word.
        assert_eq!(
            sha256(b"abc"),
            (
                72,
                h("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            )
        );
    }

    #[test]
    fn ripemd160_is_left_padded_to_a_word() {
        assert_eq!(
            ripemd160(b""),
            (
                600,
                h("0000000000000000000000009c1185a5c5e9fc54612808977ee8f548b2258d31")
            )
        );
        assert_eq!(
            ripemd160(b"abc"),
            (
                720,
                h("0000000000000000000000008eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
            )
        );
    }

    #[test]
    fn identity_returns_input_and_charges_per_word() {
        let (gas, out) = identity(b"abcd");
        assert_eq!(out, b"abcd");
        assert_eq!(gas, 18); // 15 + one word
    }

    #[test]
    fn modexp_small_case() {
        // 3^2 mod 5 = 4, in a one-byte modulus field.
        let mut input = Vec::new();
        input.extend_from_slice(&[0u8; 31]);
        input.push(1); // base_len = 1
        input.extend_from_slice(&[0u8; 31]);
        input.push(1); // exp_len = 1
        input.extend_from_slice(&[0u8; 31]);
        input.push(1); // mod_len = 1
        input.push(3); // base
        input.push(2); // exp
        input.push(5); // modulus
        let (_, out) = modexp(&input);
        assert_eq!(out, vec![4]);
    }

    #[test]
    fn modexp_zero_modulus_is_zero() {
        // mod_len = 1, modulus = 0 -> output is a zero byte, no panic.
        let mut input = vec![0u8; 96];
        input[31] = 1; // base_len
        input[63] = 1; // exp_len
        input[95] = 1; // mod_len
        input.extend_from_slice(&[7, 3, 0]); // base=7, exp=3, mod=0
        let (_, out) = modexp(&input);
        assert_eq!(out, vec![0]);
    }

    #[test]
    fn bn_add_rejects_point_off_curve() {
        // (1, 1) does not satisfy y^2 = x^3 + 3, so the call must hard-fail.
        let mut input = vec![0u8; 128];
        input[31] = 1; // x1 = 1
        input[63] = 1; // y1 = 1
        assert!(bn_add(&input).1.is_err());
    }

    #[test]
    fn bn_pairing_empty_input_is_identity() {
        // No pairs: the empty product is the identity, so the result is 1.
        let (gas, out) = bn_pairing(&[]);
        assert_eq!(gas, 45_000);
        let mut expected = vec![0u8; 32];
        expected[31] = 1;
        assert_eq!(out.unwrap(), expected);
    }

    #[test]
    fn bn_pairing_rejects_ragged_length() {
        // 100 bytes is not a whole number of 192-byte pairs.
        assert!(bn_pairing(&[0u8; 100]).1.is_err());
    }

    #[test]
    fn blake2f_rejects_wrong_length() {
        assert!(blake2f(&[0u8; 212]).1.is_err());
        assert!(blake2f(&[0u8; 214]).1.is_err());
    }

    #[test]
    fn blake2f_rejects_out_of_range_flag() {
        let mut input = vec![0u8; 213];
        input[212] = 2; // the final-block flag must be 0 or 1
        assert!(blake2f(&input).1.is_err());
    }
}

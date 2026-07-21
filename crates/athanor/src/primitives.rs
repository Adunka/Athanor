//! Fixed-width types, hashing, and address derivation.
//!
//! The word and hash types are instantiated here from the `uint` and
//! `fixed-hash` macros (the same backend OpenEthereum ran on for years)
//! rather than re-exported from a wrapper crate: the dependency tree stays
//! flat, and the types being local means inherent impls and trait impls
//! belong to this crate. Everything protocol-specific — RLP for `CREATE`,
//! the 0xff preimage for `CREATE2` — is written out in full so the
//! derivation rules are visible, not buried in a dependency.

// The parity macros trip a few style lints inside their own expansion;
// scoped here so the rest of the crate still lints clean.
#![allow(clippy::assign_op_pattern, clippy::non_canonical_clone_impl)]

use fixed_hash::construct_fixed_hash;
use tiny_keccak::{Hasher, Keccak};
use uint::construct_uint;

construct_uint! {
    /// 256-bit EVM word.
    pub struct U256(4);
}

construct_uint! {
    /// Double-width intermediate for `ADDMOD`/`MULMOD`, which are defined
    /// over the full sum/product before reduction — the Yellow Paper is
    /// explicit that the intermediate is *not* taken mod 2^256.
    pub struct U512(8);
}

impl U256 {
    pub fn to_u512(self) -> U512 {
        let mut bytes = [0u8; 64];
        self.to_big_endian(&mut bytes[32..]);
        U512::from_big_endian(&bytes)
    }
}

impl U512 {
    /// Low 256 bits. Callers guarantee the value fits (a residue mod a
    /// 256-bit modulus always does).
    pub fn low_u256(self) -> U256 {
        let mut bytes = [0u8; 64];
        self.to_big_endian(&mut bytes);
        U256::from_big_endian(&bytes[32..])
    }
}

construct_fixed_hash! {
    /// 160-bit account address.
    pub struct H160(20);
}

construct_fixed_hash! {
    /// 256-bit hash.
    pub struct H256(32);
}

impl H160 {
    /// Address with `v` in the low 8 bytes. Test fixtures and precompile
    /// addresses, mostly.
    pub fn from_low_u64_be(v: u64) -> Self {
        let mut bytes = [0u8; 20];
        bytes[12..].copy_from_slice(&v.to_be_bytes());
        H160(bytes)
    }
}

impl H256 {
    pub fn from_low_u64_be(v: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&v.to_be_bytes());
        H256(bytes)
    }
}

pub type Address = H160;
pub type B256 = H256;

/// keccak256 of the empty string. Canonical "no code" hash (EIP-161).
pub const KECCAK_EMPTY: B256 = H256([
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
]);

pub fn keccak256(data: &[u8]) -> B256 {
    let mut out = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(data);
    k.finalize(&mut out);
    H256(out)
}

/// Contract address for `CREATE`: `keccak256(rlp([sender, nonce]))[12..]`
/// (YP eq. 85). The RLP here is a two-item list whose payload is always
/// short (21 + ≤9 bytes), so the encoding is done by hand rather than
/// pulling in an RLP crate for one fixed shape.
pub fn create_address(sender: Address, nonce: u64) -> Address {
    let mut payload = Vec::with_capacity(30);
    payload.push(0x80 + 20);
    payload.extend_from_slice(sender.as_bytes());
    rlp_append_u64(&mut payload, nonce);

    let mut enc = Vec::with_capacity(31);
    enc.push(0xc0 + payload.len() as u8);
    enc.extend_from_slice(&payload);

    Address::from_slice(&keccak256(&enc)[12..])
}

/// Contract address for `CREATE2` (EIP-1014):
/// `keccak256(0xff ++ sender ++ salt ++ keccak256(init_code))[12..]`.
pub fn create2_address(sender: Address, salt: B256, init_code_hash: B256) -> Address {
    let mut buf = [0u8; 85];
    buf[0] = 0xff;
    buf[1..21].copy_from_slice(sender.as_bytes());
    buf[21..53].copy_from_slice(salt.as_bytes());
    buf[53..85].copy_from_slice(init_code_hash.as_bytes());
    Address::from_slice(&keccak256(&buf)[12..])
}

/// Minimal RLP integer encoding: big-endian, no leading zeros, single bytes
/// below 0x80 encode as themselves.
fn rlp_append_u64(out: &mut Vec<u8>, v: u64) {
    if v == 0 {
        out.push(0x80);
    } else if v < 0x80 {
        out.push(v as u8);
    } else {
        let be = v.to_be_bytes();
        let skip = be.iter().position(|&b| b != 0).unwrap();
        out.push(0x80 + (8 - skip) as u8);
        out.extend_from_slice(&be[skip..]);
    }
}

pub fn u256_to_be(v: U256) -> [u8; 32] {
    let mut buf = [0u8; 32];
    v.to_big_endian(&mut buf);
    buf
}

pub fn u256_to_h256(v: U256) -> B256 {
    H256(u256_to_be(v))
}

pub fn h256_to_u256(h: B256) -> U256 {
    U256::from_big_endian(h.as_bytes())
}

/// Truncate to the low 20 bytes, as `CALL`-family instructions do with
/// their address operand.
pub fn u256_to_address(v: U256) -> Address {
    Address::from_slice(&u256_to_be(v)[12..])
}

pub fn address_to_u256(a: Address) -> U256 {
    U256::from_big_endian(a.as_bytes())
}

/// `usize` view of a U256 when it fits, `None` otherwise. Offsets that
/// don't fit are only ever observed together with a nonzero length, where
/// gas accounting rejects them anyway — but the conversion must not panic.
pub fn as_usize_checked(v: U256) -> Option<usize> {
    if v.bits() > usize::BITS as usize {
        None
    } else {
        Some(v.as_usize())
    }
}

/// Saturating u64 view. Used where the spec clamps rather than fails,
/// e.g. the gas operand of `CALL`.
pub fn as_u64_saturated(v: U256) -> u64 {
    if v.bits() > 64 {
        u64::MAX
    } else {
        v.as_u64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> Address {
        Address::from_slice(&hex::decode(s).unwrap())
    }

    fn h256(s: &str) -> B256 {
        H256::from_slice(&hex::decode(s).unwrap())
    }

    #[test]
    fn keccak_known_vectors() {
        assert_eq!(keccak256(b""), KECCAK_EMPTY);
        assert_eq!(
            keccak256(b"abc"),
            h256("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
        );
    }

    #[test]
    fn create_address_canonical_vector() {
        // The example everyone has verified a hundred times over:
        // sender 0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0, nonces 0..3.
        let sender = addr("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0");
        for (nonce, expect) in [
            (0u64, "cd234a471b72ba2f1ccf0a70fcaba648a5eecd8d"),
            (1, "343c43a37d37dff08ae8c4a11544c718abb4fcf8"),
            (2, "f778b86fa74e846c4f0a1fbd1335fe81c00a0c91"),
            (3, "fffd933a0bc612844eaf0c6fe3e5b8e9b6c1d19c"),
        ] {
            assert_eq!(create_address(sender, nonce), addr(expect));
        }
    }

    #[test]
    fn create2_eip1014_vectors() {
        // Examples 0, 4, 5 and 6 from the EIP-1014 text.
        let cases: &[(&str, &str, &str, &str)] = &[
            (
                "0000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "00",
                "4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38",
            ),
            (
                "00000000000000000000000000000000deadbeef",
                "00000000000000000000000000000000000000000000000000000000cafebabe",
                "deadbeef",
                "60f3f640a8508fc6a86d45df051962668e1e8ac7",
            ),
            (
                "00000000000000000000000000000000deadbeef",
                "00000000000000000000000000000000000000000000000000000000cafebabe",
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\
                 deadbeefdeadbeefdeadbeef",
                "1d8bfdc5d46dc4f61d6b6115972536ebe6a8854c",
            ),
            (
                "0000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "",
                "e33c0c7f7df4809055c3eba6c09cfe4baf1bd9e0",
            ),
        ];
        for &(sender, salt, init_code, expect) in cases {
            let got = create2_address(
                addr(sender),
                h256(salt),
                keccak256(&hex::decode(init_code).unwrap()),
            );
            assert_eq!(got, addr(expect), "sender {sender}, init {init_code}");
        }
    }

    #[test]
    fn rlp_u64_boundaries() {
        let enc = |v| {
            let mut b = Vec::new();
            rlp_append_u64(&mut b, v);
            b
        };
        assert_eq!(enc(0), [0x80]);
        assert_eq!(enc(1), [0x01]);
        assert_eq!(enc(0x7f), [0x7f]);
        assert_eq!(enc(0x80), [0x81, 0x80]);
        assert_eq!(enc(0x0100), [0x82, 0x01, 0x00]);
        assert_eq!(
            enc(u64::MAX),
            [0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn address_truncation() {
        let v = U256::from_big_endian(&[0xff; 32]);
        assert_eq!(u256_to_address(v), Address::from_slice(&[0xff; 20]));
        assert_eq!(address_to_u256(Address::from_low_u64_be(7)), U256::from(7));
    }
}

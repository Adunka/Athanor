//! Real Ethereum state and storage roots, computed through the trie.
//!
//! The world state is a *secure* Merkle Patricia Trie: the key of each
//! account is `keccak256(address)` and its value is the RLP of
//! `[nonce, balance, storageRoot, codeHash]`. Each account's `storageRoot`
//! is itself a secure trie over its slots, keyed by `keccak256(slot)` with
//! the RLP of the slot's value. This module turns a [`JournaledState`]'s
//! accounts into that structure and reads off the 32-byte root — the same
//! commitment Ethereum consensus checks.
//!
//! [`JournaledState`]: crate::state::JournaledState

use std::collections::HashMap;

use athanor_trie::rlp::{encode_bytes, encode_list};
use athanor_trie::Trie;

use crate::primitives::{keccak256, Address, B256, KECCAK_EMPTY, U256};
use crate::state::Account;

/// RLP of an integer as Ethereum encodes it: the shortest big-endian byte
/// string with no leading zeros, so zero is the empty string (`0x80`).
fn rlp_u256(value: U256) -> Vec<u8> {
    let mut be = [0u8; 32];
    value.to_big_endian(&mut be);
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    encode_bytes(&be[start..])
}

fn rlp_u64(value: u64) -> Vec<u8> {
    let be = value.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    encode_bytes(&be[start..])
}

/// Storage root for a single account: a secure trie over its non-zero
/// slots. A slot set to zero is a deletion, never an entry, so an account
/// with no live storage hashes to the empty-trie root automatically.
pub fn storage_root(storage: &HashMap<U256, U256>) -> B256 {
    let mut trie = Trie::new();
    for (&slot, &value) in storage {
        if value.is_zero() {
            continue;
        }
        let mut slot_be = [0u8; 32];
        slot.to_big_endian(&mut slot_be);
        trie.insert(keccak256(&slot_be).as_bytes(), &rlp_u256(value));
    }
    B256::from(trie.root_hash())
}

/// RLP of an account leaf: `[nonce, balance, storageRoot, codeHash]`.
pub fn account_rlp(account: &Account) -> Vec<u8> {
    let storage = storage_root(&account.storage);
    let code_hash = if account.code.is_empty() {
        KECCAK_EMPTY
    } else {
        account.code.hash()
    };
    encode_list(&[
        rlp_u64(account.nonce),
        rlp_u256(account.balance),
        encode_bytes(storage.as_bytes()),
        encode_bytes(code_hash.as_bytes()),
    ])
}

/// State root over a set of accounts. Empty accounts (EIP-161: zero nonce,
/// zero balance, no code) are not part of the trie, matching how post-state
/// fixtures omit them.
pub fn state_root<'a>(accounts: impl IntoIterator<Item = (&'a Address, &'a Account)>) -> B256 {
    let mut trie = Trie::new();
    for (address, account) in accounts {
        if account.is_empty() {
            continue;
        }
        trie.insert(
            keccak256(address.as_bytes()).as_bytes(),
            &account_rlp(account),
        );
    }
    B256::from(trie.root_hash())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::Bytecode;

    fn account(nonce: u64, balance: u64) -> Account {
        Account {
            nonce,
            balance: U256::from(balance),
            ..Default::default()
        }
    }

    #[test]
    fn empty_state_is_the_empty_root() {
        let empty: HashMap<Address, Account> = HashMap::new();
        assert_eq!(
            hex::encode(state_root(empty.iter())),
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
    }

    #[test]
    fn empty_storage_hashes_to_empty_root() {
        // No live slots -> the empty-trie root, exactly as an EOA's storage
        // root is required to be.
        assert_eq!(
            hex::encode(storage_root(&HashMap::new())),
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
    }

    #[test]
    fn account_rlp_has_the_expected_shape() {
        // A fresh EOA with nonce 1 and balance 1000: a four-item list whose
        // storage root and code hash are the empty-trie root and the empty
        // code hash respectively.
        let acct = account(1, 1000);
        let encoded = account_rlp(&acct);
        let decoded = athanor_trie::rlp::decode(&encoded).unwrap();
        let items = decoded.as_list().expect("account is a list");
        assert_eq!(items.len(), 4);
        assert_eq!(items[0].as_bytes().unwrap(), &[0x01]); // nonce
        assert_eq!(items[1].as_bytes().unwrap(), &[0x03, 0xe8]); // balance 1000 = 0x03e8
        assert_eq!(items[2].as_bytes().unwrap(), KECCAK_EMPTY_STORAGE);
        assert_eq!(items[3].as_bytes().unwrap(), KECCAK_EMPTY.as_bytes());
    }

    const KECCAK_EMPTY_STORAGE: &[u8] = &[
        0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8,
        0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63,
        0xb4, 0x21,
    ];

    #[test]
    fn order_independent_and_pruning_is_reversible() {
        let mut a = account(2, 500);
        a.storage.insert(U256::from(7u64), U256::from(9u64));
        let mut contract = Account {
            nonce: 1,
            balance: U256::from(42u64),
            code: Bytecode::new(vec![0x60, 0x00]),
            ..Default::default()
        };
        contract.storage.insert(U256::from(1u64), U256::from(2u64));

        let addr_a = Address::from_low_u64_be(0xa);
        let addr_b = Address::from_low_u64_be(0xb);

        let forward: HashMap<_, _> = [(addr_a, a.clone()), (addr_b, contract.clone())].into();
        let backward: HashMap<_, _> = [(addr_b, contract), (addr_a, a)].into();
        // Insertion order must not move the root.
        assert_eq!(state_root(forward.iter()), state_root(backward.iter()));

        // Adding then dropping an account returns to the original root.
        let base = state_root(forward.iter());
        let mut extended = forward.clone();
        extended.insert(Address::from_low_u64_be(0xc), account(1, 1));
        assert_ne!(state_root(extended.iter()), base);
        extended.remove(&Address::from_low_u64_be(0xc));
        assert_eq!(state_root(extended.iter()), base);
    }
}

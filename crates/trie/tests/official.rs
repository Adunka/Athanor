//! Conformance against Ethereum's official `TrieTests`.
//!
//! The JSON fixtures in `tests/fixtures/` are copied verbatim from
//! `ethereum/tests`. Each case is a sequence of key/value operations (a
//! `null` value is a deletion) and the root hash the trie must produce once
//! they are applied. Running our implementation against these — rather than
//! against roots we computed ourselves — is what makes "Ethereum-compatible"
//! a checked claim instead of an assertion.
//!
//! Keys and values follow the `ethereum/tests` convention: a `0x` prefix
//! means hex, anything else is the literal ASCII bytes.

use athanor_trie::Trie;
use serde_json::Value;

fn decode(s: &str) -> Vec<u8> {
    match s.strip_prefix("0x") {
        Some(hex) => hex::decode(hex).expect("valid hex in fixture"),
        None => s.as_bytes().to_vec(),
    }
}

/// Apply an ordered list of operations and check the resulting root.
fn check(name: &str, ops: Vec<(String, Option<String>)>, expected: &str) {
    let mut trie = Trie::new();
    for (key, value) in ops {
        let key = decode(&key);
        match value {
            Some(v) => trie.insert(&key, &decode(&v)),
            None => trie.remove(&key),
        }
    }
    let got = format!("0x{}", hex::encode(trie.root_hash()));
    assert_eq!(got, expected, "root mismatch for case `{name}`");
}

#[test]
fn trietest_ordered_cases() {
    // Ordered operations: `"in"` is a list of [key, value] pairs, applied
    // in sequence, with deletions interleaved.
    let data: Value = serde_json::from_str(include_str!("fixtures/trietest.json")).unwrap();
    let cases = data.as_object().unwrap();
    for (name, case) in cases {
        let ops = case["in"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| {
                let pair = pair.as_array().unwrap();
                let key = pair[0].as_str().unwrap().to_string();
                let value = pair[1].as_str().map(str::to_string); // null -> None
                (key, value)
            })
            .collect();
        check(name, ops, case["root"].as_str().unwrap());
    }
    assert!(cases.len() >= 5, "expected the full ordered-test set");
}

#[test]
fn trieanyorder_cases() {
    // Order-independent: `"in"` is a map. The whole point of these is that
    // insertion order must not affect the root.
    let data: Value = serde_json::from_str(include_str!("fixtures/trieanyorder.json")).unwrap();
    let cases = data.as_object().unwrap();
    for (name, case) in cases {
        let ops = case["in"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), value.as_str().map(str::to_string)))
            .collect();
        check(name, ops, case["root"].as_str().unwrap());
    }
    assert!(cases.len() >= 7, "expected the full any-order test set");
}

#[test]
fn secure_trie_cases() {
    // The state trie is a *secure* trie: keys are keccak-hashed before
    // insertion. These official vectors pin exactly the "hash the key, then
    // build the trie" mechanism that account and storage roots rely on.
    let data: Value =
        serde_json::from_str(include_str!("fixtures/trietest_secureTrie.json")).unwrap();
    let cases = data.as_object().unwrap();
    for (name, case) in cases {
        let mut trie = Trie::new();
        for pair in case["in"].as_array().unwrap() {
            let pair = pair.as_array().unwrap();
            let key = athanor_trie::node::keccak256(&decode(pair[0].as_str().unwrap()));
            match pair[1].as_str() {
                Some(value) => trie.insert(&key, &decode(value)),
                None => trie.remove(&key),
            }
        }
        let got = format!("0x{}", hex::encode(trie.root_hash()));
        assert_eq!(
            got,
            case["root"].as_str().unwrap(),
            "secure-trie case `{name}`"
        );
    }
    assert!(cases.len() >= 3);
}

#[test]
fn insertion_order_is_irrelevant() {
    // Independently of the fixtures: the same key set in two different
    // orders is the same trie. This is the invariant the any-order fixtures
    // exist to pin, checked here directly.
    let pairs: &[(&[u8], &[u8])] = &[
        (b"do", b"verb"),
        (b"dog", b"puppy"),
        (b"doge", b"coin"),
        (b"horse", b"stallion"),
    ];

    let mut forward = Trie::new();
    for (k, v) in pairs {
        forward.insert(k, v);
    }
    let mut backward = Trie::new();
    for (k, v) in pairs.iter().rev() {
        backward.insert(k, v);
    }
    assert_eq!(forward.root_hash(), backward.root_hash());
}

//! Precompiles checked against go-ethereum's own test vectors.
//!
//! Each vector pins an input to an expected output *and* an expected gas
//! cost, so these exercise the pricing as sharply as the arithmetic — a
//! modexp gas formula off by a word, or an ecrecover that charged the wrong
//! flat fee, would fail here. The `ecrecover` set in particular covers the
//! soft-failure paths (unrecoverable key, malformed `v`) where the output is
//! empty but the call still succeeds.
//!
//! Vectors: `core/vm/testdata/precompiles/` in go-ethereum (modexp uses the
//! EIP-2565 gas schedule, which is what Cancun charges).

use athanor::precompile::{self, PrecompileResult};
use serde_json::Value;

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).expect("valid hex")
}

fn check(json: &str, run: fn(&[u8]) -> (u64, Vec<u8>)) {
    let vectors: Value = serde_json::from_str(json).unwrap();
    for vector in vectors.as_array().unwrap() {
        let name = vector["Name"].as_str().unwrap();
        let input = hex(vector["Input"].as_str().unwrap());
        let (gas, output) = run(&input);
        assert_eq!(
            output,
            hex(vector["Expected"].as_str().unwrap()),
            "output mismatch on {name}"
        );
        assert_eq!(
            gas,
            vector["Gas"].as_u64().unwrap(),
            "gas mismatch on {name}"
        );
    }
}

#[test]
fn ecrecover_vectors() {
    check(
        include_str!("fixtures/precompiles/ecrecover.json"),
        precompile::ecrecover,
    );
}

#[test]
fn modexp_vectors() {
    check(
        include_str!("fixtures/precompiles/modexp.json"),
        precompile::modexp,
    );
}

/// Like [`check`], but for the bn256 precompiles, which return a `Result`
/// because malformed input hard-fails. Every go-ethereum vector here is a
/// valid case, so a failure is itself a test failure.
fn check_fallible(json: &str, run: fn(&[u8]) -> PrecompileResult) {
    let vectors: Value = serde_json::from_str(json).unwrap();
    for vector in vectors.as_array().unwrap() {
        let name = vector["Name"].as_str().unwrap();
        let input = hex(vector["Input"].as_str().unwrap());
        let (gas, output) = run(&input);
        let Ok(output) = output else {
            panic!("{name} rejected a valid input");
        };
        assert_eq!(
            output,
            hex(vector["Expected"].as_str().unwrap()),
            "output mismatch on {name}"
        );
        assert_eq!(
            gas,
            vector["Gas"].as_u64().unwrap(),
            "gas mismatch on {name}"
        );
    }
}

#[test]
fn bn256_add_vectors() {
    check_fallible(
        include_str!("fixtures/precompiles/bn256Add.json"),
        precompile::bn_add,
    );
}

#[test]
fn bn256_scalar_mul_vectors() {
    check_fallible(
        include_str!("fixtures/precompiles/bn256ScalarMul.json"),
        precompile::bn_mul,
    );
}

#[test]
fn bn256_pairing_vectors() {
    check_fallible(
        include_str!("fixtures/precompiles/bn256Pairing.json"),
        precompile::bn_pairing,
    );
}

#[test]
fn blake2f_vectors() {
    check_fallible(
        include_str!("fixtures/precompiles/blake2F.json"),
        precompile::blake2f,
    );
}

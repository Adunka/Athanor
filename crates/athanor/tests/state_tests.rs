//! Conformance against Ethereum's official `GeneralStateTests`.
//!
//! The harness scans every fixture under `tests/fixtures/statetests/`,
//! rebuilds each case's pre-state, runs the transaction through the real
//! `Evm`, and checks the post-state root [`JournaledState::state_root`]
//! produces against Ethereum's published `hash`. That is the end-to-end
//! statement the whole trie/state effort was for: not "the pieces look
//! right" but "the machine reproduces the reference to the last wei".
//!
//! Because it scans a directory rather than hard-coding cases, the same
//! test runs the whole official suite when pointed at a full checkout —
//! just drop the fixtures in. The set committed here is a curated slice on
//! the Cancun fork (legacy and EIP-1559 fees, EIP-2930 access lists; no
//! blobs, single fork), and the harness reports how many roots matched.

use std::fs;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use athanor::{Account, Address, Bytecode, Env, Evm, B256, U256};
use serde_json::Value;

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/statetests");
const FORK: &str = "Cancun";

fn bytes(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).expect("valid hex")
}

fn u256(v: &Value) -> U256 {
    U256::from_big_endian(&bytes(v.as_str().unwrap()))
}

fn u64_of(v: &Value) -> u64 {
    bytes(v.as_str().unwrap())
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | b as u64)
}

fn address(s: &str) -> Address {
    Address::from_slice(&bytes(s))
}

fn b256(s: &str) -> B256 {
    B256::from_slice(&bytes(s))
}

/// Build a fresh `Evm` seeded with a fixture's pre-state and block env.
fn seeded_evm(test: &Value) -> Evm {
    let mut evm = Evm::new(Env::default());

    for (addr, account) in test["pre"].as_object().unwrap() {
        let mut storage = std::collections::HashMap::new();
        for (slot, value) in account["storage"].as_object().unwrap() {
            storage.insert(
                U256::from_big_endian(&bytes(slot)),
                U256::from_big_endian(&bytes(value.as_str().unwrap())),
            );
        }
        evm.journal.seed(
            address(addr),
            Account {
                balance: u256(&account["balance"]),
                nonce: u64_of(&account["nonce"]),
                code: Bytecode::new(bytes(account["code"].as_str().unwrap())),
                storage,
            },
        );
    }

    let env = &test["env"];
    evm.env.block.coinbase = address(env["currentCoinbase"].as_str().unwrap());
    evm.env.block.gas_limit = u64_of(&env["currentGasLimit"]);
    evm.env.block.number = u256(&env["currentNumber"]);
    evm.env.block.timestamp = u256(&env["currentTimestamp"]);
    evm.env.block.basefee = u256(&env["currentBaseFee"]);
    evm.env.block.prevrandao = b256(env["currentRandom"].as_str().unwrap());
    evm
}

/// Apply the transaction selected by a post entry's indexes.
fn apply_tx(evm: &mut Evm, tx: &Value, indexes: &Value) {
    let at = |key: &str| indexes[key].as_u64().unwrap() as usize;
    let di = at("data");

    evm.env.tx.caller = address(tx["sender"].as_str().unwrap());
    evm.env.tx.nonce = Some(u64_of(&tx["nonce"]));
    evm.env.tx.gas_limit = u64_of(&tx["gasLimit"][at("gas")]);
    evm.env.tx.value = u256(&tx["value"][at("value")]);
    evm.env.tx.data = bytes(tx["data"][di].as_str().unwrap());
    evm.env.tx.to = match tx["to"].as_str().unwrap() {
        "" => None,
        to => Some(address(to)),
    };

    // Effective gas price: a legacy `gasPrice`, or the EIP-1559 fee-market
    // rule min(maxFee, baseFee + maxPriority). Charging the sender this and
    // tipping the coinbase (price - baseFee) reproduces the post-state
    // balances either way.
    evm.env.tx.gas_price = match tx.get("gasPrice") {
        Some(price) => u256(price),
        None => {
            let max_fee = u256(&tx["maxFeePerGas"]);
            let max_priority = u256(&tx["maxPriorityFeePerGas"]);
            max_fee.min(evm.env.block.basefee + max_priority)
        }
    };

    // EIP-2930 access list for this data index (fixtures index it in
    // parallel with `data`).
    evm.env.tx.access_list = tx
        .get("accessLists")
        .and_then(|lists| lists.get(di))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .map(|entry| {
                    let addr = address(entry["address"].as_str().unwrap());
                    let keys = entry["storageKeys"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|k| U256::from_big_endian(&bytes(k.as_str().unwrap())))
                        .collect();
                    (addr, keys)
                })
                .collect()
        })
        .unwrap_or_default();

    // EIP-1559: a priority fee above the fee cap makes the transaction
    // invalid; the pre-state stands. (A fee cap or gas price below the base
    // fee is caught inside `transact`.)
    if tx.get("gasPrice").is_none() && u256(&tx["maxPriorityFeePerGas"]) > u256(&tx["maxFeePerGas"])
    {
        return;
    }

    // A validation failure (bad nonce, insufficient funds) leaves the
    // pre-state untouched, which is itself the asserted post-state for the
    // tests that expect rejection.
    let _ = evm.transact();
}

/// Run every post entry of one fixture case on `FORK`; returns
/// `(matched, failure_labels)`. Each case is isolated with `catch_unwind` so
/// that a fixture the harness cannot parse (e.g. a blob transaction) counts
/// as a failure rather than aborting a full-suite run.
fn run_case(name: &str, test: &Value) -> (usize, Vec<String>) {
    let Some(entries) = test["post"].get(FORK).and_then(Value::as_array) else {
        return (0, Vec::new());
    };
    let mut matched = 0;
    let mut failures = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let ok = panic::catch_unwind(AssertUnwindSafe(|| {
            // A fresh pre-state per entry: transactions must not bleed together.
            let mut evm = seeded_evm(test);
            apply_tx(&mut evm, &test["transaction"], &entry["indexes"]);
            evm.journal.state_root() == b256(entry["hash"].as_str().unwrap())
        }))
        .unwrap_or(false);
        if ok {
            matched += 1;
        } else {
            failures.push(format!("{name}[{i}]"));
        }
    }
    (matched, failures)
}

/// Collect `*.json` fixtures under `dir`, recursing into subdirectories so a
/// full checkout (which is nested by category) works as well as the flat
/// embedded set.
fn collect_json(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_json(&path, out);
        } else if path.extension().is_some_and(|e| e == "json") {
            out.push(path);
        }
    }
}

#[test]
fn general_state_tests_cancun() {
    // Point `ATHANOR_STATETESTS_DIR` at a full `GeneralStateTests` checkout to
    // run the entire suite; otherwise the embedded regression slice runs.
    let external = std::env::var("ATHANOR_STATETESTS_DIR").ok();
    let dir = external.clone().unwrap_or_else(|| FIXTURE_DIR.to_string());

    let mut files = Vec::new();
    collect_json(Path::new(&dir), &mut files);
    files.sort();
    assert!(!files.is_empty(), "no fixtures found under {dir}");

    // Over a full-suite run, unsupported fixtures panic in the parser; a
    // silent hook keeps those from burying the summary. They count as misses.
    let previous = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));

    let mut total = 0;
    let mut matched = 0;
    let mut failures = Vec::new();
    for path in &files {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        let Ok(data) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let Some(obj) = data.as_object() else {
            continue;
        };
        for (name, test) in obj {
            let (ok, fails) = run_case(name, test);
            matched += ok;
            total += ok + fails.len();
            failures.extend(fails);
        }
    }

    panic::set_hook(previous);

    eprintln!(
        "\nGeneralStateTests ({FORK}): {matched}/{total} post-state roots matched \
         across {} fixtures",
        files.len()
    );
    if !failures.is_empty() {
        // Full list to a file (a full-suite run has too many to read inline),
        // a capped preview to stderr.
        let _ = fs::write("statetests-failures.txt", failures.join("\n"));
        let shown = failures.len().min(40);
        eprintln!(
            "{} mismatched case(s) (full list in statetests-failures.txt); first {shown}:",
            failures.len()
        );
        for f in failures.iter().take(shown) {
            eprintln!("  {f}");
        }
    }

    // The embedded corpus is a regression gate and must pass entirely; an
    // external full-suite run is exploratory, so it reports without asserting.
    if external.is_none() {
        assert_eq!(
            matched,
            total,
            "{} case(s) did not match the reference root",
            total - matched
        );
    }
}

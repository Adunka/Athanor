//! Journaled world state.
//!
//! Every mutation appends an inverse operation to a journal; reverting to a
//! checkpoint replays inverses in reverse order. This gives `REVERT` and
//! exceptional halts for free at any call depth, and it is the only sane
//! way to keep the EIP-2929 warm sets, EIP-1153 transient storage and the
//! EIP-2200 "original value" bookkeeping consistent with each other — geth
//! and revm arrived at the same shape independently.
//!
//! Per-transaction substate (warm sets, transient storage, logs, the
//! created-this-tx set that EIP-6780 needs) lives here too and is cleared
//! by [`JournaledState::end_tx`].

use std::collections::{hash_map, HashMap, HashSet};

use crate::bytecode::Bytecode;
use crate::host::{AccessResult, SStoreResult, SelfDestructResult};
use crate::primitives::{Address, B256, U256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Account {
    pub balance: U256,
    pub nonce: u64,
    pub code: Bytecode,
    pub storage: HashMap<U256, U256>,
}

impl Account {
    /// EIP-161: an account is empty when it has zero balance, zero nonce
    /// and no code.
    pub fn is_empty(&self) -> bool {
        self.balance.is_zero() && self.nonce == 0 && self.code.is_empty()
    }
}

/// Inverse operations, applied newest-first on revert.
#[derive(Debug)]
enum Entry {
    /// Account did not exist before; revert removes it entirely.
    AccountCreated {
        address: Address,
    },
    /// Insertion into the created-this-transaction set (EIP-6780).
    MarkedCreated {
        address: Address,
    },
    BalanceChange {
        address: Address,
        old: U256,
    },
    NonceChange {
        address: Address,
        old: u64,
    },
    CodeChange {
        address: Address,
        old: Bytecode,
    },
    StorageChange {
        address: Address,
        key: U256,
        old: U256,
        first_write_in_tx: bool,
    },
    TransientChange {
        address: Address,
        key: U256,
        old: U256,
    },
    /// EIP-2929 warm sets *are* rolled back on revert, matching geth's
    /// journaling of access-list additions.
    AccountWarmed {
        address: Address,
    },
    SlotWarmed {
        address: Address,
        key: U256,
    },
    LogAppended,
    SelfDestructMarked {
        address: Address,
        first: bool,
    },
}

/// Source balance too small for a [`JournaledState::transfer`]; the state
/// was left untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InsufficientBalance;

#[derive(Debug, Clone, Copy)]
pub struct Checkpoint {
    journal_len: usize,
}

#[derive(Debug, Default)]
pub struct JournaledState {
    accounts: HashMap<Address, Account>,
    journal: Vec<Entry>,

    // Transaction-scoped substate.
    warm_addresses: HashSet<Address>,
    warm_slots: HashSet<(Address, U256)>,
    /// Slot values as of transaction start, recorded on first write.
    tx_original: HashMap<(Address, U256), U256>,
    transient: HashMap<(Address, U256), U256>,
    created: HashSet<Address>,
    selfdestructed: HashSet<Address>,
    logs: Vec<Log>,
}

impl JournaledState {
    pub fn new() -> Self {
        Self::default()
    }

    // --- setup (not journaled; for genesis / test fixtures) ---

    pub fn seed(&mut self, address: Address, account: Account) {
        self.accounts.insert(address, account);
    }

    pub fn account(&self, address: Address) -> Option<&Account> {
        self.accounts.get(&address)
    }

    /// Whether the account holds any nonzero storage slot — the third arm of
    /// the EIP-7610 create-collision check, alongside nonce and code.
    pub fn has_nonempty_storage(&self, address: Address) -> bool {
        self.account(address)
            .is_some_and(|acc| acc.storage.values().any(|v| !v.is_zero()))
    }

    // --- reads ---

    pub fn balance(&self, address: Address) -> U256 {
        self.accounts
            .get(&address)
            .map_or(U256::zero(), |a| a.balance)
    }

    pub fn nonce(&self, address: Address) -> u64 {
        self.accounts.get(&address).map_or(0, |a| a.nonce)
    }

    pub fn code(&self, address: Address) -> Bytecode {
        self.accounts
            .get(&address)
            .map(|a| a.code.clone())
            .unwrap_or_default()
    }

    pub fn storage(&self, address: Address, key: U256) -> U256 {
        self.accounts
            .get(&address)
            .and_then(|a| a.storage.get(&key))
            .copied()
            .unwrap_or_default()
    }

    /// EIP-161 "dead": absent or empty. Decides the `G_newaccount`
    /// surcharge for value-bearing calls and `SELFDESTRUCT`.
    pub fn is_dead(&self, address: Address) -> bool {
        match self.accounts.get(&address) {
            None => true,
            Some(account) => account.is_empty(),
        }
    }

    /// The Ethereum world-state root over the current accounts — the same
    /// 32-byte commitment consensus checks against. Empty accounts are
    /// excluded per EIP-161.
    pub fn state_root(&self) -> B256 {
        crate::trie_root::state_root(self.accounts.iter())
    }

    pub fn was_created_in_tx(&self, address: Address) -> bool {
        self.created.contains(&address)
    }

    // --- EIP-2929 temperature ---

    /// Warm an address without journaling. Transaction setup only: origin,
    /// destination, coinbase and precompiles are warm from the start and
    /// there is no checkpoint beneath them to revert to.
    pub fn prewarm_address(&mut self, address: Address) {
        self.warm_addresses.insert(address);
    }

    /// Mark a storage slot warm before execution, for an EIP-2930 access
    /// list entry. Like [`prewarm_address`], this is not journaled: the
    /// pre-warming is part of transaction setup, not an in-EVM effect that
    /// a revert could undo.
    ///
    /// [`prewarm_address`]: Self::prewarm_address
    pub fn prewarm_slot(&mut self, address: Address, key: U256) {
        self.warm_slots.insert((address, key));
    }

    /// Mark warm; returns whether it was cold. Journaled.
    pub fn warm_address(&mut self, address: Address) -> bool {
        let cold = self.warm_addresses.insert(address);
        if cold {
            self.journal.push(Entry::AccountWarmed { address });
        }
        cold
    }

    fn warm_slot(&mut self, address: Address, key: U256) -> bool {
        let cold = self.warm_slots.insert((address, key));
        if cold {
            self.journal.push(Entry::SlotWarmed { address, key });
        }
        cold
    }

    // --- journaled mutations ---

    fn account_or_create(&mut self, address: Address) -> &mut Account {
        match self.accounts.entry(address) {
            hash_map::Entry::Occupied(entry) => entry.into_mut(),
            hash_map::Entry::Vacant(entry) => {
                self.journal.push(Entry::AccountCreated { address });
                entry.insert(Account::default())
            }
        }
    }

    pub fn set_balance(&mut self, address: Address, value: U256) {
        let acc = self.account_or_create(address);
        let old = acc.balance;
        acc.balance = value;
        self.journal.push(Entry::BalanceChange { address, old });
    }

    /// Move `value` between accounts; `Err` leaves state untouched.
    pub fn transfer(
        &mut self,
        from: Address,
        to: Address,
        value: U256,
    ) -> Result<(), InsufficientBalance> {
        if value.is_zero() {
            return Ok(());
        }
        let from_balance = self.balance(from);
        if from_balance < value {
            return Err(InsufficientBalance);
        }
        self.set_balance(from, from_balance - value);
        let to_balance = self.balance(to);
        self.set_balance(to, to_balance + value);
        Ok(())
    }

    /// Bump the nonce, returning its previous value.
    pub fn inc_nonce(&mut self, address: Address) -> u64 {
        let acc = self.account_or_create(address);
        let old = acc.nonce;
        acc.nonce += 1;
        self.journal.push(Entry::NonceChange { address, old });
        old
    }

    pub fn set_code(&mut self, address: Address, code: Bytecode) {
        let acc = self.account_or_create(address);
        let old = std::mem::replace(&mut acc.code, code);
        self.journal.push(Entry::CodeChange { address, old });
    }

    /// Bring a `CREATE` target into existence: nonce 1 (EIP-161), warm
    /// (EIP-2929: the created address is added to accessed_addresses), and
    /// remembered for EIP-6780. Collision checking is the caller's job.
    pub fn create_contract_account(&mut self, address: Address) {
        self.warm_address(address);
        let acc = self.account_or_create(address);
        let old = acc.nonce;
        acc.nonce = 1;
        self.journal.push(Entry::NonceChange { address, old });
        if self.created.insert(address) {
            self.journal.push(Entry::MarkedCreated { address });
        }
    }

    // --- Host-facing accessors ---

    pub fn load_balance(&mut self, address: Address) -> AccessResult<U256> {
        let cold = self.warm_address(address);
        AccessResult {
            value: self.balance(address),
            cold,
        }
    }

    pub fn load_code(&mut self, address: Address) -> AccessResult<Bytecode> {
        let cold = self.warm_address(address);
        AccessResult {
            value: self.code(address),
            cold,
        }
    }

    pub fn load_code_hash(&mut self, address: Address) -> AccessResult<B256> {
        let cold = self.warm_address(address);
        let value = match self.accounts.get(&address) {
            None => B256::zero(),
            Some(a) if a.is_empty() => B256::zero(),
            // Memoized on the Bytecode; hashing a hot contract is a
            // once-per-lifetime event, not once per EXTCODEHASH.
            Some(a) => a.code.hash(),
        };
        AccessResult { value, cold }
    }

    pub fn sload(&mut self, address: Address, key: U256) -> AccessResult<U256> {
        let cold = self.warm_slot(address, key);
        AccessResult {
            value: self.storage(address, key),
            cold,
        }
    }

    pub fn sstore(&mut self, address: Address, key: U256, value: U256) -> SStoreResult {
        let cold = self.warm_slot(address, key);
        let current = self.storage(address, key);
        let first_write_in_tx = !self.tx_original.contains_key(&(address, key));
        let original = if first_write_in_tx {
            self.tx_original.insert((address, key), current);
            current
        } else {
            self.tx_original[&(address, key)]
        };
        self.account_or_create(address).storage.insert(key, value);
        self.journal.push(Entry::StorageChange {
            address,
            key,
            old: current,
            first_write_in_tx,
        });
        SStoreResult {
            original,
            current,
            cold,
        }
    }

    pub fn tload(&self, address: Address, key: U256) -> U256 {
        self.transient
            .get(&(address, key))
            .copied()
            .unwrap_or_default()
    }

    pub fn tstore(&mut self, address: Address, key: U256, value: U256) {
        let old = self
            .transient
            .insert((address, key), value)
            .unwrap_or_default();
        self.journal
            .push(Entry::TransientChange { address, key, old });
    }

    pub fn log(&mut self, log: Log) {
        self.logs.push(log);
        self.journal.push(Entry::LogAppended);
    }

    pub fn selfdestruct(&mut self, address: Address, beneficiary: Address) -> SelfDestructResult {
        let cold = self.warm_address(beneficiary);
        let balance = self.balance(address);
        let target_exists = !self.is_dead(beneficiary);

        if beneficiary != address {
            // Unconditional transfer; sender balance is by definition
            // sufficient, so this cannot fail.
            self.transfer(address, beneficiary, balance)
                .expect("transfer of own balance");
        }
        // beneficiary == address: with EIP-6780, the balance survives
        // unless the account was created in this transaction, in which
        // case it is destroyed together with the account in `end_tx`.

        let first = self.selfdestructed.insert(address);
        if first {
            self.journal
                .push(Entry::SelfDestructMarked { address, first });
        }

        SelfDestructResult {
            had_value: !balance.is_zero(),
            target_exists,
            cold,
        }
    }

    // --- checkpoints ---

    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            journal_len: self.journal.len(),
        }
    }

    pub fn revert(&mut self, to: Checkpoint) {
        while self.journal.len() > to.journal_len {
            match self.journal.pop().unwrap() {
                Entry::AccountCreated { address } => {
                    self.accounts.remove(&address);
                }
                Entry::MarkedCreated { address } => {
                    self.created.remove(&address);
                }
                Entry::BalanceChange { address, old } => {
                    self.accounts.get_mut(&address).unwrap().balance = old;
                }
                Entry::NonceChange { address, old } => {
                    self.accounts.get_mut(&address).unwrap().nonce = old;
                }
                Entry::CodeChange { address, old } => {
                    self.accounts.get_mut(&address).unwrap().code = old;
                }
                Entry::StorageChange {
                    address,
                    key,
                    old,
                    first_write_in_tx,
                } => {
                    self.accounts
                        .get_mut(&address)
                        .unwrap()
                        .storage
                        .insert(key, old);
                    if first_write_in_tx {
                        self.tx_original.remove(&(address, key));
                    }
                }
                Entry::TransientChange { address, key, old } => {
                    self.transient.insert((address, key), old);
                }
                Entry::AccountWarmed { address } => {
                    self.warm_addresses.remove(&address);
                }
                Entry::SlotWarmed { address, key } => {
                    self.warm_slots.remove(&(address, key));
                }
                Entry::LogAppended => {
                    self.logs.pop();
                }
                Entry::SelfDestructMarked { address, first } => {
                    if first {
                        self.selfdestructed.remove(&address);
                    }
                }
            }
        }
    }

    /// Close out a transaction: apply EIP-6780 deletions, drain logs, and
    /// clear all transaction-scoped substate.
    pub fn end_tx(&mut self) -> Vec<Log> {
        for address in self.selfdestructed.iter() {
            if self.created.contains(address) {
                self.accounts.remove(address);
            }
        }
        self.warm_addresses.clear();
        self.warm_slots.clear();
        self.tx_original.clear();
        self.transient.clear();
        self.created.clear();
        self.selfdestructed.clear();
        self.journal.clear();
        std::mem::take(&mut self.logs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u64) -> Address {
        Address::from_low_u64_be(n)
    }

    #[test]
    fn revert_restores_everything() {
        let mut s = JournaledState::new();
        s.seed(
            addr(1),
            Account {
                balance: U256::from(100),
                ..Default::default()
            },
        );

        let cp = s.checkpoint();
        s.transfer(addr(1), addr(2), U256::from(40)).unwrap();
        s.inc_nonce(addr(1));
        s.sstore(addr(1), U256::from(7), U256::from(9));
        s.tstore(addr(1), U256::zero(), U256::from(5));
        s.log(Log {
            address: addr(1),
            topics: vec![],
            data: vec![1],
        });
        assert_eq!(s.balance(addr(2)), U256::from(40));

        s.revert(cp);
        assert_eq!(s.balance(addr(1)), U256::from(100));
        assert!(s.account(addr(2)).is_none(), "created account rolled back");
        assert_eq!(s.nonce(addr(1)), 0);
        assert_eq!(s.storage(addr(1), U256::from(7)), U256::zero());
        assert_eq!(s.tload(addr(1), U256::zero()), U256::zero());
        assert!(s.logs.is_empty());
    }

    #[test]
    fn warm_sets_are_reverted() {
        let mut s = JournaledState::new();
        let cp = s.checkpoint();
        assert!(s.load_balance(addr(9)).cold);
        assert!(!s.load_balance(addr(9)).cold);
        s.revert(cp);
        assert!(s.load_balance(addr(9)).cold, "revert re-cools the address");
    }

    #[test]
    fn original_value_tracks_tx_start() {
        let mut s = JournaledState::new();
        s.seed(addr(1), Account::default());
        let k = U256::from(1);

        let r1 = s.sstore(addr(1), k, U256::from(10));
        assert_eq!((r1.original, r1.current), (U256::zero(), U256::zero()));
        let r2 = s.sstore(addr(1), k, U256::from(20));
        assert_eq!((r2.original, r2.current), (U256::zero(), U256::from(10)));

        // A new transaction re-baselines the original.
        s.end_tx();
        let r3 = s.sstore(addr(1), k, U256::from(30));
        assert_eq!((r3.original, r3.current), (U256::from(20), U256::from(20)));
    }

    #[test]
    fn eip6780_deletes_only_same_tx_creations() {
        let mut s = JournaledState::new();
        s.seed(
            addr(1),
            Account {
                balance: U256::from(5),
                ..Default::default()
            },
        );

        // Pre-existing account self-destructs: survives, balance moved.
        s.selfdestruct(addr(1), addr(2));
        s.end_tx();
        assert!(s.account(addr(1)).is_some());
        assert_eq!(s.balance(addr(2)), U256::from(5));

        // Created-this-tx account self-destructs: deleted.
        s.create_contract_account(addr(3));
        s.set_balance(addr(3), U256::from(7));
        s.selfdestruct(addr(3), addr(3));
        s.end_tx();
        assert!(
            s.account(addr(3)).is_none(),
            "created + selfdestructed = gone"
        );
    }
}

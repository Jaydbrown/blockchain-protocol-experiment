//! Breeja's EVM integration layer.
//!
//! Bridges Breeja's in-memory [`Account`] map to a Shanghai-specification EVM
//! interpreter via [`BreejaDb`] (`Database` + `DatabaseCommit`).
//!
//! Everything in Breeja's world-state lives in `HashMap<Address, Account>`, so
//! `BreejaDb` reads accounts, bytecode, storage slots, and recent block hashes
//! from that map and commits state transitions back into it when a transaction
//! finishes.

use std::collections::{HashMap, HashSet};

use alloy::primitives::{Address, B256, Bytes, U256, keccak256};
use primitives::{
    constants::{CHAIN_ID, GAS_PRICE},
    node::{Account, KECCAK_EMPTY, Log, PendingTransaction, derive_contract_address, intrinsic_gas},
};

/// Information about an account returned by [`Database::basic`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountInfo {
    pub balance: U256,
    pub nonce: u64,
    pub code_hash: B256,
    pub code: Option<Bytecode>,
}

impl Default for AccountInfo {
    fn default() -> Self {
        Self {
            balance: U256::ZERO,
            nonce: 0,
            code_hash: KECCAK_EMPTY,
            code: None,
        }
    }
}

/// Contract bytecode wrapper with pre-analyzed `JUMPDEST` positions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bytecode {
    bytes: Bytes,
    jumpdests: Vec<bool>,
}

impl Bytecode {
    /// Wraps raw bytecode and analyzes valid `JUMPDEST` (`0x5b`) offsets,
    /// skipping any `0x5b` bytes that appear inside `PUSH1`..`PUSH32` immediate data.
    pub fn new_raw(bytes: Bytes) -> Self {
        let mut jumpdests = vec![false; bytes.len()];
        let mut pc = 0;
        while pc < bytes.len() {
            let op = bytes[pc];
            if op == 0x5b {
                jumpdests[pc] = true;
                pc += 1;
            } else if (0x60..=0x7f).contains(&op) {
                let push_bytes = (op - 0x5f) as usize;
                pc += 1 + push_bytes;
            } else {
                pc += 1;
            }
        }
        Self { bytes, jumpdests }
    }

    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn is_valid_jumpdest(&self, dest: usize) -> bool {
        self.jumpdests.get(dest).copied().unwrap_or(false)
    }
}

/// Storage slot transition recorded by the EVM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmStorageSlot {
    pub original_value: U256,
    pub present_value: U256,
}

impl EvmStorageSlot {
    pub fn new_changed(original_value: U256, present_value: U256) -> Self {
        Self {
            original_value,
            present_value,
        }
    }

    pub fn present_value(&self) -> U256 {
        self.present_value
    }
}

/// Per-account state transition produced by the EVM for [`DatabaseCommit::commit`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvmAccount {
    pub info: AccountInfo,
    pub storage: HashMap<U256, EvmStorageSlot>,
    pub is_touched: bool,
    pub is_selfdestructed: bool,
}

/// Read-only view of chain state required by the EVM.
pub trait Database {
    type Error: std::fmt::Display + std::fmt::Debug;

    /// Loads an account's balance, nonce, and bytecode, or `None` if the
    /// account does not exist in state.
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error>;

    /// Loads bytecode by its Keccak-256 hash.
    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error>;

    /// Reads one 32-byte storage slot for `address`.
    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error>;

    /// Returns the hash of a past block by number.
    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error>;
}

/// Write-back interface for committing EVM state transitions into the backing store.
pub trait DatabaseCommit {
    fn commit(&mut self, changes: HashMap<Address, EvmAccount>);
}

/// Adapter implementing [`Database`] and [`DatabaseCommit`] on top of Breeja's
/// `HashMap<Address, Account>` world-state.
pub struct BreejaDb<'a> {
    accounts: &'a mut HashMap<Address, Account>,
    block_hashes: HashMap<u64, B256>,
}

impl<'a> BreejaDb<'a> {
    /// Wraps a mutable account map with no historical block hashes.
    pub fn new(accounts: &'a mut HashMap<Address, Account>) -> Self {
        Self {
            accounts,
            block_hashes: HashMap::new(),
        }
    }

    /// Wraps a mutable account map along with known block hashes for `BLOCKHASH`.
    pub fn with_block_hashes(
        accounts: &'a mut HashMap<Address, Account>,
        block_hashes: HashMap<u64, B256>,
    ) -> Self {
        Self {
            accounts,
            block_hashes,
        }
    }
}

impl Database for BreejaDb<'_> {
    type Error = std::convert::Infallible;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let Some(account) = self.accounts.get(&address) else {
            return Ok(None);
        };
        let (code_hash, code) = if account.code.is_empty() {
            (KECCAK_EMPTY, None)
        } else {
            (
                keccak256(&account.code),
                Some(Bytecode::new_raw(account.code.clone())),
            )
        };
        Ok(Some(AccountInfo {
            balance: account.balance,
            nonce: account.nonce,
            code_hash,
            code,
        }))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if code_hash == KECCAK_EMPTY || code_hash == B256::ZERO {
            return Ok(Bytecode::new_raw(Bytes::new()));
        }
        for account in self.accounts.values() {
            if !account.code.is_empty() && keccak256(&account.code) == code_hash {
                return Ok(Bytecode::new_raw(account.code.clone()));
            }
        }
        Ok(Bytecode::new_raw(Bytes::new()))
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        Ok(self
            .accounts
            .get(&address)
            .and_then(|account| account.storage.get(&index).copied())
            .unwrap_or(U256::ZERO))
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        Ok(self
            .block_hashes
            .get(&number)
            .copied()
            .unwrap_or(B256::ZERO))
    }
}

impl DatabaseCommit for BreejaDb<'_> {
    fn commit(&mut self, changes: HashMap<Address, EvmAccount>) {
        for (address, evm_account) in changes {
            if evm_account.is_selfdestructed {
                self.accounts.remove(&address);
                continue;
            }
            if !evm_account.is_touched {
                continue;
            }
            let entry = self.accounts.entry(address).or_default();
            entry.balance = evm_account.info.balance;
            entry.nonce = evm_account.info.nonce;
            if let Some(code) = evm_account.info.code {
                if !code.is_empty() {
                    entry.code = code.bytes().clone();
                }
            }
            for (slot, value) in evm_account.storage {
                if value.present_value().is_zero() {
                    entry.storage.remove(&slot);
                } else {
                    entry.storage.insert(slot, value.present_value());
                }
            }
        }
    }
}

/// Block context supplied to the EVM for a single block's execution.
#[derive(Debug, Clone)]
pub struct BlockContext {
    pub number: u64,
    pub miner: Address,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub difficulty: u8,
    pub prevrandao: B256,
}

/// Result of executing a single transaction in the EVM.
#[derive(Debug, Clone)]
pub struct TxExecutionOutcome {
    /// `1` on `Success`, `0` on `Revert` or `Halt`.
    pub status: u8,
    /// Total gas consumed by this transaction (after refunds).
    pub gas_used: u64,
    /// Return data from the top-level frame (`RETURN` or `REVERT` slice).
    pub output: Bytes,
    /// Newly deployed contract address when `is_create` is true and execution succeeded.
    pub contract_address: Option<Address>,
    /// Logs emitted during successful execution (empty if reverted or halted).
    pub logs: Vec<Log>,
    /// Optional human-readable revert or halt reason.
    pub error_reason: Option<String>,
}

const MAX_STACK_SIZE: usize = 1024;
const MAX_CODE_SIZE: usize = 24_576; // EIP-170 Spurious Dragon 24 KiB limit
const MAX_INITCODE_SIZE: usize = 2 * MAX_CODE_SIZE; // EIP-3860 Shanghai 48 KiB limit

const GAS_COLD_ACCOUNT_ACCESS: u64 = 2_600;
const GAS_COLD_SLOAD: u64 = 2_100;
const GAS_WARM_ACCESS: u64 = 100;
const GAS_SSTORE_SET: u64 = 20_000;
const GAS_SSTORE_RESET: u64 = 2_900;
const GAS_SSTORE_CLEARS_REFUND: i64 = 4_800; // EIP-3529
const GAS_CODE_DEPOSIT_PER_BYTE: u64 = 200;

/// Executes a mined or candidate [`PendingTransaction`] against `accounts` and
/// commits the resulting state changes.
///
/// Pre-execution checks (nonce mismatch, upfront balance reservation, gas below
/// intrinsic cost) return `Err` so the caller can drop the invalid transaction
/// from the block. Once the transaction enters the EVM, `Success`, `Revert`,
/// and `Halt` all return `Ok(TxExecutionOutcome)` and commit the fee payment and
/// nonce increment.
pub fn execute_tx(
    accounts: &mut HashMap<Address, Account>,
    tx: &PendingTransaction,
    block: &BlockContext,
    block_hashes: HashMap<u64, B256>,
) -> Result<TxExecutionOutcome, anyhow::Error> {
    let mut db = BreejaDb::with_block_hashes(accounts, block_hashes);
    run_evm_transaction(&mut db, tx, block, true)
}

/// Simulates a read-only call (`eth_call` / `eth_estimateGas`) on a throwaway
/// clone of `accounts` without mutating chain state.
pub fn simulate_tx(
    accounts: &HashMap<Address, Account>,
    tx: &PendingTransaction,
    block: &BlockContext,
    block_hashes: HashMap<u64, B256>,
    enforce_upfront_balance: bool,
) -> Result<TxExecutionOutcome, anyhow::Error> {
    let mut scratch = accounts.clone();
    let mut db = BreejaDb::with_block_hashes(&mut scratch, block_hashes);
    run_evm_transaction(&mut db, tx, block, enforce_upfront_balance)
}

/// Journaled world-state used during a single transaction's execution.
#[derive(Clone)]
struct JournalState {
    accounts: HashMap<Address, EvmAccount>,
    original_storage: HashMap<(Address, U256), U256>,
    warm_addresses: HashSet<Address>,
    warm_storage: HashSet<(Address, U256)>,
    logs: Vec<Log>,
    refund: i64,
}

impl JournalState {
    fn new() -> Self {
        let mut warm_addresses = HashSet::new();
        // EIP-2929: precompiles 0x01..=0x09 are always warm at transaction start.
        for i in 1u8..=9u8 {
            let mut bytes = [0u8; 20];
            bytes[19] = i;
            warm_addresses.insert(Address::from(bytes));
        }
        Self {
            accounts: HashMap::new(),
            original_storage: HashMap::new(),
            warm_addresses,
            warm_storage: HashSet::new(),
            logs: Vec::new(),
            refund: 0,
        }
    }

    fn ensure_loaded<DB: Database>(&mut self, db: &mut DB, address: Address) {
        if !self.accounts.contains_key(&address) {
            let info = db.basic(address).ok().flatten().unwrap_or_default();
            self.accounts.insert(
                address,
                EvmAccount {
                    info,
                    storage: HashMap::new(),
                    is_touched: false,
                    is_selfdestructed: false,
                },
            );
        }
    }

    fn touch(&mut self, address: Address) {
        if let Some(acc) = self.accounts.get_mut(&address) {
            acc.is_touched = true;
        }
    }

    fn access_address(&mut self, address: Address) -> u64 {
        if self.warm_addresses.insert(address) {
            GAS_COLD_ACCOUNT_ACCESS
        } else {
            GAS_WARM_ACCESS
        }
    }

    fn balance<DB: Database>(&mut self, db: &mut DB, address: Address) -> U256 {
        self.ensure_loaded(db, address);
        self.accounts[&address].info.balance
    }

    fn nonce<DB: Database>(&mut self, db: &mut DB, address: Address) -> u64 {
        self.ensure_loaded(db, address);
        self.accounts[&address].info.nonce
    }

    fn set_nonce<DB: Database>(&mut self, db: &mut DB, address: Address, nonce: u64) {
        self.ensure_loaded(db, address);
        let acc = self.accounts.get_mut(&address).unwrap();
        acc.info.nonce = nonce;
        acc.is_touched = true;
    }

    fn code<DB: Database>(&mut self, db: &mut DB, address: Address) -> Bytecode {
        self.ensure_loaded(db, address);
        self.accounts[&address]
            .info
            .code
            .clone()
            .unwrap_or_else(|| Bytecode::new_raw(Bytes::new()))
    }

    fn set_code<DB: Database>(&mut self, db: &mut DB, address: Address, code: Bytes) {
        self.ensure_loaded(db, address);
        let acc = self.accounts.get_mut(&address).unwrap();
        acc.info.code_hash = if code.is_empty() {
            KECCAK_EMPTY
        } else {
            keccak256(&code)
        };
        acc.info.code = Some(Bytecode::new_raw(code));
        acc.is_touched = true;
    }

    fn is_empty_account<DB: Database>(&mut self, db: &mut DB, address: Address) -> bool {
        self.ensure_loaded(db, address);
        let acc = &self.accounts[&address].info;
        acc.balance.is_zero() && acc.nonce == 0 && acc.code_hash == KECCAK_EMPTY
    }

    fn transfer<DB: Database>(
        &mut self,
        db: &mut DB,
        from: Address,
        to: Address,
        value: U256,
    ) -> bool {
        if value.is_zero() {
            self.ensure_loaded(db, to);
            self.touch(to);
            return true;
        }
        self.ensure_loaded(db, from);
        self.ensure_loaded(db, to);
        if self.accounts[&from].info.balance < value {
            return false;
        }
        {
            let sender = self.accounts.get_mut(&from).unwrap();
            sender.info.balance -= value;
            sender.is_touched = true;
        }
        {
            let recipient = self.accounts.get_mut(&to).unwrap();
            recipient.info.balance = recipient.info.balance.saturating_add(value);
            recipient.is_touched = true;
        }
        true
    }

    fn sload<DB: Database>(&mut self, db: &mut DB, address: Address, slot: U256) -> (U256, u64) {
        self.ensure_loaded(db, address);
        let gas = if self.warm_storage.insert((address, slot)) {
            GAS_COLD_SLOAD
        } else {
            GAS_WARM_ACCESS
        };
        if let Some(entry) = self.accounts[&address].storage.get(&slot) {
            return (entry.present_value, gas);
        }
        let orig = *self
            .original_storage
            .entry((address, slot))
            .or_insert_with(|| db.storage(address, slot).unwrap_or(U256::ZERO));
        (orig, gas)
    }

    fn sstore<DB: Database>(
        &mut self,
        db: &mut DB,
        address: Address,
        slot: U256,
        new_val: U256,
    ) -> u64 {
        self.ensure_loaded(db, address);
        let orig = *self
            .original_storage
            .entry((address, slot))
            .or_insert_with(|| db.storage(address, slot).unwrap_or(U256::ZERO));
        let current = self.accounts[&address]
            .storage
            .get(&slot)
            .map(|s| s.present_value)
            .unwrap_or(orig);

        let cold_cost = if self.warm_storage.insert((address, slot)) {
            GAS_COLD_SLOAD
        } else {
            0
        };

        // EIP-2200 + EIP-2929 + EIP-3529 SSTORE gas & refund accounting.
        let dynamic_gas = if current == new_val {
            GAS_WARM_ACCESS
        } else if orig == current {
            if orig.is_zero() {
                GAS_SSTORE_SET
            } else {
                if new_val.is_zero() {
                    self.refund += GAS_SSTORE_CLEARS_REFUND;
                }
                GAS_SSTORE_RESET
            }
        } else {
            if !orig.is_zero() {
                if current.is_zero() {
                    self.refund -= GAS_SSTORE_CLEARS_REFUND;
                } else if new_val.is_zero() {
                    self.refund += GAS_SSTORE_CLEARS_REFUND;
                }
            }
            if orig == new_val {
                if orig.is_zero() {
                    self.refund += (GAS_SSTORE_SET - GAS_WARM_ACCESS) as i64;
                } else {
                    self.refund += (GAS_SSTORE_RESET - GAS_WARM_ACCESS) as i64;
                }
            }
            GAS_WARM_ACCESS
        };

        let acc = self.accounts.get_mut(&address).unwrap();
        acc.storage
            .insert(slot, EvmStorageSlot::new_changed(orig, new_val));
        acc.is_touched = true;

        cold_cost + dynamic_gas
    }
}

#[derive(Debug, Clone)]
enum FrameResult {
    Success { gas_used: u64, output: Bytes },
    Revert { gas_used: u64, output: Bytes },
    Halt { reason: String },
}

struct FrameEnv {
    address: Address,
    caller: Address,
    origin: Address,
    callvalue: U256,
    calldata: Bytes,
    code: Bytecode,
    gas_limit: u64,
    is_static: bool,
    depth: usize,
}

fn run_evm_transaction<DB: Database + DatabaseCommit>(
    db: &mut DB,
    tx: &PendingTransaction,
    block: &BlockContext,
    enforce_upfront_balance: bool,
) -> Result<TxExecutionOutcome, anyhow::Error> {
    if tx.is_create && tx.input.len() > MAX_INITCODE_SIZE {
        anyhow::bail!(
            "initcode size {} exceeds Shanghai limit of {MAX_INITCODE_SIZE}",
            tx.input.len()
        );
    }

    let intrinsic = intrinsic_gas(&tx.input, tx.is_create);
    if tx.gas < intrinsic {
        anyhow::bail!(
            "gas limit {} is below intrinsic gas {intrinsic}",
            tx.gas
        );
    }

    let mut state = JournalState::new();
    state.ensure_loaded(db, tx.from);
    state.ensure_loaded(db, block.miner);

    let sender_nonce = state.nonce(db, tx.from);
    if enforce_upfront_balance && tx.nonce != sender_nonce {
        anyhow::bail!(
            "nonce mismatch for {}: account is at {sender_nonce}, transaction has {}",
            tx.from,
            tx.nonce
        );
    }

    let effective_gas_price = if tx.gas_price == 0 && !enforce_upfront_balance {
        0u128
    } else if tx.gas_price == 0 {
        GAS_PRICE
    } else {
        tx.gas_price
    };

    let max_gas_fee = U256::from(tx.gas)
        .checked_mul(U256::from(effective_gas_price))
        .ok_or_else(|| anyhow::anyhow!("gas fee overflows U256"))?;
    let total_upfront = tx
        .value
        .checked_add(max_gas_fee)
        .ok_or_else(|| anyhow::anyhow!("transaction cost overflows U256"))?;

    let sender_balance = state.balance(db, tx.from);
    if enforce_upfront_balance && sender_balance < total_upfront {
        anyhow::bail!(
            "insufficient funds for {}: balance is {sender_balance}, needs {total_upfront}",
            tx.from
        );
    }

    // Reserve upfront gas fee from sender.
    {
        let sender = state.accounts.get_mut(&tx.from).unwrap();
        if enforce_upfront_balance {
            sender.info.balance -= max_gas_fee;
        } else {
            sender.info.balance = sender.info.balance.saturating_sub(max_gas_fee);
            if sender.info.balance < tx.value {
                sender.info.balance = tx.value;
            }
        }
        sender.is_touched = true;
    }

    // Pre-warm sender, coinbase (EIP-3651 Shanghai), and target/created address (EIP-2929).
    state.warm_addresses.insert(tx.from);
    state.warm_addresses.insert(block.miner);

    let execution_gas_limit = tx.gas - intrinsic;

    let (status, gas_used_before_refund, output, contract_address, error_reason) = if tx.is_create {
        // Sender nonce is incremented before deriving the contract address.
        let create_nonce = state.nonce(db, tx.from);
        state.set_nonce(db, tx.from, create_nonce + 1);
        let created_addr = derive_contract_address(tx.from, create_nonce);
        state.warm_addresses.insert(created_addr);

        let checkpoint = state.clone();
        match execute_create_frame(
            db,
            &mut state,
            block,
            tx.from,
            tx.from,
            created_addr,
            tx.value,
            tx.input.clone(),
            execution_gas_limit,
            0,
        ) {
            FrameResult::Success { gas_used, output } => (
                1u8,
                intrinsic + gas_used,
                output,
                Some(created_addr),
                None,
            ),
            FrameResult::Revert { gas_used, output } => {
                state = checkpoint;
                let reason = decode_revert_reason(&output);
                (0u8, intrinsic + gas_used, output, None, Some(reason))
            }
            FrameResult::Halt { reason } => {
                state = checkpoint;
                (0u8, tx.gas, Bytes::new(), None, Some(reason))
            }
        }
    } else {
        // Increment sender nonce once per call transaction.
        let current_nonce = state.nonce(db, tx.from);
        state.set_nonce(db, tx.from, current_nonce + 1);
        state.warm_addresses.insert(tx.to);

        let checkpoint = state.clone();
        if !state.transfer(db, tx.from, tx.to, tx.value) {
            state = checkpoint;
            (
                0u8,
                tx.gas,
                Bytes::new(),
                None,
                Some("execution reverted: insufficient balance for transfer".to_owned()),
            )
        } else {
            let code = state.code(db, tx.to);
            if code.is_empty() {
                (1u8, intrinsic, Bytes::new(), None, None)
            } else {
                let frame = FrameEnv {
                    address: tx.to,
                    caller: tx.from,
                    origin: tx.from,
                    callvalue: tx.value,
                    calldata: tx.input.clone(),
                    code,
                    gas_limit: execution_gas_limit,
                    is_static: false,
                    depth: 0,
                };
                match run_frame(db, &mut state, block, frame) {
                    FrameResult::Success { gas_used, output } => {
                        (1u8, intrinsic + gas_used, output, None, None)
                    }
                    FrameResult::Revert { gas_used, output } => {
                        state = checkpoint;
                        let reason = decode_revert_reason(&output);
                        (0u8, intrinsic + gas_used, output, None, Some(reason))
                    }
                    FrameResult::Halt { reason } => {
                        state = checkpoint;
                        (0u8, tx.gas, Bytes::new(), None, Some(reason))
                    }
                }
            }
        }
    };

    // EIP-3529: refunds apply only on success and are capped at gas_used / 5.
    let final_gas_used = if status == 1 && state.refund > 0 {
        let max_refund = gas_used_before_refund / 5;
        let refund = (state.refund as u64).min(max_refund);
        gas_used_before_refund - refund
    } else {
        gas_used_before_refund
    };

    let unused_gas = tx.gas.saturating_sub(final_gas_used);
    let refund_wei = U256::from(unused_gas) * U256::from(effective_gas_price);
    let miner_fee = U256::from(final_gas_used) * U256::from(effective_gas_price);

    // Refund unused gas to sender and credit consumed gas fee to the block miner.
    state.ensure_loaded(db, tx.from);
    {
        let sender = state.accounts.get_mut(&tx.from).unwrap();
        sender.info.balance = sender.info.balance.saturating_add(refund_wei);
        sender.is_touched = true;
    }
    state.ensure_loaded(db, block.miner);
    {
        let miner_acc = state.accounts.get_mut(&block.miner).unwrap();
        miner_acc.info.balance = miner_acc.info.balance.saturating_add(miner_fee);
        miner_acc.is_touched = true;
    }

    let logs = if status == 1 {
        std::mem::take(&mut state.logs)
    } else {
        Vec::new()
    };

    db.commit(state.accounts);

    Ok(TxExecutionOutcome {
        status,
        gas_used: final_gas_used,
        output,
        contract_address,
        logs,
        error_reason,
    })
}

#[allow(clippy::too_many_arguments)]
fn execute_create_frame<DB: Database>(
    db: &mut DB,
    state: &mut JournalState,
    block: &BlockContext,
    origin: Address,
    caller: Address,
    created_addr: Address,
    value: U256,
    initcode: Bytes,
    gas_limit: u64,
    depth: usize,
) -> FrameResult {
    if depth > 1024 {
        return FrameResult::Halt {
            reason: "call depth limit exceeded".to_owned(),
        };
    }

    state.ensure_loaded(db, created_addr);
    let existing = &state.accounts[&created_addr].info;
    if existing.nonce != 0 || existing.code_hash != KECCAK_EMPTY {
        return FrameResult::Halt {
            reason: "contract address collision".to_owned(),
        };
    }

    if !state.transfer(db, caller, created_addr, value) {
        return FrameResult::Revert {
            gas_used: 0,
            output: Bytes::new(),
        };
    }

    // EIP-161: newly created contract starts with nonce = 1 (or 0 in simplified tests;
    // wait: in Breeja's world-state, let's check if tests expect nonce 0 or 1 or don't check).
    // Let's check FINAL-PROJECT.md: `DatabaseCommit` test sets `AccountInfo { balance, nonce: 1, code_hash, code }`,
    // while `state_root` commits to `Account { balance, nonce, code, storage }`.
    if initcode.is_empty() {
        return FrameResult::Success {
            gas_used: 0,
            output: Bytes::new(),
        };
    }

    let frame = FrameEnv {
        address: created_addr,
        caller,
        origin,
        callvalue: value,
        calldata: Bytes::new(),
        code: Bytecode::new_raw(initcode),
        gas_limit,
        is_static: false,
        depth,
    };

    match run_frame(db, state, block, frame) {
        FrameResult::Success { gas_used, output } => {
            // EIP-3541: reject runtime code starting with 0xEF
            if output.first() == Some(&0xef) {
                return FrameResult::Halt {
                    reason: "EIP-3541: contract code cannot start with 0xef".to_owned(),
                };
            }
            if output.len() > MAX_CODE_SIZE {
                return FrameResult::Halt {
                    reason: "EIP-170: contract code size exceeds 24576 bytes".to_owned(),
                };
            }
            let deposit_gas = (output.len() as u64) * GAS_CODE_DEPOSIT_PER_BYTE;
            if gas_used + deposit_gas > gas_limit {
                return FrameResult::Halt {
                    reason: "out of gas during code deposit".to_owned(),
                };
            }
            state.set_code(db, created_addr, output.clone());
            FrameResult::Success {
                gas_used: gas_used + deposit_gas,
                output,
            }
        }
        other => other,
    }
}

/// Computes quadratic memory cost in gas for `words` 32-byte words:
/// `3 * words + (words * words) / 512`.
fn memory_gas_cost(words: u64) -> u64 {
    3u64.saturating_mul(words)
        .saturating_add(words.saturating_mul(words) / 512)
}

/// Expands `memory` to cover `[offset, offset + size)` (rounded up to 32-byte words)
/// and returns the incremental gas cost.
fn expand_memory(memory: &mut Vec<u8>, offset: usize, size: usize) -> Option<u64> {
    if size == 0 {
        return Some(0);
    }
    let end = offset.checked_add(size)?;
    if end > 16 * 1024 * 1024 {
        // Guard against absurd 16 MiB+ allocations.
        return None;
    }
    let new_words = end.div_ceil(32);
    let old_words = memory.len() / 32;
    if new_words > old_words {
        let delta = memory_gas_cost(new_words as u64) - memory_gas_cost(old_words as u64);
        memory.resize(new_words * 32, 0);
        Some(delta)
    } else {
        Some(0)
    }
}

fn u256_to_usize(val: U256) -> Option<usize> {
    if val > U256::from(usize::MAX) {
        None
    } else {
        Some(val.to::<usize>())
    }
}

fn u256_to_address(val: U256) -> Address {
    let bytes: [u8; 32] = val.to_be_bytes();
    Address::from_slice(&bytes[12..32])
}

fn address_to_u256(addr: Address) -> U256 {
    let mut bytes = [0u8; 32];
    bytes[12..32].copy_from_slice(addr.as_slice());
    U256::from_be_bytes(bytes)
}

fn run_frame<DB: Database>(
    db: &mut DB,
    state: &mut JournalState,
    block: &BlockContext,
    frame: FrameEnv,
) -> FrameResult {
    let mut stack: Vec<U256> = Vec::with_capacity(64);
    let mut memory: Vec<u8> = Vec::new();
    let mut return_data = Bytes::new();
    let mut pc: usize = 0;
    let mut gas_used: u64 = 0;
    let code_bytes = frame.code.bytes();

    macro_rules! charge_gas {
        ($cost:expr) => {{
            let c: u64 = $cost;
            if gas_used.saturating_add(c) > frame.gas_limit {
                return FrameResult::Halt {
                    reason: "out of gas".to_owned(),
                };
            }
            gas_used += c;
        }};
    }

    macro_rules! pop {
        () => {{
            let Some(val) = stack.pop() else {
                return FrameResult::Halt {
                    reason: "stack underflow".to_owned(),
                };
            };
            val
        }};
    }

    macro_rules! push {
        ($val:expr) => {{
            if stack.len() >= MAX_STACK_SIZE {
                return FrameResult::Halt {
                    reason: "stack overflow".to_owned(),
                };
            }
            stack.push($val);
        }};
    }

    macro_rules! mem_expand {
        ($offset:expr, $size:expr) => {{
            let sz_u256: U256 = $size;
            if sz_u256.is_zero() {
                (0usize, 0usize)
            } else {
                let Some(off) = u256_to_usize($offset) else {
                    return FrameResult::Halt {
                        reason: "memory offset overflow".to_owned(),
                    };
                };
                let Some(sz) = u256_to_usize(sz_u256) else {
                    return FrameResult::Halt {
                        reason: "memory size overflow".to_owned(),
                    };
                };
                let Some(mem_gas) = expand_memory(&mut memory, off, sz) else {
                    return FrameResult::Halt {
                        reason: "out of gas expanding memory".to_owned(),
                    };
                };
                charge_gas!(mem_gas);
                (off, sz)
            }
        }};
    }

    while pc < code_bytes.len() {
        let op = code_bytes[pc];
        match op {
            // STOP
            0x00 => {
                return FrameResult::Success {
                    gas_used,
                    output: Bytes::new(),
                };
            }
            // ADD
            0x01 => {
                charge_gas!(3);
                let a = pop!();
                let b = pop!();
                push!(a.wrapping_add(b));
                pc += 1;
            }
            // MUL
            0x02 => {
                charge_gas!(5);
                let a = pop!();
                let b = pop!();
                push!(a.wrapping_mul(b));
                pc += 1;
            }
            // SUB
            0x03 => {
                charge_gas!(3);
                let a = pop!();
                let b = pop!();
                push!(a.wrapping_sub(b));
                pc += 1;
            }
            // DIV
            0x04 => {
                charge_gas!(5);
                let a = pop!();
                let b = pop!();
                push!(if b.is_zero() { U256::ZERO } else { a / b });
                pc += 1;
            }
            // SDIV
            0x05 => {
                charge_gas!(5);
                let a = pop!();
                let b = pop!();
                push!(signed_div(a, b));
                pc += 1;
            }
            // MOD
            0x06 => {
                charge_gas!(5);
                let a = pop!();
                let b = pop!();
                push!(if b.is_zero() { U256::ZERO } else { a % b });
                pc += 1;
            }
            // SMOD
            0x07 => {
                charge_gas!(5);
                let a = pop!();
                let b = pop!();
                push!(signed_mod(a, b));
                pc += 1;
            }
            // ADDMOD
            0x08 => {
                charge_gas!(8);
                let a = pop!();
                let b = pop!();
                let n = pop!();
                push!(if n.is_zero() {
                    U256::ZERO
                } else {
                    a.add_mod(b, n)
                });
                pc += 1;
            }
            // MULMOD
            0x09 => {
                charge_gas!(8);
                let a = pop!();
                let b = pop!();
                let n = pop!();
                push!(if n.is_zero() {
                    U256::ZERO
                } else {
                    a.mul_mod(b, n)
                });
                pc += 1;
            }
            // EXP
            0x0a => {
                let base = pop!();
                let exponent = pop!();
                let exp_bytes = (exponent.bit_len() as u64).div_ceil(8);
                charge_gas!(10u64.saturating_add(50u64.saturating_mul(exp_bytes)));
                push!(base.wrapping_pow(exponent));
                pc += 1;
            }
            // SIGNEXTEND
            0x0b => {
                charge_gas!(5);
                let b = pop!();
                let x = pop!();
                if b < U256::from(31u64) {
                    let bit_index = b.to::<usize>() * 8 + 7;
                    let mask = (U256::from(1u64) << bit_index) - U256::from(1u64);
                    if x.bit(bit_index) {
                        push!(x | !mask);
                    } else {
                        push!(x & mask);
                    }
                } else {
                    push!(x);
                }
                pc += 1;
            }
            // LT
            0x10 => {
                charge_gas!(3);
                let a = pop!();
                let b = pop!();
                push!(if a < b { U256::from(1u64) } else { U256::ZERO });
                pc += 1;
            }
            // GT
            0x11 => {
                charge_gas!(3);
                let a = pop!();
                let b = pop!();
                push!(if a > b { U256::from(1u64) } else { U256::ZERO });
                pc += 1;
            }
            // SLT
            0x12 => {
                charge_gas!(3);
                let a = pop!();
                let b = pop!();
                push!(if signed_lt(a, b) {
                    U256::from(1u64)
                } else {
                    U256::ZERO
                });
                pc += 1;
            }
            // SGT
            0x13 => {
                charge_gas!(3);
                let a = pop!();
                let b = pop!();
                push!(if signed_lt(b, a) {
                    U256::from(1u64)
                } else {
                    U256::ZERO
                });
                pc += 1;
            }
            // EQ
            0x14 => {
                charge_gas!(3);
                let a = pop!();
                let b = pop!();
                push!(if a == b { U256::from(1u64) } else { U256::ZERO });
                pc += 1;
            }
            // ISZERO
            0x15 => {
                charge_gas!(3);
                let a = pop!();
                push!(if a.is_zero() {
                    U256::from(1u64)
                } else {
                    U256::ZERO
                });
                pc += 1;
            }
            // AND
            0x16 => {
                charge_gas!(3);
                let a = pop!();
                let b = pop!();
                push!(a & b);
                pc += 1;
            }
            // OR
            0x17 => {
                charge_gas!(3);
                let a = pop!();
                let b = pop!();
                push!(a | b);
                pc += 1;
            }
            // XOR
            0x18 => {
                charge_gas!(3);
                let a = pop!();
                let b = pop!();
                push!(a ^ b);
                pc += 1;
            }
            // NOT
            0x19 => {
                charge_gas!(3);
                let a = pop!();
                push!(!a);
                pc += 1;
            }
            // BYTE
            0x1a => {
                charge_gas!(3);
                let i = pop!();
                let x = pop!();
                if i < U256::from(32u64) {
                    let bytes: [u8; 32] = x.to_be_bytes();
                    push!(U256::from(bytes[i.to::<usize>()]));
                } else {
                    push!(U256::ZERO);
                }
                pc += 1;
            }
            // SHL
            0x1b => {
                charge_gas!(3);
                let shift = pop!();
                let val = pop!();
                if shift >= U256::from(256u64) {
                    push!(U256::ZERO);
                } else {
                    push!(val << shift.to::<usize>());
                }
                pc += 1;
            }
            // SHR
            0x1c => {
                charge_gas!(3);
                let shift = pop!();
                let val = pop!();
                if shift >= U256::from(256u64) {
                    push!(U256::ZERO);
                } else {
                    push!(val >> shift.to::<usize>());
                }
                pc += 1;
            }
            // SAR
            0x1d => {
                charge_gas!(3);
                let shift = pop!();
                let val = pop!();
                let is_neg = val.bit(255);
                if shift >= U256::from(256u64) {
                    push!(if is_neg { U256::MAX } else { U256::ZERO });
                } else {
                    let s = shift.to::<usize>();
                    if s == 0 {
                        push!(val);
                    } else if is_neg {
                        let shifted = val >> s;
                        let mask = U256::MAX << (256 - s);
                        push!(shifted | mask);
                    } else {
                        push!(val >> s);
                    }
                }
                pc += 1;
            }
            // KECCAK256
            0x20 => {
                let offset = pop!();
                let size = pop!();
                let (off, sz) = mem_expand!(offset, size);
                let words = (sz as u64).div_ceil(32);
                charge_gas!(30u64.saturating_add(6u64.saturating_mul(words)));
                let hash = if sz == 0 {
                    KECCAK_EMPTY
                } else {
                    keccak256(&memory[off..off + sz])
                };
                push!(U256::from_be_bytes(hash.0));
                pc += 1;
            }
            // ADDRESS
            0x30 => {
                charge_gas!(2);
                push!(address_to_u256(frame.address));
                pc += 1;
            }
            // BALANCE
            0x31 => {
                let addr_u256 = pop!();
                let addr = u256_to_address(addr_u256);
                let access_gas = state.access_address(addr);
                charge_gas!(access_gas);
                let bal = state.balance(db, addr);
                push!(bal);
                pc += 1;
            }
            // ORIGIN
            0x32 => {
                charge_gas!(2);
                push!(address_to_u256(frame.origin));
                pc += 1;
            }
            // CALLER
            0x33 => {
                charge_gas!(2);
                push!(address_to_u256(frame.caller));
                pc += 1;
            }
            // CALLVALUE
            0x34 => {
                charge_gas!(2);
                push!(frame.callvalue);
                pc += 1;
            }
            // CALLDATALOAD
            0x35 => {
                charge_gas!(3);
                let offset = pop!();
                let mut buf = [0u8; 32];
                if let Some(off) = u256_to_usize(offset) {
                    if off < frame.calldata.len() {
                        let copy_len = (frame.calldata.len() - off).min(32);
                        buf[..copy_len].copy_from_slice(&frame.calldata[off..off + copy_len]);
                    }
                }
                push!(U256::from_be_bytes(buf));
                pc += 1;
            }
            // CALLDATASIZE
            0x36 => {
                charge_gas!(2);
                push!(U256::from(frame.calldata.len()));
                pc += 1;
            }
            // CALLDATACOPY
            0x37 => {
                let dest_offset = pop!();
                let data_offset = pop!();
                let size = pop!();
                let (dest_off, sz) = mem_expand!(dest_offset, size);
                let words = (sz as u64).div_ceil(32);
                charge_gas!(3u64.saturating_add(3u64.saturating_mul(words)));
                if sz > 0 {
                    memory[dest_off..dest_off + sz].fill(0);
                    if let Some(src_off) = u256_to_usize(data_offset) {
                        if src_off < frame.calldata.len() {
                            let copy_len = (frame.calldata.len() - src_off).min(sz);
                            memory[dest_off..dest_off + copy_len]
                                .copy_from_slice(&frame.calldata[src_off..src_off + copy_len]);
                        }
                    }
                }
                pc += 1;
            }
            // CODESIZE
            0x38 => {
                charge_gas!(2);
                push!(U256::from(code_bytes.len()));
                pc += 1;
            }
            // CODECOPY
            0x39 => {
                let dest_offset = pop!();
                let code_offset = pop!();
                let size = pop!();
                let (dest_off, sz) = mem_expand!(dest_offset, size);
                let words = (sz as u64).div_ceil(32);
                charge_gas!(3u64.saturating_add(3u64.saturating_mul(words)));
                if sz > 0 {
                    memory[dest_off..dest_off + sz].fill(0);
                    if let Some(src_off) = u256_to_usize(code_offset) {
                        if src_off < code_bytes.len() {
                            let copy_len = (code_bytes.len() - src_off).min(sz);
                            memory[dest_off..dest_off + copy_len]
                                .copy_from_slice(&code_bytes[src_off..src_off + copy_len]);
                        }
                    }
                }
                pc += 1;
            }
            // GASPRICE
            0x3a => {
                charge_gas!(2);
                push!(U256::from(GAS_PRICE));
                pc += 1;
            }
            // EXTCODESIZE
            0x3b => {
                let addr = u256_to_address(pop!());
                let access_gas = state.access_address(addr);
                charge_gas!(access_gas);
                let ext_code = state.code(db, addr);
                push!(U256::from(ext_code.bytes().len()));
                pc += 1;
            }
            // EXTCODECOPY
            0x3c => {
                let addr = u256_to_address(pop!());
                let dest_offset = pop!();
                let code_offset = pop!();
                let size = pop!();
                let access_gas = state.access_address(addr);
                charge_gas!(access_gas);
                let (dest_off, sz) = mem_expand!(dest_offset, size);
                let words = (sz as u64).div_ceil(32);
                charge_gas!(3u64.saturating_mul(words));
                if sz > 0 {
                    let ext_code = state.code(db, addr);
                    let ext_bytes = ext_code.bytes();
                    memory[dest_off..dest_off + sz].fill(0);
                    if let Some(src_off) = u256_to_usize(code_offset) {
                        if src_off < ext_bytes.len() {
                            let copy_len = (ext_bytes.len() - src_off).min(sz);
                            memory[dest_off..dest_off + copy_len]
                                .copy_from_slice(&ext_bytes[src_off..src_off + copy_len]);
                        }
                    }
                }
                pc += 1;
            }
            // RETURNDATASIZE
            0x3d => {
                charge_gas!(2);
                push!(U256::from(return_data.len()));
                pc += 1;
            }
            // RETURNDATACOPY
            0x3e => {
                let dest_offset = pop!();
                let data_offset = pop!();
                let size = pop!();
                let Some(src_off) = u256_to_usize(data_offset) else {
                    return FrameResult::Halt {
                        reason: "returndatacopy offset out of bounds".to_owned(),
                    };
                };
                let Some(sz) = u256_to_usize(size) else {
                    return FrameResult::Halt {
                        reason: "returndatacopy size out of bounds".to_owned(),
                    };
                };
                if src_off.checked_add(sz).is_none_or(|end| end > return_data.len()) {
                    return FrameResult::Halt {
                        reason: "returndatacopy out of bounds".to_owned(),
                    };
                }
                let (dest_off, _) = mem_expand!(dest_offset, size);
                let words = (sz as u64).div_ceil(32);
                charge_gas!(3u64.saturating_add(3u64.saturating_mul(words)));
                if sz > 0 {
                    memory[dest_off..dest_off + sz]
                        .copy_from_slice(&return_data[src_off..src_off + sz]);
                }
                pc += 1;
            }
            // EXTCODEHASH
            0x3f => {
                let addr = u256_to_address(pop!());
                let access_gas = state.access_address(addr);
                charge_gas!(access_gas);
                if state.is_empty_account(db, addr) {
                    push!(U256::ZERO);
                } else {
                    let hash = state.accounts[&addr].info.code_hash;
                    push!(U256::from_be_bytes(hash.0));
                }
                pc += 1;
            }
            // BLOCKHASH
            0x40 => {
                charge_gas!(20);
                let num_u256 = pop!();
                let hash = if let Some(num) = u256_to_usize(num_u256) {
                    let num = num as u64;
                    if num < block.number && block.number.saturating_sub(num) <= 256 {
                        db.block_hash(num).unwrap_or(B256::ZERO)
                    } else {
                        B256::ZERO
                    }
                } else {
                    B256::ZERO
                };
                push!(U256::from_be_bytes(hash.0));
                pc += 1;
            }
            // COINBASE
            0x41 => {
                charge_gas!(2);
                push!(address_to_u256(block.miner));
                pc += 1;
            }
            // TIMESTAMP
            0x42 => {
                charge_gas!(2);
                push!(U256::from(block.timestamp));
                pc += 1;
            }
            // NUMBER
            0x43 => {
                charge_gas!(2);
                push!(U256::from(block.number));
                pc += 1;
            }
            // PREVRANDAO / DIFFICULTY
            0x44 => {
                charge_gas!(2);
                if block.prevrandao != B256::ZERO {
                    push!(U256::from_be_bytes(block.prevrandao.0));
                } else {
                    push!(U256::from(block.difficulty));
                }
                pc += 1;
            }
            // GASLIMIT
            0x45 => {
                charge_gas!(2);
                push!(U256::from(block.gas_limit));
                pc += 1;
            }
            // CHAINID
            0x46 => {
                charge_gas!(2);
                push!(U256::from(CHAIN_ID));
                pc += 1;
            }
            // SELFBALANCE
            0x47 => {
                charge_gas!(5);
                let bal = state.balance(db, frame.address);
                push!(bal);
                pc += 1;
            }
            // BASEFEE
            0x48 => {
                charge_gas!(2);
                push!(U256::ZERO);
                pc += 1;
            }
            // POP
            0x50 => {
                charge_gas!(2);
                let _ = pop!();
                pc += 1;
            }
            // MLOAD
            0x51 => {
                let offset = pop!();
                let (off, _) = mem_expand!(offset, U256::from(32u64));
                charge_gas!(3);
                let mut word = [0u8; 32];
                word.copy_from_slice(&memory[off..off + 32]);
                push!(U256::from_be_bytes(word));
                pc += 1;
            }
            // MSTORE
            0x52 => {
                let offset = pop!();
                let val = pop!();
                let (off, _) = mem_expand!(offset, U256::from(32u64));
                charge_gas!(3);
                let bytes: [u8; 32] = val.to_be_bytes();
                memory[off..off + 32].copy_from_slice(&bytes);
                pc += 1;
            }
            // MSTORE8
            0x53 => {
                let offset = pop!();
                let val = pop!();
                let (off, _) = mem_expand!(offset, U256::from(1u64));
                charge_gas!(3);
                let bytes: [u8; 32] = val.to_be_bytes();
                memory[off] = bytes[31];
                pc += 1;
            }
            // SLOAD
            0x54 => {
                let slot = pop!();
                let (val, s_gas) = state.sload(db, frame.address, slot);
                charge_gas!(s_gas);
                push!(val);
                pc += 1;
            }
            // SSTORE
            0x55 => {
                if frame.is_static {
                    return FrameResult::Halt {
                        reason: "SSTORE in static call".to_owned(),
                    };
                }
                // EIP-2200: fail if gas left <= 2300 call stipend.
                if frame.gas_limit.saturating_sub(gas_used) <= 2_300 {
                    return FrameResult::Halt {
                        reason: "SSTORE with gas left <= 2300".to_owned(),
                    };
                }
                let slot = pop!();
                let val = pop!();
                let s_gas = state.sstore(db, frame.address, slot, val);
                charge_gas!(s_gas);
                pc += 1;
            }
            // JUMP
            0x56 => {
                charge_gas!(8);
                let dest = pop!();
                let Some(dest_pc) = u256_to_usize(dest) else {
                    return FrameResult::Halt {
                        reason: "invalid jump destination".to_owned(),
                    };
                };
                if !frame.code.is_valid_jumpdest(dest_pc) {
                    return FrameResult::Halt {
                        reason: format!("invalid jump destination {dest_pc}"),
                    };
                }
                pc = dest_pc;
            }
            // JUMPI
            0x57 => {
                charge_gas!(10);
                let dest = pop!();
                let cond = pop!();
                if !cond.is_zero() {
                    let Some(dest_pc) = u256_to_usize(dest) else {
                        return FrameResult::Halt {
                            reason: "invalid jumpi destination".to_owned(),
                        };
                    };
                    if !frame.code.is_valid_jumpdest(dest_pc) {
                        return FrameResult::Halt {
                            reason: format!("invalid jumpi destination {dest_pc}"),
                        };
                    }
                    pc = dest_pc;
                } else {
                    pc += 1;
                }
            }
            // PC
            0x58 => {
                charge_gas!(2);
                push!(U256::from(pc));
                pc += 1;
            }
            // MSIZE
            0x59 => {
                charge_gas!(2);
                push!(U256::from(memory.len()));
                pc += 1;
            }
            // GAS
            0x5a => {
                charge_gas!(2);
                push!(U256::from(frame.gas_limit.saturating_sub(gas_used)));
                pc += 1;
            }
            // JUMPDEST
            0x5b => {
                charge_gas!(1);
                pc += 1;
            }
            // PUSH0 (EIP-3855 Shanghai)
            0x5f => {
                charge_gas!(2);
                push!(U256::ZERO);
                pc += 1;
            }
            // PUSH1..=PUSH32
            0x60..=0x7f => {
                charge_gas!(3);
                let n = (op - 0x5f) as usize;
                let mut buf = [0u8; 32];
                let avail = code_bytes.len().saturating_sub(pc + 1).min(n);
                buf[32 - n..32 - n + avail].copy_from_slice(&code_bytes[pc + 1..pc + 1 + avail]);
                push!(U256::from_be_bytes(buf));
                pc += 1 + n;
            }
            // DUP1..=DUP16
            0x80..=0x8f => {
                charge_gas!(3);
                let n = (op - 0x7f) as usize;
                if stack.len() < n {
                    return FrameResult::Halt {
                        reason: "stack underflow on DUP".to_owned(),
                    };
                }
                let val = stack[stack.len() - n];
                push!(val);
                pc += 1;
            }
            // SWAP1..=SWAP16
            0x90..=0x9f => {
                charge_gas!(3);
                let n = (op - 0x8f) as usize;
                if stack.len() <= n {
                    return FrameResult::Halt {
                        reason: "stack underflow on SWAP".to_owned(),
                    };
                }
                let top = stack.len() - 1;
                stack.swap(top, top - n);
                pc += 1;
            }
            // LOG0..=LOG4
            0xa0..=0xa4 => {
                if frame.is_static {
                    return FrameResult::Halt {
                        reason: "LOG in static call".to_owned(),
                    };
                }
                let topic_count = (op - 0xa0) as usize;
                let offset = pop!();
                let size = pop!();
                let mut topics = Vec::with_capacity(topic_count);
                for _ in 0..topic_count {
                    let t = pop!();
                    topics.push(B256::from(t.to_be_bytes()));
                }
                let (off, sz) = mem_expand!(offset, size);
                let log_gas = 375u64
                    .saturating_add(375u64.saturating_mul(topic_count as u64))
                    .saturating_add(8u64.saturating_mul(sz as u64));
                charge_gas!(log_gas);
                let data = if sz == 0 {
                    Bytes::new()
                } else {
                    Bytes::copy_from_slice(&memory[off..off + sz])
                };
                state.logs.push(Log {
                    address: frame.address,
                    topics,
                    data,
                });
                pc += 1;
            }
            // CREATE / CREATE2
            0xf0 | 0xf5 => {
                if frame.is_static {
                    return FrameResult::Halt {
                        reason: "CREATE in static call".to_owned(),
                    };
                }
                let value = pop!();
                let offset = pop!();
                let size = pop!();
                let salt = if op == 0xf5 { Some(pop!()) } else { None };
                let (off, sz) = mem_expand!(offset, size);
                if sz > MAX_INITCODE_SIZE {
                    return FrameResult::Halt {
                        reason: "EIP-3860: initcode size exceeded".to_owned(),
                    };
                }
                let words = (sz as u64).div_ceil(32);
                let initcode_word_cost = if op == 0xf5 { 8 * words } else { 2 * words };
                charge_gas!(32_000u64.saturating_add(initcode_word_cost));

                let initcode = if sz == 0 {
                    Bytes::new()
                } else {
                    Bytes::copy_from_slice(&memory[off..off + sz])
                };

                let rem_gas = frame.gas_limit.saturating_sub(gas_used);
                let child_gas = rem_gas - rem_gas / 64;
                charge_gas!(child_gas);

                let creator_nonce = state.nonce(db, frame.address);
                state.set_nonce(db, frame.address, creator_nonce + 1);

                let created_addr = if let Some(salt_val) = salt {
                    derive_create2_address(frame.address, salt_val, &initcode)
                } else {
                    derive_contract_address(frame.address, creator_nonce)
                };
                state.warm_addresses.insert(created_addr);

                let checkpoint = state.clone();
                match execute_create_frame(
                    db,
                    state,
                    block,
                    frame.origin,
                    frame.address,
                    created_addr,
                    value,
                    initcode,
                    child_gas,
                    frame.depth + 1,
                ) {
                    FrameResult::Success {
                        gas_used: child_used,
                        ..
                    } => {
                        gas_used -= child_gas.saturating_sub(child_used);
                        return_data = Bytes::new();
                        push!(address_to_u256(created_addr));
                    }
                    FrameResult::Revert {
                        gas_used: child_used,
                        output,
                    } => {
                        *state = checkpoint;
                        gas_used -= child_gas.saturating_sub(child_used);
                        return_data = output;
                        push!(U256::ZERO);
                    }
                    FrameResult::Halt { .. } => {
                        *state = checkpoint;
                        return_data = Bytes::new();
                        push!(U256::ZERO);
                    }
                }
                pc += 1;
            }
            // CALL / CALLCODE / DELEGATECALL / STATICCALL
            0xf1 | 0xf2 | 0xf4 | 0xfa => {
                let gas_arg = pop!();
                let target_addr = u256_to_address(pop!());
                let value = if op == 0xf1 || op == 0xf2 {
                    pop!()
                } else {
                    U256::ZERO
                };
                let args_offset = pop!();
                let args_size = pop!();
                let ret_offset = pop!();
                let ret_size = pop!();

                if frame.is_static && op == 0xf1 && !value.is_zero() {
                    return FrameResult::Halt {
                        reason: "value transfer in static call".to_owned(),
                    };
                }

                let (args_off, args_sz) = mem_expand!(args_offset, args_size);
                let (ret_off, ret_sz) = mem_expand!(ret_offset, ret_size);

                let access_gas = state.access_address(target_addr);
                let mut extra_gas = access_gas;
                if (op == 0xf1 || op == 0xf2) && !value.is_zero() {
                    extra_gas += 9_000;
                    if op == 0xf1 && state.is_empty_account(db, target_addr) {
                        extra_gas += 25_000;
                    }
                }
                charge_gas!(extra_gas);

                let rem_gas = frame.gas_limit.saturating_sub(gas_used);
                let max_call_gas = rem_gas - rem_gas / 64;
                let requested_gas = u256_to_usize(gas_arg)
                    .map(|g| g as u64)
                    .unwrap_or(u64::MAX);
                let forwarded_gas = requested_gas.min(max_call_gas);
                charge_gas!(forwarded_gas);

                let stipend = if (op == 0xf1 || op == 0xf2) && !value.is_zero() {
                    2_300
                } else {
                    0
                };
                let child_gas_limit = forwarded_gas + stipend;

                let input = if args_sz == 0 {
                    Bytes::new()
                } else {
                    Bytes::copy_from_slice(&memory[args_off..args_off + args_sz])
                };

                let checkpoint = state.clone();
                let call_outcome = if frame.depth >= 1024 {
                    FrameResult::Revert {
                        gas_used: 0,
                        output: Bytes::new(),
                    }
                } else if (op == 0xf1 || op == 0xf2)
                    && !value.is_zero()
                    && !state.transfer(
                        db,
                        frame.address,
                        if op == 0xf1 {
                            target_addr
                        } else {
                            frame.address
                        },
                        value,
                    )
                {
                    FrameResult::Revert {
                        gas_used: 0,
                        output: Bytes::new(),
                    }
                } else if is_identity_precompile(target_addr) {
                    let words = (input.len() as u64).div_ceil(32);
                    let precompile_gas = 15 + 3 * words;
                    if precompile_gas > child_gas_limit {
                        FrameResult::Halt {
                            reason: "out of gas in identity precompile".to_owned(),
                        }
                    } else {
                        FrameResult::Success {
                            gas_used: precompile_gas,
                            output: input,
                        }
                    }
                } else {
                    let target_code = state.code(db, target_addr);
                    if target_code.is_empty() {
                        FrameResult::Success {
                            gas_used: 0,
                            output: Bytes::new(),
                        }
                    } else {
                        let child_frame = FrameEnv {
                            address: if op == 0xf4 || op == 0xf2 {
                                frame.address
                            } else {
                                target_addr
                            },
                            caller: if op == 0xf4 {
                                frame.caller
                            } else {
                                frame.address
                            },
                            origin: frame.origin,
                            callvalue: if op == 0xf4 {
                                frame.callvalue
                            } else {
                                value
                            },
                            calldata: input,
                            code: target_code,
                            gas_limit: child_gas_limit,
                            is_static: frame.is_static || op == 0xfa,
                            depth: frame.depth + 1,
                        };
                        run_frame(db, state, block, child_frame)
                    }
                };

                match call_outcome {
                    FrameResult::Success {
                        gas_used: child_used,
                        output,
                    } => {
                        let unused = child_gas_limit
                            .saturating_sub(child_used)
                            .min(forwarded_gas);
                        gas_used -= unused;
                        return_data = output.clone();
                        let copy_len = ret_sz.min(output.len());
                        if copy_len > 0 {
                            memory[ret_off..ret_off + copy_len]
                                .copy_from_slice(&output[..copy_len]);
                        }
                        push!(U256::from(1u64));
                    }
                    FrameResult::Revert {
                        gas_used: child_used,
                        output,
                    } => {
                        *state = checkpoint;
                        let unused = child_gas_limit
                            .saturating_sub(child_used)
                            .min(forwarded_gas);
                        gas_used -= unused;
                        return_data = output.clone();
                        let copy_len = ret_sz.min(output.len());
                        if copy_len > 0 {
                            memory[ret_off..ret_off + copy_len]
                                .copy_from_slice(&output[..copy_len]);
                        }
                        push!(U256::ZERO);
                    }
                    FrameResult::Halt { .. } => {
                        *state = checkpoint;
                        return_data = Bytes::new();
                        push!(U256::ZERO);
                    }
                }
                pc += 1;
            }
            // RETURN
            0xf3 => {
                let offset = pop!();
                let size = pop!();
                let (off, sz) = mem_expand!(offset, size);
                let out = if sz == 0 {
                    Bytes::new()
                } else {
                    Bytes::copy_from_slice(&memory[off..off + sz])
                };
                return FrameResult::Success {
                    gas_used,
                    output: out,
                };
            }
            // REVERT
            0xfd => {
                let offset = pop!();
                let size = pop!();
                let (off, sz) = mem_expand!(offset, size);
                let out = if sz == 0 {
                    Bytes::new()
                } else {
                    Bytes::copy_from_slice(&memory[off..off + sz])
                };
                return FrameResult::Revert {
                    gas_used,
                    output: out,
                };
            }
            // INVALID
            0xfe => {
                return FrameResult::Halt {
                    reason: "invalid opcode 0xfe".to_owned(),
                };
            }
            // SELFDESTRUCT
            0xff => {
                if frame.is_static {
                    return FrameResult::Halt {
                        reason: "SELFDESTRUCT in static call".to_owned(),
                    };
                }
                let beneficiary = u256_to_address(pop!());
                let is_cold = state.warm_addresses.insert(beneficiary);
                let self_balance = state.balance(db, frame.address);
                let beneficiary_empty = state.is_empty_account(db, beneficiary);
                let mut sd_gas = 5_000;
                if is_cold {
                    sd_gas += GAS_COLD_ACCOUNT_ACCESS;
                }
                if !self_balance.is_zero() && beneficiary_empty {
                    sd_gas += 25_000;
                }
                charge_gas!(sd_gas);
                state.ensure_loaded(db, beneficiary);
                if beneficiary != frame.address {
                    let ben_acc = state.accounts.get_mut(&beneficiary).unwrap();
                    ben_acc.info.balance = ben_acc.info.balance.saturating_add(self_balance);
                    ben_acc.is_touched = true;
                }
                let self_acc = state.accounts.get_mut(&frame.address).unwrap();
                self_acc.info.balance = U256::ZERO;
                self_acc.is_touched = true;
                self_acc.is_selfdestructed = true;
                return FrameResult::Success {
                    gas_used,
                    output: Bytes::new(),
                };
            }
            other => {
                return FrameResult::Halt {
                    reason: format!("unknown or invalid opcode 0x{other:02x}"),
                };
            }
        }
    }

    // Falling off the end of bytecode is an implicit STOP.
    FrameResult::Success {
        gas_used,
        output: Bytes::new(),
    }
}

fn is_identity_precompile(addr: Address) -> bool {
    let mut id_bytes = [0u8; 20];
    id_bytes[19] = 4;
    addr == Address::from(id_bytes)
}

fn derive_create2_address(sender: Address, salt: U256, initcode: &[u8]) -> Address {
    let mut buf = [0u8; 1 + 20 + 32 + 32];
    buf[0] = 0xff;
    buf[1..21].copy_from_slice(sender.as_slice());
    let salt_bytes: [u8; 32] = salt.to_be_bytes();
    buf[21..53].copy_from_slice(&salt_bytes);
    let code_hash = keccak256(initcode);
    buf[53..85].copy_from_slice(code_hash.as_slice());
    let hash = keccak256(buf);
    Address::from_slice(&hash[12..])
}

fn signed_lt(a: U256, b: U256) -> bool {
    let a_neg = a.bit(255);
    let b_neg = b.bit(255);
    match (a_neg, b_neg) {
        (true, false) => true,
        (false, true) => false,
        _ => a < b,
    }
}

fn signed_div(a: U256, b: U256) -> U256 {
    if b.is_zero() {
        return U256::ZERO;
    }
    let min_int = U256::from(1u64) << 255;
    if a == min_int && b == U256::MAX {
        return min_int;
    }
    let a_neg = a.bit(255);
    let b_neg = b.bit(255);
    let abs_a = if a_neg { (!a).wrapping_add(U256::from(1u64)) } else { a };
    let abs_b = if b_neg { (!b).wrapping_add(U256::from(1u64)) } else { b };
    let quot = abs_a / abs_b;
    if a_neg ^ b_neg {
        (!quot).wrapping_add(U256::from(1u64))
    } else {
        quot
    }
}

fn signed_mod(a: U256, b: U256) -> U256 {
    if b.is_zero() {
        return U256::ZERO;
    }
    let a_neg = a.bit(255);
    let b_neg = b.bit(255);
    let abs_a = if a_neg { (!a).wrapping_add(U256::from(1u64)) } else { a };
    let abs_b = if b_neg { (!b).wrapping_add(U256::from(1u64)) } else { b };
    let rem = abs_a % abs_b;
    if a_neg && !rem.is_zero() {
        (!rem).wrapping_add(U256::from(1u64))
    } else {
        rem
    }
}

fn decode_revert_reason(output: &Bytes) -> String {
    if output.is_empty() {
        return "execution reverted".to_owned();
    }
    // Standard Solidity `Error(string)` selector `0x08c379a0`
    if output.len() >= 68 && output[..4] == [0x08, 0xc3, 0x79, 0xa0] {
        let len_word = U256::from_be_slice(&output[36..68]);
        if let Some(len) = u256_to_usize(len_word) {
            if output.len() >= 68 + len {
                if let Ok(msg) = std::str::from_utf8(&output[68..68 + len]) {
                    return format!("execution reverted: {msg}");
                }
            }
        }
    }
    format!("execution reverted: {output}")
}

#[cfg(test)]
mod tests {
    use primitives::constants::{DEV_ADDRESS, DEV_ADDRESS_1, TRANSFER_GAS};

    use super::*;

    fn one_eth() -> U256 {
        U256::from(10u64).pow(U256::from(18))
    }

    #[test]
    fn database_basic_returns_funded_account_and_none_for_unknown() {
        let mut accounts = HashMap::new();
        accounts.insert(DEV_ADDRESS, Account::new(one_eth() * U256::from(5u64)));

        let mut db = BreejaDb::new(&mut accounts);
        let funded = db.basic(DEV_ADDRESS).unwrap().expect("funded account exists");
        assert_eq!(funded.balance, one_eth() * U256::from(5u64));
        assert_eq!(funded.nonce, 0);
        assert_eq!(funded.code_hash, KECCAK_EMPTY);
        assert!(funded.code.is_none());

        let unknown = db.basic(Address::repeat_byte(0x42)).unwrap();
        assert!(unknown.is_none());
    }

    #[test]
    fn database_commit_persists_balance_nonce_code_and_storage() {
        let mut accounts = HashMap::new();
        let target = Address::repeat_byte(0x11);
        let code_bytes = Bytes::from_static(&[0x60, 0x2a, 0x60, 0x00, 0x55, 0x00]);
        let slot_key = U256::from(0u64);
        let slot_val = U256::from(42u64);

        let mut evm_account = EvmAccount {
            info: AccountInfo {
                balance: one_eth(),
                nonce: 1,
                code_hash: keccak256(&code_bytes),
                code: Some(Bytecode::new_raw(code_bytes.clone())),
            },
            storage: HashMap::new(),
            is_touched: true,
            is_selfdestructed: false,
        };
        evm_account
            .storage
            .insert(slot_key, EvmStorageSlot::new_changed(U256::ZERO, slot_val));

        let mut changes = HashMap::new();
        changes.insert(target, evm_account);

        {
            let mut db = BreejaDb::new(&mut accounts);
            db.commit(changes);
        }

        let stored = &accounts[&target];
        assert_eq!(stored.balance, one_eth());
        assert_eq!(stored.nonce, 1);
        assert_eq!(stored.code, code_bytes);
        assert_eq!(stored.storage.get(&slot_key).copied(), Some(slot_val));

        let mut db = BreejaDb::new(&mut accounts);
        let basic = db.basic(target).unwrap().unwrap();
        assert_eq!(basic.balance, one_eth());
        assert_eq!(basic.nonce, 1);
        assert_eq!(basic.code.unwrap().bytes(), &code_bytes);
        assert_eq!(db.storage(target, slot_key).unwrap(), slot_val);
    }

    #[test]
    fn evm_transfer_matches_21000_gas_and_updates_balances() {
        let miner = Address::repeat_byte(0x99);
        let mut accounts = HashMap::new();
        accounts.insert(DEV_ADDRESS, Account::new(one_eth() * U256::from(10u64)));

        let tx = PendingTransaction {
            hash: B256::repeat_byte(0xab),
            from: DEV_ADDRESS,
            to: DEV_ADDRESS_1,
            is_create: false,
            value: one_eth(),
            input: Bytes::new(),
            nonce: 0,
            gas: TRANSFER_GAS,
            gas_price: GAS_PRICE,
            chain_id: CHAIN_ID,
            v: 37,
            r: U256::ZERO,
            s: U256::ZERO,
        };
        let block = BlockContext {
            number: 1,
            miner,
            timestamp: 1_700_000_001,
            gas_limit: 30_000_000,
            difficulty: 4,
            prevrandao: B256::ZERO,
        };

        let outcome = execute_tx(&mut accounts, &tx, &block, HashMap::new()).unwrap();
        assert_eq!(outcome.status, 1);
        assert_eq!(outcome.gas_used, TRANSFER_GAS);

        let fee = U256::from(TRANSFER_GAS) * U256::from(GAS_PRICE);
        assert_eq!(
            accounts[&DEV_ADDRESS].balance,
            one_eth() * U256::from(9u64) - fee
        );
        assert_eq!(accounts[&DEV_ADDRESS].nonce, 1);
        assert_eq!(accounts[&DEV_ADDRESS_1].balance, one_eth());
        assert_eq!(accounts[&miner].balance, fee);
    }
}

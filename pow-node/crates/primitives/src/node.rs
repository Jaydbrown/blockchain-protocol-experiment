use std::collections::HashMap;

use alloy::primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_rlp::{Encodable, RlpEncodable};
use serde::{Deserialize, Serialize};

use crate::constants::{
    BLOCK_GAS_LIMIT, EXTRA_DATA, GAS_PRICE, MAX_DIFFICULTY_LEADING_ZEROS,
    MIN_DIFFICULTY_LEADING_ZEROS, TRANSFER_GAS,
};

/// Keccak-256 hash of the empty byte slice `""`.
pub const KECCAK_EMPTY: B256 = B256::new([
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
]);

/// Derives the address of a contract deployed by `sender` at `nonce` (`CREATE` rule:
/// `keccak256(rlp([sender, nonce]))[12..]`).
pub fn derive_contract_address(sender: Address, nonce: u64) -> Address {
    let mut buf = Vec::new();
    let payload_len = sender.length() + nonce.length();
    alloy_rlp::Header {
        list: true,
        payload_length: payload_len,
    }
    .encode(&mut buf);
    sender.encode(&mut buf);
    nonce.encode(&mut buf);
    let hash = keccak256(&buf);
    Address::from_slice(&hash[12..])
}

/// An EVM log emitted by `LOG0`–`LOG4` during contract execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, RlpEncodable)]
#[serde(rename_all = "camelCase")]
pub struct Log {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
}

/// An Ethereum account: externally owned or contract.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub nonce: u64,
    pub balance: U256,
    pub storage_root: B256,
    pub code_hash: B256,
    #[serde(default)]
    pub code: Bytes,
    #[serde(default)]
    pub storage: HashMap<U256, U256>,
}

impl Encodable for Account {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let storage_root = if self.storage.is_empty() {
            self.storage_root
        } else {
            storage_root_of(&self.storage)
        };
        let code_hash = if self.code.is_empty() {
            self.code_hash
        } else {
            keccak256(&self.code)
        };
        let payload_len = self.nonce.length()
            + self.balance.length()
            + storage_root.length()
            + code_hash.length();
        alloy_rlp::Header {
            list: true,
            payload_length: payload_len,
        }
        .encode(out);
        self.nonce.encode(out);
        self.balance.encode(out);
        storage_root.encode(out);
        code_hash.encode(out);
    }

    fn length(&self) -> usize {
        let storage_root = if self.storage.is_empty() {
            self.storage_root
        } else {
            storage_root_of(&self.storage)
        };
        let code_hash = if self.code.is_empty() {
            self.code_hash
        } else {
            keccak256(&self.code)
        };
        let payload_len = self.nonce.length()
            + self.balance.length()
            + storage_root.length()
            + code_hash.length();
        alloy_rlp::length_of_length(payload_len) + payload_len
    }
}

/// Computes a deterministic commitment over a contract's non-zero storage slots.
pub fn storage_root_of(storage: &HashMap<U256, U256>) -> B256 {
    let mut entries: Vec<(&U256, &U256)> = storage
        .iter()
        .filter(|(_, val)| !val.is_zero())
        .collect();
    if entries.is_empty() {
        return B256::ZERO;
    }
    entries.sort_by_key(|(slot, _)| **slot);

    let mut buf = Vec::with_capacity(entries.len() * 64);
    for (slot, value) in entries {
        buf.extend_from_slice(&slot.to_be_bytes::<32>());
        buf.extend_from_slice(&value.to_be_bytes::<32>());
    }
    keccak256(buf)
}

/// Computes the 2048-bit (256-byte) Ethereum Yellow Paper Bloom filter (`M3:2048`)
/// over a slice of logs.
pub fn compute_logs_bloom(logs: &[Log]) -> Bytes {
    let mut bloom = [0u8; 256];
    for log in logs {
        bloom_insert(&mut bloom, log.address.as_slice());
        for topic in &log.topics {
            bloom_insert(&mut bloom, topic.as_slice());
        }
    }
    Bytes::copy_from_slice(&bloom)
}

fn bloom_insert(bloom: &mut [u8; 256], data: &[u8]) {
    let hash = keccak256(data);
    for i in [0usize, 2, 4] {
        let bit_index = (((hash[i] as usize) << 8) | (hash[i + 1] as usize)) & 2047;
        let byte_index = 255 - (bit_index / 8);
        let bit_mask = 1u8 << (bit_index % 8);
        bloom[byte_index] |= bit_mask;
    }
}

/// Computes the Shanghai intrinsic gas cost of a transaction.
///
/// - Base cost: `21,000` gas (`TRANSFER_GAS`)
/// - Calldata: `4` gas per zero byte, `16` gas per non-zero byte
/// - Contract creation (`is_create`): `+32,000` gas plus EIP-3860 initcode word cost
///   (`2` gas per 32-byte word of initcode)
pub fn intrinsic_gas(input: &[u8], is_create: bool) -> u64 {
    let mut gas = TRANSFER_GAS;
    for &byte in input {
        if byte == 0 {
            gas = gas.saturating_add(4);
        } else {
            gas = gas.saturating_add(16);
        }
    }
    if is_create {
        gas = gas.saturating_add(32_000);
        let words = (input.len() as u64).div_ceil(32);
        gas = gas.saturating_add(words.saturating_mul(2));
    }
    gas
}

/// A sealed block.
///
/// Everything above `hash` is the *header*: the bytes that are hashed to produce
/// `hash`. `nonce` and `hash` are the proof of work — the miner searches for a
/// `nonce` that makes `hash` small enough to satisfy `difficulty`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    pub number: u64,
    pub parent_hash: B256,
    pub state_root: B256,
    pub transaction_root: B256,
    pub receipts_root: B256,
    /// Number of leading zero bits `hash` must have for this block to be valid.
    pub difficulty: u8,
    /// Sum of every ancestor's difficulty plus this block's. The heaviest chain
    /// wins, which is what makes proof of work a consensus rule and not just a
    /// puzzle.
    pub total_difficulty: u64,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub miner: Address,
    pub extra_data: Bytes,
    /// The proof-of-work solution.
    pub nonce: u64,
    /// `keccak256(rlp(header))`, which is only valid once `nonce` has been found.
    pub hash: B256,
    /// Hashes of the transactions this block executed, in execution order.
    pub transactions: Vec<B256>,
}

/// The part of a [`Block`] that the proof of work commits to.
///
/// This is a separate struct so that the hashed bytes are unambiguous: RLP
/// encode exactly these fields, in exactly this order, and hash the result.
/// Mining is the search for a `nonce` that makes that hash small enough.
#[derive(Debug, Clone, RlpEncodable)]
pub struct BlockHeader {
    pub number: u64,
    pub parent_hash: B256,
    pub state_root: B256,
    pub transaction_root: B256,
    pub receipts_root: B256,
    pub difficulty: u8,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub miner: Address,
    pub extra_data: Bytes,
    pub nonce: u64,
}

/// A transaction that has been included in a block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub hash: B256,
    pub block_hash: B256,
    pub block_number: u64,
    pub transaction_index: u64,
    pub chain_id: u64,
    pub from: Address,
    pub to: Address,
    #[serde(default)]
    pub is_create: bool,
    pub value: U256,
    pub nonce: u64,
    pub gas: u64,
    pub gas_price: u128,
    pub input: Bytes,
    pub v: u64,
    pub r: U256,
    pub s: U256,
}

/// The receipt proving what a transaction did.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionReceipt {
    pub transaction_hash: B256,
    pub transaction_index: u64,
    pub block_hash: B256,
    pub block_number: u64,
    pub from: Address,
    pub to: Address,
    #[serde(default)]
    pub is_create: bool,
    pub gas_used: u64,
    pub cummulative_gas_used: u64,
    pub effective_gas_price: u128,
    #[serde(default)]
    pub contract_address: Option<Address>,
    #[serde(default)]
    pub logs: Vec<Log>,
    #[serde(default)]
    pub logs_bloom: Bytes,
    /// `1` for success, `0` for revert or halt.
    pub status: u8,
}

/// A transaction that has been accepted into the mempool but not yet mined.
#[derive(Debug, Clone, Default)]
pub struct PendingTransaction {
    pub hash: B256,
    pub from: Address,
    pub to: Address,
    pub is_create: bool,
    pub value: U256,
    pub input: Bytes,
    pub nonce: u64,
    pub gas: u64,
    pub gas_price: u128,
    pub chain_id: u64,
    pub v: u64,
    pub r: U256,
    pub s: U256,
}

/// The accounts a chain starts with, before any block has been mined.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BreejaGenesis {
    pub accounts: Vec<(Address, U256)>,
}

/// Everything the node knows: the current account state, the chain of blocks,
/// the transactions and receipts in them, and the mempool of transactions
/// waiting to be mined.
#[derive(Debug, Clone, Default)]
pub struct BlockState {
    /// Account state as of the chain head.
    accounts: HashMap<Address, Account>,
    /// Blocks by number; `blocks[n]` is the block with `number == n`.
    blocks: Vec<Block>,
    /// Account state as it was *after* each block, so historical balance, nonce,
    /// code, and storage queries can be answered honestly.
    state_history: Vec<HashMap<Address, Account>>,
    /// Block number for a given block hash.
    block_index: HashMap<B256, u64>,
    transactions: HashMap<B256, Transaction>,
    receipts: HashMap<B256, TransactionReceipt>,
    /// Validated transactions waiting to be included in a block, oldest first.
    mempool: Vec<PendingTransaction>,
}

impl Account {
    pub fn new(balance: U256) -> Self {
        Self {
            balance,
            ..Default::default()
        }
    }

    /// Recomputes `code_hash` and `storage_root` from `code` and `storage`.
    pub fn refresh_roots(&mut self) {
        self.code_hash = if self.code.is_empty() {
            B256::ZERO
        } else {
            keccak256(&self.code)
        };
        self.storage_root = storage_root_of(&self.storage);
    }

    /// Consumes this account's current nonce and advances it, the way sending a
    /// transaction does.
    pub fn increase_nonce(&mut self) -> u64 {
        let used_nonce = self.nonce;
        self.nonce += 1;
        used_nonce
    }

    /// Debits `amount`, failing if the account cannot cover it.
    pub fn debit(&mut self, amount: U256) -> Result<U256, anyhow::Error> {
        match self.balance.checked_sub(amount) {
            Some(remaining) => {
                self.balance = remaining;
                Ok(self.balance)
            }
            None => anyhow::bail!(
                "insufficient balance: have {}, need {}",
                self.balance,
                amount
            ),
        }
    }

    /// Credits `amount`.
    pub fn credit(&mut self, amount: U256) -> Result<U256, anyhow::Error> {
        match self.balance.checked_add(amount) {
            Some(total) => {
                self.balance = total;
                Ok(self.balance)
            }
            None => anyhow::bail!("balance overflow crediting {}", amount),
        }
    }
}

impl BlockHeader {
    /// `keccak256(rlp(header))` — the block hash, and the value proof of work
    /// has to drive below the difficulty target.
    pub fn hash(&self) -> B256 {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        keccak256(buf)
    }
}

impl Block {
    /// Rebuilds the header that was hashed to produce [`Block::hash`], so any
    /// node can re-derive the hash and check the proof of work for itself.
    pub fn header(&self) -> BlockHeader {
        BlockHeader {
            number: self.number,
            parent_hash: self.parent_hash,
            state_root: self.state_root,
            transaction_root: self.transaction_root,
            receipts_root: self.receipts_root,
            difficulty: self.difficulty,
            timestamp: self.timestamp,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            miner: self.miner,
            extra_data: self.extra_data.clone(),
            nonce: self.nonce,
        }
    }
}

/// Counts the leading zero bits of a hash.
pub fn leading_zero_bits(hash: &B256) -> u16 {
    let mut bits = 0u16;
    for byte in hash.0.iter() {
        if *byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros() as u16;
            break;
        }
    }
    bits
}

/// Whether `hash` satisfies a difficulty of `difficulty` leading zero bits.
pub fn meets_difficulty(hash: &B256, difficulty: u8) -> bool {
    leading_zero_bits(hash) >= difficulty as u16
}

/// Picks the difficulty for the next block.
pub fn retarget_difficulty(current: u8, actual_ms: u64, target_ms: u64) -> u8 {
    let next = if actual_ms.saturating_mul(2) < target_ms {
        current.saturating_add(1)
    } else if actual_ms > target_ms.saturating_mul(2) {
        current.saturating_sub(1)
    } else {
        current
    };
    next.clamp(MIN_DIFFICULTY_LEADING_ZEROS, MAX_DIFFICULTY_LEADING_ZEROS)
}

/// Commits to a whole account set (including contract code and storage) in a single hash.
pub fn state_root_of(accounts: &HashMap<Address, Account>) -> B256 {
    let mut entries: Vec<(&Address, &Account)> = accounts.iter().collect();
    entries.sort_by_key(|(address, _)| **address);

    let mut buf = Vec::new();
    for (address, account) in entries {
        buf.extend_from_slice(address.as_slice());
        account.encode(&mut buf);
    }
    keccak256(buf)
}

/// Hashes an ordered list of hashes into a single root.
pub fn hash_list_root(items: &[B256]) -> B256 {
    if items.is_empty() {
        return B256::ZERO;
    }
    let mut buf = Vec::with_capacity(items.len() * 32);
    for item in items {
        buf.extend_from_slice(item.as_slice());
    }
    keccak256(buf)
}

impl BlockState {
    /// Builds the starting state from a genesis definition and seals the genesis
    /// block over it.
    pub fn new_with_gensis(breeja_gen: BreejaGenesis, difficulty: u8) -> Self {
        let mut accounts = HashMap::new();
        for (address, balance) in breeja_gen.accounts {
            accounts.insert(address, Account::new(balance));
        }

        let mut state = Self {
            accounts,
            ..Default::default()
        };

        let header = BlockHeader {
            number: 0,
            parent_hash: B256::ZERO,
            state_root: state_root_of(&state.accounts),
            transaction_root: B256::ZERO,
            receipts_root: B256::ZERO,
            difficulty,
            timestamp: 0,
            gas_limit: BLOCK_GAS_LIMIT,
            gas_used: 0,
            miner: Address::ZERO,
            extra_data: Bytes::from_static(EXTRA_DATA.as_bytes()),
            nonce: 0,
        };
        let genesis = Block {
            hash: header.hash(),
            total_difficulty: difficulty as u64,
            transactions: Vec::new(),
            number: header.number,
            parent_hash: header.parent_hash,
            state_root: header.state_root,
            transaction_root: header.transaction_root,
            receipts_root: header.receipts_root,
            difficulty: header.difficulty,
            timestamp: header.timestamp,
            gas_limit: header.gas_limit,
            gas_used: header.gas_used,
            miner: header.miner,
            extra_data: header.extra_data.clone(),
            nonce: header.nonce,
        };

        state.block_index.insert(genesis.hash, 0);
        state.blocks.push(genesis);
        state.state_history.push(state.accounts.clone());
        state
    }

    /// Number of the chain head. Genesis is block 0, so a fresh chain is at 0.
    pub fn get_block_number(&self) -> u64 {
        self.blocks.len() as u64 - 1
    }

    pub fn head(&self) -> &Block {
        self.blocks
            .last()
            .expect("chain always contains the genesis block")
    }

    pub fn get_block(&self, number: u64) -> Option<&Block> {
        self.blocks.get(number as usize)
    }

    pub fn get_block_by_hash(&self, hash: &B256) -> Option<&Block> {
        self.block_index
            .get(hash)
            .and_then(|number| self.get_block(*number))
    }

    pub fn get_transaction(&self, hash: &B256) -> Option<&Transaction> {
        self.transactions.get(hash)
    }

    pub fn get_receipt(&self, hash: &B256) -> Option<&TransactionReceipt> {
        self.receipts.get(hash)
    }

    // account, code & storage queries

    /// Account at the chain head.
    pub fn get_account(&self, address: &Address) -> Account {
        self.accounts.get(address).cloned().unwrap_or_default()
    }

    /// Account as it was after block `number`, or `None` if that block does not
    /// exist.
    pub fn get_account_at(&self, address: &Address, number: u64) -> Option<Account> {
        self.state_history
            .get(number as usize)
            .map(|snapshot| snapshot.get(address).cloned().unwrap_or_default())
    }

    /// Contract bytecode at `address` at the chain head (`Bytes::new()` if none).
    pub fn get_code(&self, address: &Address) -> Bytes {
        self.accounts
            .get(address)
            .map(|a| a.code.clone())
            .unwrap_or_default()
    }

    /// Contract bytecode at `address` as of block `number`.
    pub fn get_code_at(&self, address: &Address, number: u64) -> Option<Bytes> {
        self.get_account_at(address, number).map(|a| a.code)
    }

    /// Storage slot `slot` of `address` at the chain head (`U256::ZERO` if unset).
    pub fn get_storage(&self, address: &Address, slot: U256) -> U256 {
        self.accounts
            .get(address)
            .and_then(|a| a.storage.get(&slot).copied())
            .unwrap_or(U256::ZERO)
    }

    /// Storage slot `slot` of `address` as of block `number`.
    pub fn get_storage_at(&self, address: &Address, slot: U256, number: u64) -> Option<U256> {
        self.get_account_at(address, number)
            .map(|a| a.storage.get(&slot).copied().unwrap_or(U256::ZERO))
    }

    /// Full account map as of block `number`.
    pub fn accounts_at(&self, number: u64) -> Option<HashMap<Address, Account>> {
        self.state_history.get(number as usize).cloned()
    }

    /// Map of block numbers to block hashes for `BLOCKHASH` opcode queries.
    pub fn block_hashes_snapshot(&self) -> HashMap<u64, B256> {
        self.blocks.iter().map(|b| (b.number, b.hash)).collect()
    }

    /// The nonce the sender's *next* transaction must carry.
    pub fn get_pending_nonce(&self, address: &Address) -> u64 {
        let mined = self.get_account(address).nonce;
        let queued = self.mempool.iter().filter(|tx| &tx.from == address).count() as u64;
        mined + queued
    }

    /// Balance minus everything the mempool has already committed to spending.
    pub fn get_pending_balance(&self, address: &Address) -> U256 {
        let balance = self.get_account(address).balance;
        let committed: U256 = self
            .mempool
            .iter()
            .filter(|tx| &tx.from == address)
            .map(|tx| tx.value + U256::from(tx.gas) * U256::from(tx.gas_price))
            .fold(U256::ZERO, |acc, cost| acc + cost);
        balance.saturating_sub(committed)
    }

    /// Commits to the account set at the chain head in a single hash.
    pub fn state_root(&self) -> B256 {
        state_root_of(&self.accounts)
    }

    /// A copy of the account state at the head, for the miner to execute against
    /// without holding the state lock.
    pub fn accounts_snapshot(&self) -> HashMap<Address, Account> {
        self.accounts.clone()
    }

    // mempool

    pub fn add_to_mempool(&mut self, tx: PendingTransaction) {
        self.mempool.push(tx);
    }

    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }

    pub fn mempool_contains(&self, hash: &B256) -> bool {
        self.mempool.iter().any(|tx| &tx.hash == hash)
    }

    /// Returns candidate pending transactions for the next block in arrival order.
    /// Actual gas-limit fitting happens during `execute_block` once each
    /// transaction's true EVM gas consumption is measured.
    pub fn peek_mempool_batch(&self) -> Vec<PendingTransaction> {
        self.mempool.clone()
    }

    // block production

    /// Installs a sealed block as the new chain head.
    pub fn commit_block(
        &mut self,
        accounts: HashMap<Address, Account>,
        block: Block,
        transactions: Vec<Transaction>,
        receipts: Vec<TransactionReceipt>,
    ) {
        let mined: Vec<B256> = transactions.iter().map(|tx| tx.hash).collect();
        self.mempool
            .retain(|pending| !mined.contains(&pending.hash));

        self.accounts = accounts;
        self.block_index.insert(block.hash, block.number);
        for tx in transactions {
            self.transactions.insert(tx.hash, tx);
        }
        for receipt in receipts {
            self.receipts.insert(receipt.transaction_hash, receipt);
        }
        self.blocks.push(block);
        self.state_history.push(self.accounts.clone());
    }

    /// Default gas price for a node with no fee market: a constant.
    pub fn gas_price(&self) -> u128 {
        GAS_PRICE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zero_bits_counts_what_it_says() {
        assert_eq!(leading_zero_bits(&B256::ZERO), 256);
        assert_eq!(leading_zero_bits(&B256::repeat_byte(0xff)), 0);

        let mut bytes = [0u8; 32];
        bytes[1] = 0x0f;
        assert_eq!(leading_zero_bits(&B256::new(bytes)), 12);
    }

    #[test]
    fn difficulty_is_only_retargeted_when_a_whole_bit_is_warranted() {
        assert_eq!(retarget_difficulty(20, 100, 2_000), 21);
        assert_eq!(retarget_difficulty(20, 5_000, 2_000), 19);
        assert_eq!(retarget_difficulty(20, 1_500, 2_000), 20);
        assert_eq!(retarget_difficulty(20, 2_000, 2_000), 20);
        assert_eq!(retarget_difficulty(20, 3_900, 2_000), 20);
    }

    #[test]
    fn difficulty_stays_inside_its_clamps() {
        assert_eq!(
            retarget_difficulty(MIN_DIFFICULTY_LEADING_ZEROS, u64::MAX, 1),
            MIN_DIFFICULTY_LEADING_ZEROS
        );
        assert_eq!(
            retarget_difficulty(MAX_DIFFICULTY_LEADING_ZEROS, 0, u64::MAX),
            MAX_DIFFICULTY_LEADING_ZEROS
        );
    }

    #[test]
    fn a_fresh_chain_has_a_genesis_block_and_funded_accounts() {
        let address = Address::repeat_byte(0x11);
        let genesis = BreejaGenesis {
            accounts: vec![(address, U256::from(1_000u64))],
        };
        let state = BlockState::new_with_gensis(genesis, 8);

        assert_eq!(state.get_block_number(), 0);
        assert_eq!(state.head().number, 0);
        assert_eq!(state.head().parent_hash, B256::ZERO);
        assert_eq!(state.get_account(&address).balance, U256::from(1_000u64));
        assert_eq!(state.get_account(&address).nonce, 0);
        assert_eq!(state.get_account(&Address::ZERO).balance, U256::ZERO);
    }

    #[test]
    fn the_genesis_block_is_reachable_by_hash_and_by_number() {
        let state = BlockState::new_with_gensis(BreejaGenesis::default(), 8);
        let hash = state.head().hash;
        assert_eq!(state.get_block_by_hash(&hash).unwrap().number, 0);
        assert_eq!(state.get_block(0).unwrap().hash, hash);
        assert!(state.get_block(1).is_none());
    }

    #[test]
    fn the_state_root_commits_to_balances_and_ignores_map_ordering() {
        let a = Address::repeat_byte(0x01);
        let b = Address::repeat_byte(0x02);

        let mut one = HashMap::new();
        one.insert(a, Account::new(U256::from(1u64)));
        one.insert(b, Account::new(U256::from(2u64)));

        let mut two = HashMap::new();
        two.insert(b, Account::new(U256::from(2u64)));
        two.insert(a, Account::new(U256::from(1u64)));

        assert_eq!(state_root_of(&one), state_root_of(&two));

        let mut three = one.clone();
        three.insert(a, Account::new(U256::from(99u64)));
        assert_ne!(state_root_of(&one), state_root_of(&three));
    }

    #[test]
    fn the_state_root_commits_to_contract_storage_and_code() {
        let addr = Address::repeat_byte(0x42);

        let mut one = HashMap::new();
        one.insert(addr, Account::new(U256::ZERO));

        let mut two = one.clone();
        two.get_mut(&addr)
            .unwrap()
            .storage
            .insert(U256::ZERO, U256::from(42u64));

        assert_ne!(
            state_root_of(&one),
            state_root_of(&two),
            "two states differing only in one storage slot must produce different state roots"
        );
    }

    #[test]
    fn logs_bloom_sets_expected_bits_for_non_empty_logs() {
        let empty = compute_logs_bloom(&[]);
        assert!(empty.iter().all(|&b| b == 0));

        let log = Log {
            address: Address::repeat_byte(0x33),
            topics: vec![B256::repeat_byte(0x77)],
            data: Bytes::from_static(&[0x2a]),
        };
        let bloom = compute_logs_bloom(std::slice::from_ref(&log));
        assert_eq!(bloom.len(), 256);
        assert!(bloom.iter().any(|&b| b != 0));

        // Verify that every bit set for the single log is set in the bloom filter
        let mut expected = [0u8; 256];
        bloom_insert(&mut expected, log.address.as_slice());
        bloom_insert(&mut expected, log.topics[0].as_slice());
        assert_eq!(bloom.as_ref(), &expected[..]);
    }

    #[test]
    fn pending_nonce_and_balance_account_for_what_is_already_queued() {
        let sender = Address::repeat_byte(0x11);
        let one_eth = U256::from(10u64).pow(U256::from(18));
        let genesis = BreejaGenesis {
            accounts: vec![(sender, one_eth * U256::from(10u64))],
        };
        let mut state = BlockState::new_with_gensis(genesis, 8);

        assert_eq!(state.get_pending_nonce(&sender), 0);

        state.add_to_mempool(PendingTransaction {
            hash: B256::repeat_byte(0xaa),
            from: sender,
            to: Address::repeat_byte(0x22),
            is_create: false,
            value: one_eth,
            input: Bytes::new(),
            nonce: 0,
            gas: TRANSFER_GAS,
            gas_price: GAS_PRICE,
            chain_id: 1,
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        });

        assert_eq!(state.get_pending_nonce(&sender), 1);
        assert!(state.get_pending_balance(&sender) < one_eth * U256::from(9u64));
        assert_eq!(state.mempool_len(), 1);
        assert!(state.mempool_contains(&B256::repeat_byte(0xaa)));
    }
}

use std::collections::HashMap;

use alloy::primitives::{Address, B256};
use primitives::{
    constants::{BLOCK_GAS_LIMIT, BLOCK_REWARD},
    node::{
        Account, PendingTransaction, Transaction, TransactionReceipt, compute_logs_bloom,
        hash_list_root,
    },
};

use crate::evm::{BlockContext, TxExecutionOutcome, execute_tx};

/// What executing a batch of transactions produced.
pub struct Execution {
    /// Account state after the batch, ready to become the new head state.
    pub accounts: HashMap<Address, Account>,
    pub transactions: Vec<Transaction>,
    pub receipts: Vec<TransactionReceipt>,
    pub gas_used: u64,
    pub transaction_root: B256,
    pub receipts_root: B256,
    pub state_root: B256,
}

/// Applies one transaction (plain ETH transfer, contract call, or contract
/// creation) to the account state via the EVM.
///
/// Kept under the original `apply_transfer` name for backwards compatibility
/// with existing unit tests, while also returning the full [`TxExecutionOutcome`]
/// via [`apply_transaction`].
pub fn apply_transfer(
    accounts: &mut HashMap<Address, Account>,
    tx: &PendingTransaction,
    miner: Address,
) -> Result<u64, anyhow::Error> {
    let block = BlockContext {
        number: 1,
        miner,
        timestamp: 1,
        gas_limit: BLOCK_GAS_LIMIT,
        difficulty: 1,
        prevrandao: B256::ZERO,
    };
    let outcome = execute_tx(accounts, tx, &block, HashMap::new())?;
    Ok(outcome.gas_used)
}

/// Executes one transaction through the EVM against `accounts` using the given
/// [`BlockContext`] and historical `block_hashes`.
pub fn apply_transaction(
    accounts: &mut HashMap<Address, Account>,
    tx: &PendingTransaction,
    block: &BlockContext,
    block_hashes: HashMap<u64, B256>,
) -> Result<TxExecutionOutcome, anyhow::Error> {
    execute_tx(accounts, tx, block, block_hashes)
}

/// Pays the miner for sealing a block.
///
/// This is the only way new ETH enters the supply, and it is what makes mining
/// worth the electricity. Breeja pays Frontier's 5 ETH; Ethereum reduced this
/// twice before dropping it entirely at the merge.
pub fn pay_block_reward(
    accounts: &mut HashMap<Address, Account>,
    miner: Address,
) -> Result<(), anyhow::Error> {
    accounts.entry(miner).or_default().credit(BLOCK_REWARD)?;
    Ok(())
}

/// Executes a batch of pending transactions, producing the state and receipts the
/// next block will commit to.
///
/// Invalid transactions (such as a stale nonce or insufficient upfront balance)
/// or transactions whose gas consumption would exceed [`BLOCK_GAS_LIMIT`] are
/// *skipped*, not included. Transactions that enter the EVM and revert (`REVERT`)
/// or halt (`OutOfGas`, `INVALID`, etc.) *are* included in the block with
/// `status: 0`, because they consumed gas and incremented the sender's nonce.
pub fn execute_block(
    accounts: HashMap<Address, Account>,
    batch: &[PendingTransaction],
    block_number: u64,
    miner: Address,
) -> Execution {
    let block = BlockContext {
        number: block_number,
        miner,
        timestamp: block_number,
        gas_limit: BLOCK_GAS_LIMIT,
        difficulty: 1,
        prevrandao: B256::ZERO,
    };
    execute_block_with_context(accounts, batch, &block, &HashMap::new())
}

/// Executes a batch of pending transactions with full block environment context
/// and historical block hashes.
pub fn execute_block_with_context(
    mut accounts: HashMap<Address, Account>,
    batch: &[PendingTransaction],
    block: &BlockContext,
    block_hashes: &HashMap<u64, B256>,
) -> Execution {
    let mut transactions = Vec::new();
    let mut receipts = Vec::new();
    let mut gas_used = 0u64;

    for tx in batch {
        // Clone state before executing so a transaction that exceeds remaining
        // block gas or fails pre-execution checks leaves `accounts` untouched.
        let mut candidate_accounts = accounts.clone();
        match execute_tx(&mut candidate_accounts, tx, block, block_hashes.clone()) {
            Ok(outcome) => {
                if gas_used.saturating_add(outcome.gas_used) > block.gas_limit {
                    tracing::warn!(
                        tx = %tx.hash,
                        tx_gas = outcome.gas_used,
                        block_gas_used = gas_used,
                        block_gas_limit = block.gas_limit,
                        "skipping transaction that would exceed block gas limit"
                    );
                    continue;
                }

                accounts = candidate_accounts;
                let index = transactions.len() as u64;
                gas_used += outcome.gas_used;

                transactions.push(Transaction {
                    hash: tx.hash,
                    // The block hash is unknown until the block is sealed, so it
                    // is stamped in afterwards.
                    block_hash: B256::ZERO,
                    block_number: block.number,
                    transaction_index: index,
                    chain_id: tx.chain_id,
                    from: tx.from,
                    to: tx.to,
                    is_create: tx.is_create,
                    value: tx.value,
                    nonce: tx.nonce,
                    gas: tx.gas,
                    gas_price: tx.gas_price,
                    input: tx.input.clone(),
                    v: tx.v,
                    r: tx.r,
                    s: tx.s,
                });

                let logs_bloom = compute_logs_bloom(&outcome.logs);
                receipts.push(TransactionReceipt {
                    transaction_hash: tx.hash,
                    transaction_index: index,
                    block_hash: B256::ZERO,
                    block_number: block.number,
                    from: tx.from,
                    to: tx.to,
                    is_create: tx.is_create,
                    contract_address: outcome.contract_address,
                    gas_used: outcome.gas_used,
                    cummulative_gas_used: gas_used,
                    effective_gas_price: tx.gas_price,
                    status: outcome.status,
                    logs: outcome.logs,
                    logs_bloom,
                });
            }
            Err(error) => {
                tracing::warn!(tx = %tx.hash, %error, "dropping transaction that no longer applies");
            }
        }
    }

    // The miner's reward is paid after the transactions, so a miner cannot spend
    // it inside the very block that grants it.
    if let Err(error) = pay_block_reward(&mut accounts, block.miner) {
        tracing::error!(%error, "failed to pay block reward");
    }

    let tx_hashes: Vec<B256> = transactions.iter().map(|tx| tx.hash).collect();
    let receipt_hashes: Vec<B256> = receipts.iter().map(|r| r.transaction_hash).collect();

    Execution {
        transaction_root: hash_list_root(&tx_hashes),
        receipts_root: hash_list_root(&receipt_hashes),
        state_root: primitives::node::state_root_of(&accounts),
        accounts,
        transactions,
        receipts,
        gas_used,
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{Bytes, U256};
    use primitives::{
        constants::{DEV_ADDRESS, DEV_ADDRESS_1, GAS_PRICE, TRANSFER_GAS},
        node::derive_contract_address,
    };

    use super::*;

    fn one_eth() -> U256 {
        U256::from(10u64).pow(U256::from(18))
    }

    fn funded(balance: U256) -> HashMap<Address, Account> {
        let mut accounts = HashMap::new();
        accounts.insert(DEV_ADDRESS, Account::new(balance));
        accounts
    }

    fn transfer(value: U256, nonce: u64) -> PendingTransaction {
        PendingTransaction {
            hash: B256::repeat_byte(0xab),
            from: DEV_ADDRESS,
            to: DEV_ADDRESS_1,
            is_create: false,
            value,
            input: Bytes::new(),
            nonce,
            gas: TRANSFER_GAS,
            gas_price: GAS_PRICE,
            chain_id: 1,
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        }
    }

    #[test]
    fn a_transfer_moves_value_charges_a_fee_and_bumps_the_nonce() {
        let miner = Address::repeat_byte(0x99);
        let mut accounts = funded(one_eth() * U256::from(10u64));
        let fee = U256::from(TRANSFER_GAS) * U256::from(GAS_PRICE);

        let gas = apply_transfer(&mut accounts, &transfer(one_eth(), 0), miner).unwrap();
        assert_eq!(gas, TRANSFER_GAS);

        let sender = &accounts[&DEV_ADDRESS];
        assert_eq!(
            sender.balance,
            one_eth() * U256::from(10u64) - one_eth() - fee
        );
        assert_eq!(sender.nonce, 1);
        assert_eq!(accounts[&DEV_ADDRESS_1].balance, one_eth());
        assert_eq!(accounts[&miner].balance, fee);
    }

    #[test]
    fn no_eth_is_created_or_destroyed_by_a_transfer() {
        let miner = Address::repeat_byte(0x99);
        let start = one_eth() * U256::from(10u64);
        let mut accounts = funded(start);

        apply_transfer(&mut accounts, &transfer(one_eth(), 0), miner).unwrap();

        let total: U256 = accounts
            .values()
            .map(|a| a.balance)
            .fold(U256::ZERO, |a, b| a + b);
        assert_eq!(total, start);
    }

    #[test]
    fn a_transfer_the_sender_cannot_afford_is_rejected() {
        let miner = Address::repeat_byte(0x99);
        // Enough for the value but not the fee on top.
        let mut accounts = funded(one_eth());
        assert!(apply_transfer(&mut accounts, &transfer(one_eth(), 0), miner).is_err());
    }

    #[test]
    fn a_transfer_with_the_wrong_nonce_is_rejected() {
        let miner = Address::repeat_byte(0x99);
        let mut accounts = funded(one_eth() * U256::from(10u64));
        assert!(apply_transfer(&mut accounts, &transfer(one_eth(), 7), miner).is_err());
    }

    #[test]
    fn executing_a_block_pays_the_reward_and_records_receipts() {
        let miner = Address::repeat_byte(0x99);
        let accounts = funded(one_eth() * U256::from(10u64));
        let batch = vec![transfer(one_eth(), 0)];

        let execution = execute_block(accounts, &batch, 1, miner);

        assert_eq!(execution.transactions.len(), 1);
        assert_eq!(execution.receipts.len(), 1);
        assert_eq!(execution.receipts[0].status, 1);
        assert_eq!(execution.gas_used, TRANSFER_GAS);
        assert_eq!(execution.receipts[0].cummulative_gas_used, TRANSFER_GAS);

        let fee = U256::from(TRANSFER_GAS) * U256::from(GAS_PRICE);
        assert_eq!(execution.accounts[&miner].balance, BLOCK_REWARD + fee);

        // Non-empty roots, because this block committed to a transaction.
        assert_ne!(execution.transaction_root, B256::ZERO);
        assert_ne!(execution.state_root, B256::ZERO);
    }

    #[test]
    fn an_empty_block_still_pays_the_miner_but_commits_to_no_transactions() {
        let miner = Address::repeat_byte(0x99);
        let execution = execute_block(funded(one_eth()), &[], 1, miner);

        assert!(execution.transactions.is_empty());
        assert_eq!(execution.gas_used, 0);
        assert_eq!(execution.transaction_root, B256::ZERO);
        assert_eq!(execution.accounts[&miner].balance, BLOCK_REWARD);
    }

    #[test]
    fn a_transaction_that_no_longer_applies_is_skipped_not_mined() {
        let miner = Address::repeat_byte(0x99);
        let accounts = funded(one_eth() * U256::from(10u64));
        // Two transactions claiming the same nonce: only the first can apply.
        let batch = vec![transfer(one_eth(), 0), transfer(one_eth(), 0)];

        let execution = execute_block(accounts, &batch, 1, miner);
        assert_eq!(execution.transactions.len(), 1);
    }

    #[test]
    fn deploys_and_calls_test_contract_storing_42_and_emitting_log0() {
        let miner = Address::repeat_byte(0x99);
        let accounts = funded(one_eth() * U256::from(10u64));

        // Initcode: 0x600b600c600039600b6000f3602a60005560006000a000
        // Returns 11-byte runtime: 0x602a60005560006000a000 (SSTORE(0, 42); LOG0(0, 0); STOP)
        let initcode: Bytes = "0x600b600c600039600b6000f3602a60005560006000a000"
            .parse()
            .unwrap();
        let expected_runtime: Bytes = "0x602a60005560006000a000".parse().unwrap();
        let expected_contract = derive_contract_address(DEV_ADDRESS, 0);

        let deploy_tx = PendingTransaction {
            hash: B256::repeat_byte(0x01),
            from: DEV_ADDRESS,
            to: Address::ZERO,
            is_create: true,
            value: U256::ZERO,
            input: initcode,
            nonce: 0,
            gas: 100_000,
            gas_price: GAS_PRICE,
            chain_id: 1,
            v: 37,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let call_tx = PendingTransaction {
            hash: B256::repeat_byte(0x02),
            from: DEV_ADDRESS,
            to: expected_contract,
            is_create: false,
            value: U256::ZERO,
            input: Bytes::new(),
            nonce: 1,
            gas: 100_000,
            gas_price: GAS_PRICE,
            chain_id: 1,
            v: 37,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let execution = execute_block(accounts, &[deploy_tx, call_tx], 1, miner);
        assert_eq!(execution.receipts.len(), 2);

        // Receipt 0: deployment
        let deploy_receipt = &execution.receipts[0];
        assert_eq!(deploy_receipt.status, 1);
        assert_eq!(deploy_receipt.contract_address, Some(expected_contract));
        assert_eq!(deploy_receipt.gas_used, 55_522);
        assert_eq!(execution.accounts[&expected_contract].code, expected_runtime);

        // Receipt 1: contract call
        let call_receipt = &execution.receipts[1];
        assert_eq!(call_receipt.status, 1);
        assert_eq!(call_receipt.contract_address, None);
        assert_eq!(call_receipt.gas_used, 43_487);
        assert_eq!(call_receipt.cummulative_gas_used, 55_522 + 43_487);
        assert_eq!(
            execution.accounts[&expected_contract]
                .storage
                .get(&U256::ZERO)
                .copied(),
            Some(U256::from(42u64))
        );
        assert_eq!(call_receipt.logs.len(), 1);
        assert_eq!(call_receipt.logs[0].address, expected_contract);
        assert!(call_receipt.logs[0].topics.is_empty());
        assert!(call_receipt.logs[0].data.is_empty());
        assert!(call_receipt.logs_bloom.iter().any(|&b| b != 0));
    }

    #[test]
    fn reverting_and_halting_transactions_are_included_with_status_zero() {
        let miner = Address::repeat_byte(0x99);
        let start = one_eth() * U256::from(10u64);
        let accounts = funded(start);

        // Tx 0: deploys initcode `0x60006000fd` (`PUSH1 0, PUSH1 0, REVERT`).
        // Reverts after spending intrinsic (53000 + 2*4 + 3*16 + 2 = 53058) + 6 (two PUSH1s) = 53064 gas.
        // Unused gas from the 100,000 limit is refunded.
        let revert_tx = PendingTransaction {
            hash: B256::repeat_byte(0x11),
            from: DEV_ADDRESS,
            to: Address::ZERO,
            is_create: true,
            value: U256::ZERO,
            input: "0x60006000fd".parse().unwrap(),
            nonce: 0,
            gas: 100_000,
            gas_price: GAS_PRICE,
            chain_id: 1,
            v: 37,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        // Tx 1: deploys initcode `0xfe` (`INVALID` opcode).
        // Halts and consumes the entire 100,000 gas_limit.
        let halt_tx = PendingTransaction {
            hash: B256::repeat_byte(0x22),
            from: DEV_ADDRESS,
            to: Address::ZERO,
            is_create: true,
            value: U256::ZERO,
            input: "0xfe".parse().unwrap(),
            nonce: 1,
            gas: 100_000,
            gas_price: GAS_PRICE,
            chain_id: 1,
            v: 37,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let execution = execute_block(accounts, &[revert_tx, halt_tx], 1, miner);
        assert_eq!(execution.receipts.len(), 2);

        let rev_receipt = &execution.receipts[0];
        assert_eq!(rev_receipt.status, 0);
        assert_eq!(rev_receipt.contract_address, None);
        assert!(rev_receipt.gas_used < 100_000);
        assert_eq!(rev_receipt.gas_used, 53_064);

        let halt_receipt = &execution.receipts[1];
        assert_eq!(halt_receipt.status, 0);
        assert_eq!(halt_receipt.contract_address, None);
        assert_eq!(halt_receipt.gas_used, 100_000);

        // Sender nonce was incremented for both included transactions.
        assert_eq!(execution.accounts[&DEV_ADDRESS].nonce, 2);
    }

    #[test]
    fn block_gas_limit_skips_transactions_that_would_overflow_block_gas() {
        let miner = Address::repeat_byte(0x99);
        let accounts = funded(one_eth() * U256::from(100u64));
        let block = BlockContext {
            number: 1,
            miner,
            timestamp: 1,
            // Only enough room for two 21,000-gas transfers (42,000 gas total).
            gas_limit: TRANSFER_GAS * 2,
            difficulty: 1,
            prevrandao: B256::ZERO,
        };

        let batch = vec![
            transfer(one_eth(), 0),
            transfer(one_eth(), 1),
            transfer(one_eth(), 2),
        ];

        let execution = execute_block_with_context(accounts, &batch, &block, &HashMap::new());
        assert_eq!(execution.transactions.len(), 2);
        assert_eq!(execution.gas_used, TRANSFER_GAS * 2);
        assert_eq!(execution.accounts[&DEV_ADDRESS].nonce, 2);
    }
}

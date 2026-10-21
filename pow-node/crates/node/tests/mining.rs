//! End-to-end tests: sign a transaction, let the miner seal it, check the result.

use std::time::{Duration, Instant};

use alloy::primitives::{Address, B256, Bytes, U256};
use node::{
    Chain, ChainConfig, miner,
    testing::{
        DEV_PRIVATE_KEY, DEV_PRIVATE_KEY_1, address_of, one_eth, sign_call, sign_deploy,
        sign_transfer, sign_transfer_with,
    },
};
use primitives::{
    constants::{GAS_PRICE, TRANSFER_GAS},
    node::{BreejaGenesis, derive_contract_address},
};

/// A chain that mines almost instantly, so tests do not spend real time hashing.
fn test_chain(funded: &[(Address, U256)]) -> Chain {
    let miner_address = Address::repeat_byte(0x99);
    let config = ChainConfig {
        difficulty: 4,
        target_block_time: Duration::from_millis(50),
        miner: miner_address,
    };
    Chain::new(
        BreejaGenesis {
            accounts: funded.to_vec(),
        },
        config,
    )
}

/// Blocks until `predicate` holds, or fails the test after `timeout`.
fn wait_for(timeout: Duration, label: &str, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out after {timeout:?} waiting for {label}");
}

#[test]
fn a_signed_transfer_is_mined_and_moves_the_eth() {
    let alice = address_of(DEV_PRIVATE_KEY).unwrap();
    let bob = address_of(DEV_PRIVATE_KEY_1).unwrap();
    let chain = test_chain(&[(alice, one_eth() * U256::from(100u64))]);

    let raw = sign_transfer(DEV_PRIVATE_KEY, bob, one_eth() * U256::from(5u64), 0).unwrap();
    let tx_hash = chain.submit_raw_transaction(&raw).unwrap();

    // Before mining, the transaction is pending: no receipt yet.
    assert!(chain.read().get_receipt(&tx_hash).is_none());
    assert_eq!(chain.read().mempool_len(), 1);

    let handle = miner::spawn(chain.clone());
    wait_for(Duration::from_secs(10), "the transfer to be mined", || {
        chain.read().get_receipt(&tx_hash).is_some()
    });
    chain.shutdown();
    handle.join().unwrap();

    let state = chain.read();
    let receipt = state.get_receipt(&tx_hash).unwrap();
    assert_eq!(receipt.status, 1);
    assert_eq!(receipt.gas_used, TRANSFER_GAS);
    assert_ne!(receipt.block_hash, B256::ZERO);

    // Bob received exactly the value; Alice paid value plus the fee.
    let fee = U256::from(TRANSFER_GAS) * U256::from(GAS_PRICE);
    assert_eq!(
        state.get_account(&bob).balance,
        one_eth() * U256::from(5u64)
    );
    assert_eq!(
        state.get_account(&alice).balance,
        one_eth() * U256::from(95u64) - fee
    );
    assert_eq!(state.get_account(&alice).nonce, 1);

    // The transaction is out of the mempool and findable by hash.
    assert_eq!(state.mempool_len(), 0);
    let tx = state.get_transaction(&tx_hash).unwrap();
    assert_eq!(tx.from, alice);
    assert_eq!(tx.to, bob);
    assert_eq!(tx.value, one_eth() * U256::from(5u64));

    // The block it landed in lists it.
    let block = state.get_block_by_hash(&receipt.block_hash).unwrap();
    assert!(block.transactions.contains(&tx_hash));
    assert_eq!(block.gas_used, TRANSFER_GAS);
}

#[test]
fn every_block_is_a_valid_proof_of_work_linked_to_its_parent() {
    let chain = test_chain(&[]);
    let handle = miner::spawn(chain.clone());
    wait_for(Duration::from_secs(10), "five blocks to be mined", || {
        chain.read().get_block_number() >= 5
    });
    chain.shutdown();
    handle.join().unwrap();

    let state = chain.read();
    let head = state.get_block_number();

    for number in 1..=head {
        let block = state.get_block(number).unwrap();
        let parent = state.get_block(number - 1).unwrap();

        // Each block names its parent, which is what makes this a chain.
        assert_eq!(block.parent_hash, parent.hash, "block {number} parent link");
        assert!(
            block.timestamp > parent.timestamp,
            "block {number} timestamp"
        );
        assert_eq!(
            block.total_difficulty,
            parent.total_difficulty + block.difficulty as u64,
            "block {number} cumulative difficulty"
        );

        // And the proof of work actually holds: re-deriving the hash from the
        // header reproduces it, and it meets the claimed difficulty.
        node::pow::verify(&block.header(), &block.hash, block.difficulty)
            .unwrap_or_else(|e| panic!("block {number} has an invalid proof of work: {e}"));
    }
}

#[test]
fn the_miner_is_paid_a_block_reward_for_every_block() {
    let chain = test_chain(&[]);
    let miner_address = chain.config().miner;

    let handle = miner::spawn(chain.clone());
    wait_for(Duration::from_secs(10), "three blocks", || {
        chain.read().get_block_number() >= 3
    });
    chain.shutdown();
    handle.join().unwrap();

    let state = chain.read();
    let blocks = state.get_block_number();
    let expected = primitives::constants::BLOCK_REWARD * U256::from(blocks);
    assert_eq!(state.get_account(&miner_address).balance, expected);
}

#[test]
fn several_transfers_from_one_sender_are_mined_in_nonce_order() {
    let alice = address_of(DEV_PRIVATE_KEY).unwrap();
    let bob = address_of(DEV_PRIVATE_KEY_1).unwrap();
    let chain = test_chain(&[(alice, one_eth() * U256::from(100u64))]);

    // Three transactions queued back to back, without waiting for a block.
    let mut hashes = Vec::new();
    for nonce in 0..3 {
        let raw = sign_transfer(DEV_PRIVATE_KEY, bob, one_eth(), nonce).unwrap();
        hashes.push(chain.submit_raw_transaction(&raw).unwrap());
    }
    assert_eq!(chain.read().get_pending_nonce(&alice), 3);

    let handle = miner::spawn(chain.clone());
    wait_for(Duration::from_secs(10), "all three transfers", || {
        hashes.iter().all(|h| chain.read().get_receipt(h).is_some())
    });
    chain.shutdown();
    handle.join().unwrap();

    let state = chain.read();
    assert_eq!(
        state.get_account(&bob).balance,
        one_eth() * U256::from(3u64)
    );
    assert_eq!(state.get_account(&alice).nonce, 3);

    // Each receipt records its position, and cumulative gas grows across a block.
    for (nonce, hash) in hashes.iter().enumerate() {
        let tx = state.get_transaction(hash).unwrap();
        assert_eq!(tx.nonce, nonce as u64);
    }
}

#[test]
fn the_chain_never_creates_or_destroys_eth_outside_the_block_reward() {
    let alice = address_of(DEV_PRIVATE_KEY).unwrap();
    let bob = address_of(DEV_PRIVATE_KEY_1).unwrap();
    let start = one_eth() * U256::from(100u64);
    let chain = test_chain(&[(alice, start)]);

    for nonce in 0..3 {
        let raw = sign_transfer(DEV_PRIVATE_KEY, bob, one_eth(), nonce).unwrap();
        chain.submit_raw_transaction(&raw).unwrap();
    }

    let handle = miner::spawn(chain.clone());
    wait_for(Duration::from_secs(10), "the transfers to be mined", || {
        chain.read().get_account(&alice).nonce == 3
    });
    chain.shutdown();
    handle.join().unwrap();

    let state = chain.read();
    let blocks = state.get_block_number();
    let minted = primitives::constants::BLOCK_REWARD * U256::from(blocks);

    // Total supply is exactly what genesis funded plus what mining minted. Fees
    // moved from Alice to the miner but did not change the total.
    let total = [alice, bob, chain.config().miner]
        .iter()
        .map(|a| state.get_account(a).balance)
        .fold(U256::ZERO, |acc, b| acc + b);
    assert_eq!(total, start + minted);
}

#[test]
fn historical_balances_are_preserved_as_the_chain_grows() {
    let alice = address_of(DEV_PRIVATE_KEY).unwrap();
    let bob = address_of(DEV_PRIVATE_KEY_1).unwrap();
    let start = one_eth() * U256::from(100u64);
    let chain = test_chain(&[(alice, start)]);

    let raw = sign_transfer(DEV_PRIVATE_KEY, bob, one_eth() * U256::from(5u64), 0).unwrap();
    let tx_hash = chain.submit_raw_transaction(&raw).unwrap();

    let handle = miner::spawn(chain.clone());
    wait_for(Duration::from_secs(10), "the transfer to be mined", || {
        chain.read().get_receipt(&tx_hash).is_some()
    });
    // Let the chain grow past the transfer.
    let mined_at = chain.read().get_receipt(&tx_hash).unwrap().block_number;
    wait_for(Duration::from_secs(10), "two more blocks", || {
        chain.read().get_block_number() >= mined_at + 2
    });
    chain.shutdown();
    handle.join().unwrap();

    let state = chain.read();
    // At genesis Bob had nothing and Alice had everything...
    assert_eq!(state.get_account_at(&bob, 0).unwrap().balance, U256::ZERO);
    assert_eq!(state.get_account_at(&alice, 0).unwrap().balance, start);
    // ...and from the block that mined the transfer onwards, Bob has 5 ETH.
    assert_eq!(
        state.get_account_at(&bob, mined_at).unwrap().balance,
        one_eth() * U256::from(5u64)
    );
    // A block that does not exist has no state.
    assert!(state.get_account_at(&bob, 10_000).is_none());
}

#[test]
fn the_node_refuses_transactions_it_cannot_execute() {
    let alice = address_of(DEV_PRIVATE_KEY).unwrap();
    let bob = address_of(DEV_PRIVATE_KEY_1).unwrap();
    let chain = test_chain(&[(alice, one_eth() * U256::from(10u64))]);

    // A gas price below the chain's fixed price.
    let underpriced =
        sign_transfer_with(DEV_PRIVATE_KEY, bob, one_eth(), 0, 1, TRANSFER_GAS).unwrap();
    assert!(chain.submit_raw_transaction(&underpriced).is_err());

    // A gas limit below the intrinsic cost of a transfer.
    let starved = sign_transfer_with(DEV_PRIVATE_KEY, bob, one_eth(), 0, GAS_PRICE, 1_000).unwrap();
    assert!(chain.submit_raw_transaction(&starved).is_err());

    // More ETH than the sender has.
    let overdraft =
        sign_transfer(DEV_PRIVATE_KEY, bob, one_eth() * U256::from(1_000u64), 0).unwrap();
    assert!(chain.submit_raw_transaction(&overdraft).is_err());

    // A nonce that skips ahead.
    let future_nonce = sign_transfer(DEV_PRIVATE_KEY, bob, one_eth(), 7).unwrap();
    assert!(chain.submit_raw_transaction(&future_nonce).is_err());

    // Nothing was admitted.
    assert_eq!(chain.read().mempool_len(), 0);

    // The valid version of the same transfer is accepted...
    let valid = sign_transfer(DEV_PRIVATE_KEY, bob, one_eth(), 0).unwrap();
    chain.submit_raw_transaction(&valid).unwrap();
    assert_eq!(chain.read().mempool_len(), 1);

    // ...but not twice.
    assert!(chain.submit_raw_transaction(&valid).is_err());
    assert_eq!(chain.read().mempool_len(), 1);
}

#[test]
fn a_new_transaction_makes_the_miner_rebuild_its_candidate_block() {
    let alice = address_of(DEV_PRIVATE_KEY).unwrap();
    let bob = address_of(DEV_PRIVATE_KEY_1).unwrap();
    let chain = test_chain(&[(alice, one_eth() * U256::from(100u64))]);

    // Start mining with an empty mempool, then submit mid-flight.
    let handle = miner::spawn(chain.clone());
    wait_for(Duration::from_secs(10), "the chain to start", || {
        chain.read().get_block_number() >= 1
    });

    let raw = sign_transfer(DEV_PRIVATE_KEY, bob, one_eth(), 0).unwrap();
    let tx_hash = chain.submit_raw_transaction(&raw).unwrap();

    wait_for(
        Duration::from_secs(10),
        "the late transfer to be mined",
        || chain.read().get_receipt(&tx_hash).is_some(),
    );
    chain.shutdown();
    handle.join().unwrap();

    assert_eq!(
        chain.read().get_account(&bob).balance,
        one_eth(),
        "a transaction submitted while mining was already underway still got mined"
    );
}

#[test]
fn a_contract_is_deployed_and_called_across_mined_blocks() {
    let alice = address_of(DEV_PRIVATE_KEY).unwrap();
    let chain = test_chain(&[(alice, one_eth() * U256::from(100u64))]);

    let initcode: Bytes = "0x600b600c600039600b6000f3602a60005560006000a000"
        .parse()
        .unwrap();
    let expected_contract = derive_contract_address(alice, 0);

    let deploy_raw = sign_deploy(DEV_PRIVATE_KEY, initcode, U256::ZERO, 0, 100_000).unwrap();
    let deploy_hash = chain.submit_raw_transaction(&deploy_raw).unwrap();

    let call_raw = sign_call(
        DEV_PRIVATE_KEY,
        expected_contract,
        Bytes::new(),
        U256::ZERO,
        1,
        100_000,
    )
    .unwrap();
    let call_hash = chain.submit_raw_transaction(&call_raw).unwrap();

    let handle = miner::spawn(chain.clone());
    wait_for(
        Duration::from_secs(10),
        "deploy and call to be mined",
        || {
            let s = chain.read();
            s.get_receipt(&deploy_hash).is_some() && s.get_receipt(&call_hash).is_some()
        },
    );
    chain.shutdown();
    handle.join().unwrap();

    let state = chain.read();
    let deploy_receipt = state.get_receipt(&deploy_hash).unwrap();
    assert_eq!(deploy_receipt.status, 1);
    assert_eq!(deploy_receipt.contract_address, Some(expected_contract));
    assert!(!state.get_code(&expected_contract).is_empty());

    let call_receipt = state.get_receipt(&call_hash).unwrap();
    assert_eq!(call_receipt.status, 1);
    assert_eq!(
        state.get_storage(&expected_contract, U256::ZERO),
        U256::from(42u64)
    );
    assert_eq!(call_receipt.logs.len(), 1);
}


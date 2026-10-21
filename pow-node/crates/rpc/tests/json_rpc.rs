use std::time::Duration;

use alloy::primitives::{Address, Bytes, U256};
use jsonrpsee::{
    core::client::ClientT,
    http_client::{HttpClient, HttpClientBuilder},
    rpc_params,
};
use node::{
    Chain, ChainConfig, miner,
    testing::{
        DEV_PRIVATE_KEY, DEV_PRIVATE_KEY_1, address_of, one_eth, sign_call, sign_deploy,
        sign_transfer,
    },
};
use primitives::node::{BreejaGenesis, derive_contract_address};
use rpc::{RPCContext, start_server};
use serde_json::Value;

/// A running node and a client pointed at it.
struct Harness {
    client: HttpClient,
    chain: Chain,
    _server: jsonrpsee::server::ServerHandle,
    miner: Option<std::thread::JoinHandle<()>>,
}

impl Harness {
    /// Starts a node with the given funded accounts, mining on a dedicated thread.
    async fn start(funded: &[(Address, U256)], mine: bool) -> Self {
        let config = ChainConfig {
            difficulty: 4,
            target_block_time: Duration::from_millis(50),
            miner: Address::repeat_byte(0x99),
        };
        let chain = Chain::new(
            BreejaGenesis {
                accounts: funded.to_vec(),
            },
            config,
        );

        // Port 0 lets the OS pick a free port, so tests can run in parallel.
        let (server, address) = start_server(RPCContext::new(chain.clone()), "127.0.0.1:0")
            .await
            .expect("server should start");
        let url = format!("http://{address}");
        let client = HttpClientBuilder::default().build(url).unwrap();

        let miner = mine.then(|| miner::spawn(chain.clone()));

        Self {
            client,
            chain,
            _server: server,
            miner,
        }
    }

    /// Polls `predicate` until it holds, or panics.
    async fn wait_for(&self, label: &str, mut predicate: impl FnMut(&Chain) -> bool) {
        for _ in 0..1_000 {
            if predicate(&self.chain) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {label}");
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.chain.shutdown();
        if let Some(handle) = self.miner.take() {
            let _ = handle.join();
        }
    }
}

/// Parses a hex quantity the way a client would.
fn from_quantity(raw: &str) -> u128 {
    u128::from_str_radix(raw.trim_start_matches("0x"), 16).expect("a valid hex quantity")
}

#[tokio::test]
async fn eth_chain_id_returns_the_configured_chain_id() {
    let harness = Harness::start(&[], false).await;
    let id: String = harness
        .client
        .request("eth_chainId", rpc_params![])
        .await
        .unwrap();
    assert_eq!(id, "0x1");
}

#[tokio::test]
async fn eth_block_number_starts_at_genesis_and_climbs_as_blocks_are_mined() {
    let harness = Harness::start(&[], true).await;

    harness
        .wait_for("blocks to be mined", |c| c.read().get_block_number() >= 3)
        .await;

    let number: String = harness
        .client
        .request("eth_blockNumber", rpc_params![])
        .await
        .unwrap();
    assert!(
        number.starts_with("0x"),
        "must be a hex quantity, got {number}"
    );
    assert!(from_quantity(&number) >= 3);
}

#[tokio::test]
async fn eth_get_block_by_number_accepts_tags_and_numbers() {
    let harness = Harness::start(&[], true).await;
    harness
        .wait_for("a block", |c| c.read().get_block_number() >= 2)
        .await;

    // By tag, with the fullTransactions flag.
    let latest: Value = harness
        .client
        .request("eth_getBlockByNumber", rpc_params!["latest", false])
        .await
        .unwrap();
    assert!(latest["hash"].as_str().unwrap().starts_with("0x"));

    // By tag, with the flag omitted entirely — also valid JSON-RPC.
    let genesis: Value = harness
        .client
        .request("eth_getBlockByNumber", rpc_params!["earliest"])
        .await
        .unwrap();
    assert_eq!(genesis["number"], "0x0");
    assert_eq!(
        genesis["parentHash"],
        format!("0x{}", "0".repeat(64)),
        "genesis has no parent"
    );

    // By number.
    let first: Value = harness
        .client
        .request("eth_getBlockByNumber", rpc_params!["0x1", false])
        .await
        .unwrap();
    assert_eq!(first["number"], "0x1");

    // Every field a client expects is present and hex-encoded.
    for field in [
        "number",
        "hash",
        "parentHash",
        "stateRoot",
        "transactionsRoot",
        "receiptsRoot",
        "difficulty",
        "totalDifficulty",
        "timestamp",
        "gasLimit",
        "gasUsed",
        "miner",
        "extraData",
        "nonce",
        "size",
    ] {
        let value = first[field]
            .as_str()
            .unwrap_or_else(|| panic!("{field} missing"));
        assert!(value.starts_with("0x"), "{field} is not hex: {value}");
    }
    // The proof-of-work nonce is a fixed-width 8-byte field, not a quantity.
    assert_eq!(first["nonce"].as_str().unwrap().len(), 18);
}

#[tokio::test]
async fn eth_get_block_by_number_rejects_a_block_that_does_not_exist() {
    let harness = Harness::start(&[], false).await;
    let result: Result<Value, _> = harness
        .client
        .request("eth_getBlockByNumber", rpc_params!["0xffffff", false])
        .await;
    assert!(
        result.is_err(),
        "a future block should be an error, not null"
    );
}

#[tokio::test]
async fn eth_get_block_by_hash_finds_the_same_block_as_by_number() {
    let harness = Harness::start(&[], true).await;
    harness
        .wait_for("a block", |c| c.read().get_block_number() >= 1)
        .await;

    let by_number: Value = harness
        .client
        .request("eth_getBlockByNumber", rpc_params!["0x1", false])
        .await
        .unwrap();
    let hash = by_number["hash"].as_str().unwrap().to_owned();

    let by_hash: Value = harness
        .client
        .request("eth_getBlockByHash", rpc_params![hash, false])
        .await
        .unwrap();
    assert_eq!(by_hash, by_number);

    // An unknown hash is null, not an error.
    let missing: Value = harness
        .client
        .request(
            "eth_getBlockByHash",
            rpc_params![format!("0x{}", "11".repeat(32)), false],
        )
        .await
        .unwrap();
    assert!(missing.is_null());
}

#[tokio::test]
async fn eth_get_balance_reads_current_pending_and_historical_state() {
    let alice = address_of(DEV_PRIVATE_KEY).unwrap();
    let bob = address_of(DEV_PRIVATE_KEY_1).unwrap();
    let harness = Harness::start(&[(alice, one_eth() * U256::from(100u64))], true).await;

    // Latest, and the one-parameter form.
    let balance: String = harness
        .client
        .request("eth_getBalance", rpc_params![alice, "latest"])
        .await
        .unwrap();
    assert_eq!(balance, "0x56bc75e2d63100000");
    let without_tag: String = harness
        .client
        .request("eth_getBalance", rpc_params![alice])
        .await
        .unwrap();
    assert_eq!(without_tag, balance);

    // An address nobody funded is zero, not an error.
    let empty: String = harness
        .client
        .request(
            "eth_getBalance",
            rpc_params![Address::repeat_byte(0x77), "latest"],
        )
        .await
        .unwrap();
    assert_eq!(empty, "0x0");

    // Send 5 ETH and wait for it to land.
    let raw = sign_transfer(DEV_PRIVATE_KEY, bob, one_eth() * U256::from(5u64), 0).unwrap();
    let tx_hash: String = harness
        .client
        .request("eth_sendRawTransaction", rpc_params![raw.to_string()])
        .await
        .unwrap();
    harness
        .wait_for("the transfer to be mined", |c| {
            c.read().get_account(&bob).balance > U256::ZERO
        })
        .await;

    let bob_now: String = harness
        .client
        .request("eth_getBalance", rpc_params![bob, "latest"])
        .await
        .unwrap();
    assert_eq!(from_quantity(&bob_now), 5 * 10u128.pow(18));

    // At genesis Bob had nothing, and the chain still remembers that.
    let bob_at_genesis: String = harness
        .client
        .request("eth_getBalance", rpc_params![bob, "0x0"])
        .await
        .unwrap();
    assert_eq!(bob_at_genesis, "0x0");

    let _ = tx_hash;
}

#[tokio::test]
async fn eth_get_transaction_count_tracks_mined_and_pending_nonces() {
    let alice = address_of(DEV_PRIVATE_KEY).unwrap();
    let bob = address_of(DEV_PRIVATE_KEY_1).unwrap();
    // No miner: the transactions stay pending, which is what this test is about.
    let harness = Harness::start(&[(alice, one_eth() * U256::from(100u64))], false).await;

    let mined: String = harness
        .client
        .request("eth_getTransactionCount", rpc_params![alice, "latest"])
        .await
        .unwrap();
    assert_eq!(mined, "0x0");

    for nonce in 0..2 {
        let raw = sign_transfer(DEV_PRIVATE_KEY, bob, one_eth(), nonce).unwrap();
        let _: String = harness
            .client
            .request("eth_sendRawTransaction", rpc_params![raw.to_string()])
            .await
            .unwrap();
    }

    // "latest" still sees no mined transactions...
    let mined: String = harness
        .client
        .request("eth_getTransactionCount", rpc_params![alice, "latest"])
        .await
        .unwrap();
    assert_eq!(mined, "0x0");

    // ...but "pending" includes the queued ones, which is the nonce a wallet must
    // use for its next transaction.
    let pending: String = harness
        .client
        .request("eth_getTransactionCount", rpc_params![alice, "pending"])
        .await
        .unwrap();
    assert_eq!(pending, "0x2");
}

#[tokio::test]
async fn a_transfer_produces_a_transaction_and_a_receipt() {
    let alice = address_of(DEV_PRIVATE_KEY).unwrap();
    let bob = address_of(DEV_PRIVATE_KEY_1).unwrap();
    let harness = Harness::start(&[(alice, one_eth() * U256::from(100u64))], true).await;

    let raw = sign_transfer(DEV_PRIVATE_KEY, bob, one_eth(), 0).unwrap();
    let tx_hash: String = harness
        .client
        .request("eth_sendRawTransaction", rpc_params![raw.to_string()])
        .await
        .unwrap();
    assert_eq!(tx_hash.len(), 66, "a transaction hash is 32 bytes of hex");

    // Before it is mined, there is a transaction but no receipt. That difference
    // is exactly how a client knows to keep waiting.
    harness
        .wait_for("the transfer to be mined", |c| {
            c.read().get_receipt(&tx_hash.parse().unwrap()).is_some()
        })
        .await;

    let tx: Value = harness
        .client
        .request("eth_getTransactionByHash", rpc_params![tx_hash.clone()])
        .await
        .unwrap();
    assert_eq!(tx["from"], format!("{alice:#x}"));
    assert_eq!(tx["to"], format!("{bob:#x}"));
    assert_eq!(tx["value"], "0xde0b6b3a7640000");
    assert_eq!(tx["nonce"], "0x0");
    assert_eq!(tx["input"], "0x");
    assert_eq!(tx["type"], "0x0", "legacy transaction");
    assert_eq!(tx["chainId"], "0x1");

    let receipt: Value = harness
        .client
        .request("eth_getTransactionReceipt", rpc_params![tx_hash.clone()])
        .await
        .unwrap();
    assert_eq!(receipt["status"], "0x1");
    assert_eq!(receipt["gasUsed"], "0x5208");
    assert_eq!(receipt["from"], format!("{alice:#x}"));
    assert_eq!(receipt["to"], format!("{bob:#x}"));
    assert!(
        receipt["contractAddress"].is_null(),
        "no contracts without an EVM"
    );
    assert_eq!(receipt["logs"].as_array().unwrap().len(), 0);
    assert_eq!(receipt["blockHash"], tx["blockHash"]);

    // The block it landed in lists it, and can inline it.
    let block: Value = harness
        .client
        .request(
            "eth_getBlockByHash",
            rpc_params![receipt["blockHash"].as_str().unwrap(), true],
        )
        .await
        .unwrap();
    let inlined = block["transactions"].as_array().unwrap();
    assert_eq!(inlined.len(), 1);
    assert_eq!(inlined[0]["hash"], tx_hash);

    // With the flag off, the same block lists bare hashes instead.
    let hashes_only: Value = harness
        .client
        .request(
            "eth_getBlockByHash",
            rpc_params![receipt["blockHash"].as_str().unwrap(), false],
        )
        .await
        .unwrap();
    assert_eq!(hashes_only["transactions"][0], tx_hash);
}

#[tokio::test]
async fn an_unknown_transaction_or_receipt_is_null() {
    let harness = Harness::start(&[], false).await;
    let unknown = format!("0x{}", "11".repeat(32));

    let tx: Value = harness
        .client
        .request("eth_getTransactionByHash", rpc_params![unknown.clone()])
        .await
        .unwrap();
    assert!(tx.is_null());

    let receipt: Value = harness
        .client
        .request("eth_getTransactionReceipt", rpc_params![unknown])
        .await
        .unwrap();
    assert!(receipt.is_null());
}

#[tokio::test]
async fn eth_send_raw_transaction_rejects_what_the_node_cannot_execute() {
    let alice = address_of(DEV_PRIVATE_KEY).unwrap();
    let harness = Harness::start(&[(alice, one_eth())], false).await;

    // Not hex at all.
    let result: Result<String, _> = harness
        .client
        .request("eth_sendRawTransaction", rpc_params!["not hex"])
        .await;
    assert!(result.is_err());

    // Hex, but not a transaction.
    let result: Result<String, _> = harness
        .client
        .request("eth_sendRawTransaction", rpc_params!["0xdeadbeef"])
        .await;
    assert!(result.is_err());

    // A real transaction for more ETH than the sender has.
    let raw = sign_transfer(
        DEV_PRIVATE_KEY,
        Address::repeat_byte(0x22),
        one_eth() * U256::from(1_000u64),
        0,
    )
    .unwrap();
    let result: Result<String, _> = harness
        .client
        .request("eth_sendRawTransaction", rpc_params![raw.to_string()])
        .await;
    let error = result.expect_err("an unaffordable transfer must be rejected");
    assert!(
        error.to_string().contains("insufficient funds"),
        "the error should say why: {error}"
    );
}

#[tokio::test]
async fn eth_call_executes_view_calls_without_mutating_state_and_errors_on_revert() {
    let alice = address_of(DEV_PRIVATE_KEY).unwrap();
    let harness = Harness::start(&[(alice, one_eth() * U256::from(100u64))], true).await;

    // A call with no calldata to an EOA invokes no code, so it returns no data.
    let result: String = harness
        .client
        .request(
            "eth_call",
            rpc_params![
                serde_json::json!({"to": Address::repeat_byte(0x22), "value": "0x1"}),
                "latest"
            ],
        )
        .await
        .unwrap();
    assert_eq!(result, "0x");

    // The one-parameter form is valid too.
    let result: String = harness
        .client
        .request(
            "eth_call",
            rpc_params![serde_json::json!({"to": Address::repeat_byte(0x22)})],
        )
        .await
        .unwrap();
    assert_eq!(result, "0x");

    // Previously this test asserted that calldata to `0x22..22` failed with `"no EVM"`.
    // Now that Breeja has an EVM:
    // 1. Deploy a contract whose runtime stores 42 at slot 0 when called with empty calldata,
    //    returns slot 0 (32 bytes) when called with `0x01`, and reverts when called with `0xff`.
    //    Runtime (29 bytes):
    //      00: 60 00 35          CALLDATALOAD(0)
    //      03: 60 f8 1c          SHR 248 (first byte of calldata)
    //      06: 80 60 ff 14       DUP1, PUSH1 0xff, EQ
    //      0a: 60 19 57          JUMPI -> 0x19 (revert)
    //      0d: 60 00 54          SLOAD(0)
    //      10: 60 00 52          MSTORE(0, val)
    //      13: 60 20 60 00 f3    RETURN(0, 32)
    //      18: 00                STOP
    //      19: 5b 60 00 60 00 fd JUMPDEST, REVERT(0, 0)
    //    Initcode stores 42 in slot 0 and returns the 31-byte (0x1f) runtime:
    //      60 2a 60 00 55 (SSTORE(0, 42))
    //      60 1f 60 11 60 00 39 60 1f 60 00 f3 (CODECOPY 31 bytes from offset 17, RETURN)
    let initcode: Bytes =
        "0x602a600055601f6011600039601f6000f360003560f81c8060ff1460195760005460005260206000f3005b60006000fd"
            .parse()
            .unwrap();
    let contract = derive_contract_address(alice, 0);
    let deploy_raw = sign_deploy(DEV_PRIVATE_KEY, initcode, U256::ZERO, 0, 200_000).unwrap();
    let deploy_hash: String = harness
        .client
        .request("eth_sendRawTransaction", rpc_params![deploy_raw.to_string()])
        .await
        .unwrap();
    harness
        .wait_for("contract deployment", |c| {
            c.read().get_receipt(&deploy_hash.parse().unwrap()).is_some()
        })
        .await;

    // `eth_call` reads slot 0 (42 = 0x2a) and returns 32-byte ABI-encoded word without mutating state.
    let call_out: String = harness
        .client
        .request(
            "eth_call",
            rpc_params![
                serde_json::json!({"to": contract, "data": "0x01"}),
                "latest"
            ],
        )
        .await
        .unwrap();
    assert_eq!(
        call_out,
        "0x000000000000000000000000000000000000000000000000000000000000002a"
    );

    // Calling with `0xff` triggers `REVERT` and surfaces a JSON-RPC error.
    let revert_res: Result<String, _> = harness
        .client
        .request(
            "eth_call",
            rpc_params![
                serde_json::json!({"to": contract, "data": "0xff"}),
                "latest"
            ],
        )
        .await;
    assert!(revert_res.is_err(), "a reverting eth_call must return an error");
}

#[tokio::test]
async fn eth_estimate_gas_returns_the_intrinsic_cost_of_a_transfer() {
    let alice = address_of(DEV_PRIVATE_KEY).unwrap();
    let harness = Harness::start(&[(alice, one_eth() * U256::from(10u64))], false).await;

    let estimate: String = harness
        .client
        .request(
            "eth_estimateGas",
            rpc_params![serde_json::json!({
                "from": alice,
                "to": Address::repeat_byte(0x22),
                "value": "0xde0b6b3a7640000"
            })],
        )
        .await
        .unwrap();
    assert_eq!(estimate, "0x5208", "21000 gas");

    // Previously this test checked that contract creation failed because there was no EVM.
    // Now that Breeja has an EVM, estimating a valid deployment succeeds and returns a
    // gas limit sufficient to deploy the contract, whereas estimating a reverting deployment
    // (`0x60006000fd`) returns a JSON-RPC error.
    let deploy_estimate: String = harness
        .client
        .request(
            "eth_estimateGas",
            rpc_params![serde_json::json!({
                "from": alice,
                "data": "0x600b600c600039600b6000f3602a60005560006000a000"
            })],
        )
        .await
        .unwrap();
    assert!(from_quantity(&deploy_estimate) >= 55_522);

    let revert_estimate: Result<String, _> = harness
        .client
        .request(
            "eth_estimateGas",
            rpc_params![serde_json::json!({"from": alice, "data": "0x60006000fd"})],
        )
        .await;
    assert!(revert_estimate.is_err());
}

#[tokio::test]
async fn an_unsupported_method_gets_the_standard_method_not_found_error() {
    let harness = Harness::start(&[], false).await;

    // Previously this test used `eth_gasPrice` as its example of an unimplemented method.
    // Because Milestone 5 implements `eth_gasPrice`, we now test `eth_syncing` (which
    // remains unimplemented) to verify JSON-RPC `-32601 Method not found`.
    let result: Result<Value, _> = harness.client.request("eth_syncing", rpc_params![]).await;
    let error = result.expect_err("an unregistered method must be an error");
    assert!(
        error.to_string().contains("Method not found") || error.to_string().contains("-32601"),
        "got: {error}"
    );
}

#[tokio::test]
async fn eth_gas_price_returns_the_configured_fixed_gas_price() {
    let harness = Harness::start(&[], false).await;
    let price: String = harness
        .client
        .request("eth_gasPrice", rpc_params![])
        .await
        .unwrap();
    assert_eq!(price, "0x3b9aca00", "1 gwei (1_000_000_000 wei)");
}

#[tokio::test]
async fn eth_get_code_and_eth_get_storage_at_support_historical_block_tags() {
    let alice = address_of(DEV_PRIVATE_KEY).unwrap();
    let harness = Harness::start(&[(alice, one_eth() * U256::from(100u64))], true).await;

    let initcode: Bytes = "0x600b600c600039600b6000f3602a60005560006000a000"
        .parse()
        .unwrap();
    let contract = derive_contract_address(alice, 0);

    // Before deployment, `eth_getCode` for an EOA or undeployed contract is `0x`.
    let eoa_code: String = harness
        .client
        .request("eth_getCode", rpc_params![alice, "latest"])
        .await
        .unwrap();
    assert_eq!(eoa_code, "0x");

    let deploy_raw = sign_deploy(DEV_PRIVATE_KEY, initcode, U256::ZERO, 0, 100_000).unwrap();
    let deploy_hash: String = harness
        .client
        .request("eth_sendRawTransaction", rpc_params![deploy_raw.to_string()])
        .await
        .unwrap();
    harness
        .wait_for("deploy to be mined", |c| {
            c.read().get_receipt(&deploy_hash.parse().unwrap()).is_some()
        })
        .await;

    // At latest, `eth_getCode` returns the 11-byte runtime code, while at genesis (`0x0`) it was `0x`.
    let code_latest: String = harness
        .client
        .request("eth_getCode", rpc_params![contract, "latest"])
        .await
        .unwrap();
    assert_eq!(code_latest, "0x602a60005560006000a000");

    let code_genesis: String = harness
        .client
        .request("eth_getCode", rpc_params![contract, "0x0"])
        .await
        .unwrap();
    assert_eq!(code_genesis, "0x");

    // Now call the contract so it writes 42 (`0x2a`) to storage slot 0.
    let call_raw = sign_call(
        DEV_PRIVATE_KEY,
        contract,
        Bytes::new(),
        U256::ZERO,
        1,
        100_000,
    )
    .unwrap();
    let call_hash: String = harness
        .client
        .request("eth_sendRawTransaction", rpc_params![call_raw.to_string()])
        .await
        .unwrap();
    harness
        .wait_for("call to be mined", |c| {
            c.read().get_receipt(&call_hash.parse().unwrap()).is_some()
        })
        .await;

    let slot_latest: String = harness
        .client
        .request("eth_getStorageAt", rpc_params![contract, "0x0", "latest"])
        .await
        .unwrap();
    assert_eq!(
        slot_latest,
        "0x000000000000000000000000000000000000000000000000000000000000002a"
    );

    let slot_genesis: String = harness
        .client
        .request("eth_getStorageAt", rpc_params![contract, "0x0", "0x0"])
        .await
        .unwrap();
    assert_eq!(
        slot_genesis,
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
}

#[tokio::test]
async fn eth_get_logs_filters_by_block_range_address_and_positional_topics() {
    let alice = address_of(DEV_PRIVATE_KEY).unwrap();
    let harness = Harness::start(&[(alice, one_eth() * U256::from(100u64))], true).await;

    // Runtime that emits LOG2 with topic0 = 0x1111..11 (or 0x2222..22 from calldata) and topic1 = 0xaaaa..aa:
    //   00: 60 2a 60 00 52    MSTORE(0, 42)         -- 32-byte data payload = 42
    //   05: 60 aa 60 00 35    PUSH1 0xaa, CALLDATALOAD(0) -> topic1 = 0xaa, topic0 = calldata[0..32]
    //   0a: 60 20 60 00 a2    LOG2(offset=0, size=32, topic0, topic1)
    //   0f: 00                STOP
    // Initcode (12-byte loader + 16-byte runtime = 28 bytes):
    //   60 10 60 0c 60 00 39 60 10 60 00 f3 ++ 602a60005260aa60003560206000a200
    let initcode: Bytes =
        "0x6010600c60003960106000f3602a60005260aa60003560206000a200"
            .parse()
            .unwrap();
    let contract = derive_contract_address(alice, 0);

    let deploy_raw = sign_deploy(DEV_PRIVATE_KEY, initcode, U256::ZERO, 0, 150_000).unwrap();
    let deploy_hash: String = harness
        .client
        .request("eth_sendRawTransaction", rpc_params![deploy_raw.to_string()])
        .await
        .unwrap();
    harness
        .wait_for("deploy to be mined", |c| {
            c.read().get_receipt(&deploy_hash.parse().unwrap()).is_some()
        })
        .await;

    let topic_a = format!("0x{}", "11".repeat(32));
    let topic_b = format!("0x{}", "22".repeat(32));
    let topic_1 = "0x00000000000000000000000000000000000000000000000000000000000000aa";

    let call1 = sign_call(
        DEV_PRIVATE_KEY,
        contract,
        topic_a.parse().unwrap(),
        U256::ZERO,
        1,
        100_000,
    )
    .unwrap();
    let hash1: String = harness
        .client
        .request("eth_sendRawTransaction", rpc_params![call1.to_string()])
        .await
        .unwrap();

    let call2 = sign_call(
        DEV_PRIVATE_KEY,
        contract,
        topic_b.parse().unwrap(),
        U256::ZERO,
        2,
        100_000,
    )
    .unwrap();
    let hash2: String = harness
        .client
        .request("eth_sendRawTransaction", rpc_params![call2.to_string()])
        .await
        .unwrap();

    harness
        .wait_for("both log-emitting calls to be mined", |c| {
            let s = c.read();
            s.get_receipt(&hash1.parse().unwrap()).is_some()
                && s.get_receipt(&hash2.parse().unwrap()).is_some()
        })
        .await;

    // 1. Filter by address across all blocks (`earliest` to `latest`) -> returns both logs.
    let all_logs: Vec<Value> = harness
        .client
        .request(
            "eth_getLogs",
            rpc_params![serde_json::json!({
                "fromBlock": "earliest",
                "toBlock": "latest",
                "address": contract
            })],
        )
        .await
        .unwrap();
    assert_eq!(all_logs.len(), 2);

    // 2. Filter by specific topic0 (`topic_a`) -> returns only the first log.
    let filtered_topic0: Vec<Value> = harness
        .client
        .request(
            "eth_getLogs",
            rpc_params![serde_json::json!({
                "fromBlock": "earliest",
                "toBlock": "latest",
                "address": contract,
                "topics": [topic_a]
            })],
        )
        .await
        .unwrap();
    assert_eq!(filtered_topic0.len(), 1);
    assert_eq!(filtered_topic0[0]["transactionHash"], hash1);

    // 3. Filter with wildcard `null` in position 0 and `topic_1` in position 1 -> returns both logs.
    let wildcard_logs: Vec<Value> = harness
        .client
        .request(
            "eth_getLogs",
            rpc_params![serde_json::json!({
                "fromBlock": "earliest",
                "toBlock": "latest",
                "topics": [null, topic_1]
            })],
        )
        .await
        .unwrap();
    assert_eq!(wildcard_logs.len(), 2);

    // 4. Specifying both `blockHash` and `fromBlock` is rejected per EIP-234.
    let conflict: Result<Value, _> = harness
        .client
        .request(
            "eth_getLogs",
            rpc_params![serde_json::json!({
                "blockHash": format!("0x{}", "00".repeat(32)),
                "fromBlock": "0x0"
            })],
        )
        .await;
    assert!(conflict.is_err());
}


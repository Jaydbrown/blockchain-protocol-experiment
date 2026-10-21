use alloy::primitives::{Address, B256, Bytes, U256};
use jsonrpsee::{
    core::RpcResult,
    types::{ErrorObjectOwned, Params, error::ErrorCode},
};
use node::evm::{BlockContext, simulate_tx};
use primitives::{
    constants::{BLOCK_GAS_LIMIT, CHAIN_ID, GAS_PRICE, TRANSFER_GAS},
    node::{BlockState, PendingTransaction, intrinsic_gas},
    params::{BlockTag, CallRequest, LogFilter},
    response::{
        BlockResponse, LogResponse, TransactionReceiptResponse, TransactionResponse, data_bytes,
        data_hash, quantity,
    },
};
use serde_json::Value;

use crate::RPCContext;

/// JSON-RPC error code Ethereum clients use for "your request was understood but
/// is not valid", as opposed to a malformed one.
const INVALID_INPUT: i32 = -32000;

/// Turns an internal error into a JSON-RPC error object the client can read.
fn invalid_input(error: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INVALID_INPUT, error.to_string(), None::<()>)
}

fn invalid_params(error: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        ErrorCode::InvalidParams.code(),
        error.to_string(),
        None::<()>,
    )
}

/// Parses a 32-byte hash parameter.
fn parse_hash(raw: &str) -> Result<B256, ErrorObjectOwned> {
    raw.parse::<B256>()
        .map_err(|e| invalid_params(format!("invalid 32-byte hash {raw:?}: {e}")))
}

/// Resolves a block tag against the chain head, erroring on a block that does not
/// exist rather than silently substituting the latest one.
fn resolve_tag(state: &BlockState, tag: &BlockTag) -> Result<u64, ErrorObjectOwned> {
    tag.resolve(state.get_block_number()).map_err(invalid_input)
}

/// Builds a [`BlockContext`] for executing or simulating against block `number`.
fn block_context_at(state: &BlockState, number: u64) -> BlockContext {
    if let Some(block) = state.get_block(number) {
        BlockContext {
            number: block.number,
            miner: block.miner,
            timestamp: block.timestamp,
            gas_limit: block.gas_limit,
            difficulty: block.difficulty,
            prevrandao: block.parent_hash,
        }
    } else {
        let head = state.head();
        BlockContext {
            number,
            miner: head.miner,
            timestamp: head.timestamp,
            gas_limit: BLOCK_GAS_LIMIT,
            difficulty: head.difficulty,
            prevrandao: head.hash,
        }
    }
}

/// Converts a JSON-RPC [`CallRequest`] into a synthetic [`PendingTransaction`]
/// suitable for [`simulate_tx`].
fn call_request_to_tx(request: &CallRequest, gas_limit: u64) -> PendingTransaction {
    let is_create = request.to.is_none();
    let to = request.to.unwrap_or(Address::ZERO);
    let input = request.calldata();
    let gas_price = request
        .gas_price
        .map(|p| p.try_into().unwrap_or(u128::MAX))
        .unwrap_or(0);
    PendingTransaction {
        hash: B256::ZERO,
        from: request.from.unwrap_or(Address::ZERO),
        to,
        is_create,
        value: request.value.unwrap_or(U256::ZERO),
        input,
        nonce: 0,
        gas: gas_limit,
        gas_price,
        chain_id: CHAIN_ID,
        v: 27,
        r: U256::ZERO,
        s: U256::ZERO,
    }
}

/// The chain's id, used by wallets for EIP-155 replay protection.
pub fn chain_id_handler() -> String {
    quantity(CHAIN_ID)
}

/// The chain's fixed gas price (`eth_gasPrice`).
pub fn gas_price_handler() -> String {
    quantity(GAS_PRICE)
}

/// The number of the chain head. A freshly started node sits at `0x0`, the genesis
/// block, and climbs from there as the miner seals blocks.
pub fn block_number_handler(context: &RPCContext) -> String {
    quantity(context.chain.read().get_block_number())
}

/// Renders a block, inlining full transaction objects if the caller asked for them.
fn render_block(state: &BlockState, number: u64, full_transactions: bool) -> Value {
    let Some(block) = state.get_block(number) else {
        return Value::Null;
    };

    let transactions: Vec<Value> = if full_transactions {
        block
            .transactions
            .iter()
            .filter_map(|hash| state.get_transaction(hash))
            .map(|tx| {
                serde_json::to_value(TransactionResponse::from(tx))
                    .expect("a transaction response always serializes")
            })
            .collect()
    } else {
        block
            .transactions
            .iter()
            .map(|hash| Value::String(data_hash(hash)))
            .collect()
    };

    serde_json::to_value(BlockResponse::from_block(block, transactions))
        .expect("a block response always serializes")
}

pub fn get_block_by_number_handler(params: Params<'_>, context: &RPCContext) -> RpcResult<Value> {
    // Ethereum's optional trailing parameters have to be read one at a time: a
    // client may send just the block, or the block and the `fullTransactions`
    // flag, and both are valid.
    let mut sequence = params.sequence();
    let tag: BlockTag = sequence.next()?;
    let full_transactions = sequence.optional_next::<bool>()?.unwrap_or(false);

    let state = context.chain.read();
    let number = resolve_tag(&state, &tag)?;
    Ok(render_block(&state, number, full_transactions))
}

pub fn get_block_by_hash_handler(params: Params<'_>, context: &RPCContext) -> RpcResult<Value> {
    let mut sequence = params.sequence();
    let hash = parse_hash(&sequence.next::<String>()?)?;
    let full_transactions = sequence.optional_next::<bool>()?.unwrap_or(false);

    let state = context.chain.read();
    // An unknown hash is `null`, not an error: the caller asked a legitimate
    // question and the answer is "no such block".
    let Some(number) = state.get_block_by_hash(&hash).map(|block| block.number) else {
        return Ok(Value::Null);
    };
    Ok(render_block(&state, number, full_transactions))
}

pub fn get_transaction_by_hash_handler(
    params: Params<'_>,
    context: &RPCContext,
) -> RpcResult<Value> {
    let hash = parse_hash(&params.one::<String>()?)?;

    let state = context.chain.read();
    match state.get_transaction(&hash) {
        Some(tx) => Ok(serde_json::to_value(TransactionResponse::from(tx))
            .expect("a transaction response always serializes")),
        None => Ok(Value::Null),
    }
}

/// A receipt exists only once a transaction has been mined. A transaction still
/// sitting in the mempool correctly returns `null` here, which is exactly how a
/// client polls for confirmation.
pub fn get_transaction_receipt_handler(
    params: Params<'_>,
    context: &RPCContext,
) -> RpcResult<Value> {
    let hash = parse_hash(&params.one::<String>()?)?;

    let state = context.chain.read();
    match state.get_receipt(&hash) {
        Some(receipt) => Ok(
            serde_json::to_value(TransactionReceiptResponse::from(receipt))
                .expect("a receipt response always serializes"),
        ),
        None => Ok(Value::Null),
    }
}

pub fn get_balance_handler(params: Params<'_>, context: &RPCContext) -> RpcResult<String> {
    let mut sequence = params.sequence();
    let address: Address = sequence.next()?;
    let tag = sequence
        .optional_next::<BlockTag>()?
        .unwrap_or(BlockTag::Latest);

    let state = context.chain.read();
    let balance = match tag {
        // "pending" means "after everything in the mempool lands", which is what a
        // wallet wants before it builds the next transaction.
        BlockTag::Pending => state.get_pending_balance(&address),
        _ => {
            let number = resolve_tag(&state, &tag)?;
            state
                .get_account_at(&address, number)
                .map(|account| account.balance)
                .unwrap_or(U256::ZERO)
        }
    };

    Ok(quantity(balance))
}

/// The account's nonce: how many transactions it has sent.
pub fn get_transaction_count_handler(
    params: Params<'_>,
    context: &RPCContext,
) -> RpcResult<String> {
    let mut sequence = params.sequence();
    let address: Address = sequence.next()?;
    let tag = sequence
        .optional_next::<BlockTag>()?
        .unwrap_or(BlockTag::Latest);

    let state = context.chain.read();
    let nonce = match tag {
        BlockTag::Pending => state.get_pending_nonce(&address),
        _ => {
            let number = resolve_tag(&state, &tag)?;
            state
                .get_account_at(&address, number)
                .map(|account| account.nonce)
                .unwrap_or(0)
        }
    };

    Ok(quantity(nonce))
}

/// Returns the deployed runtime bytecode at `address` as of the requested block
/// (`eth_getCode`), or `"0x"` if the account has no code.
pub fn get_code_handler(params: Params<'_>, context: &RPCContext) -> RpcResult<String> {
    let mut sequence = params.sequence();
    let address: Address = sequence.next()?;
    let tag = sequence
        .optional_next::<BlockTag>()?
        .unwrap_or(BlockTag::Latest);

    let state = context.chain.read();
    let number = resolve_tag(&state, &tag)?;
    let code = state
        .get_code_at(&address, number)
        .unwrap_or_else(Bytes::new);
    Ok(data_bytes(&code))
}

/// Returns the 32-byte word at `slot` in `address`'s contract storage as of the
/// requested block (`eth_getStorageAt`), zero-padded to 64 hex digits.
pub fn get_storage_at_handler(params: Params<'_>, context: &RPCContext) -> RpcResult<String> {
    let mut sequence = params.sequence();
    let address: Address = sequence.next()?;
    let slot: U256 = sequence.next()?;
    let tag = sequence
        .optional_next::<BlockTag>()?
        .unwrap_or(BlockTag::Latest);

    let state = context.chain.read();
    let number = resolve_tag(&state, &tag)?;
    let val = state
        .get_storage_at(&address, slot, number)
        .unwrap_or(U256::ZERO);
    let word = B256::from(val.to_be_bytes());
    Ok(data_hash(&word))
}

/// Queries event logs matching a [`LogFilter`] across a block range or single
/// block hash (`eth_getLogs`).
pub fn get_logs_handler(params: Params<'_>, context: &RPCContext) -> RpcResult<Value> {
    let filter: LogFilter = params.one()?;

    // EIP-234: specifying both `blockHash` and `fromBlock`/`toBlock` is an error.
    if filter.block_hash.is_some() && (filter.from_block.is_some() || filter.to_block.is_some()) {
        return Err(invalid_input(
            "blockHash is mutually exclusive with fromBlock and toBlock",
        ));
    }

    let state = context.chain.read();
    let (from_block, to_block) = if let Some(ref block_hash) = filter.block_hash {
        let Some(block) = state.get_block_by_hash(block_hash) else {
            return Err(invalid_input(format!("unknown block hash {block_hash}")));
        };
        (block.number, block.number)
    } else {
        let from_tag = filter.from_block.as_ref().unwrap_or(&BlockTag::Latest);
        let to_tag = filter.to_block.as_ref().unwrap_or(&BlockTag::Latest);
        let from = resolve_tag(&state, from_tag)?;
        let to = resolve_tag(&state, to_tag)?;
        (from, to)
    };

    if from_block > to_block {
        return Ok(Value::Array(Vec::new()));
    }

    let mut matching_logs = Vec::new();
    for number in from_block..=to_block {
        let Some(block) = state.get_block(number) else {
            continue;
        };
        let mut log_index_in_block = 0u64;
        for tx_hash in &block.transactions {
            let Some(receipt) = state.get_receipt(tx_hash) else {
                continue;
            };
            for log in &receipt.logs {
                let current_log_index = log_index_in_block;
                log_index_in_block += 1;

                if let Some(ref addr_filter) = filter.address {
                    if !addr_filter.matches(&log.address) {
                        continue;
                    }
                }

                if let Some(ref topic_filters) = filter.topics {
                    let topics_match = topic_filters
                        .iter()
                        .enumerate()
                        .all(|(pos, tf)| tf.matches(log.topics.get(pos)));
                    if !topics_match {
                        continue;
                    }
                }

                matching_logs.push(LogResponse::from_receipt_log(
                    receipt,
                    log,
                    current_log_index,
                ));
            }
        }
    }

    Ok(serde_json::to_value(matching_logs).expect("log responses always serialize"))
}

/// Accepts a signed transaction, validates it, and queues it for mining.
///
/// The response is the transaction hash, returned the moment the transaction is
/// *accepted* — not when it is mined. The client then polls
/// `eth_getTransactionReceipt` until a receipt appears, which is the standard
/// Ethereum confirmation flow.
pub fn send_raw_transaction_handler(params: Params<'_>, context: &RPCContext) -> RpcResult<String> {
    let raw: String = params.one()?;
    let raw: Bytes = raw
        .parse()
        .map_err(|e| invalid_params(format!("raw transaction is not valid hex: {e}")))?;

    let hash = context
        .chain
        .submit_raw_transaction(&raw)
        .map_err(invalid_input)?;

    Ok(data_hash(&hash))
}

/// Executes a read-only call against a throwaway snapshot of chain state at the
/// requested block tag (`eth_call`).
///
/// Never mutates state or increments nonces. If the call reverts or halts in the
/// EVM, returns a JSON-RPC error containing the revert reason.
pub fn call_handler(params: Params<'_>, context: &RPCContext) -> RpcResult<String> {
    let mut sequence = params.sequence();
    let request: CallRequest = sequence.next()?;
    let tag = sequence
        .optional_next::<BlockTag>()?
        .unwrap_or(BlockTag::Latest);

    let (accounts, block_ctx, block_hashes) = {
        let state = context.chain.read();
        let number = resolve_tag(&state, &tag)?;
        let accounts = state.accounts_at(number).unwrap_or_default();
        let block_ctx = block_context_at(&state, number);
        let block_hashes = state.block_hashes_snapshot();
        (accounts, block_ctx, block_hashes)
    };

    let gas_limit = request
        .gas
        .map(|g| g.try_into().unwrap_or(BLOCK_GAS_LIMIT))
        .unwrap_or(BLOCK_GAS_LIMIT);
    let tx = call_request_to_tx(&request, gas_limit);
    let outcome = simulate_tx(&accounts, &tx, &block_ctx, block_hashes, false)
        .map_err(invalid_input)?;

    if outcome.status == 0 {
        return Err(invalid_input(
            outcome
                .error_reason
                .unwrap_or_else(|| "execution reverted".to_owned()),
        ));
    }

    Ok(data_bytes(&outcome.output))
}

/// Estimates the minimum gas limit a transaction needs to succeed (`eth_estimateGas`).
///
/// Runs the transaction against a throwaway snapshot of chain state and binary
/// searches between the transaction's intrinsic gas floor and [`BLOCK_GAS_LIMIT`]
/// to find the tightest gas limit that completes with `status == 1`.
pub fn estimate_gas_handler(params: Params<'_>, context: &RPCContext) -> RpcResult<String> {
    let mut sequence = params.sequence();
    let request: CallRequest = sequence.next()?;
    let tag = sequence
        .optional_next::<BlockTag>()?
        .unwrap_or(BlockTag::Latest);

    let (accounts, block_ctx, block_hashes) = {
        let state = context.chain.read();
        let number = resolve_tag(&state, &tag)?;

        // If `from` and `value` are specified, surface insufficient funds early.
        if let Some(from) = request.from {
            let value = request.value.unwrap_or(U256::ZERO);
            let fee = U256::from(TRANSFER_GAS) * U256::from(GAS_PRICE);
            let available = state.get_pending_balance(&from);
            if !value.is_zero() && available < value + fee {
                return Err(invalid_input(format!(
                    "insufficient funds: {from} has {available} but the transfer needs {}",
                    value + fee
                )));
            }
        }

        let accounts = state.accounts_at(number).unwrap_or_default();
        let block_ctx = block_context_at(&state, number);
        let block_hashes = state.block_hashes_snapshot();
        (accounts, block_ctx, block_hashes)
    };

    let is_create = request.to.is_none();
    let calldata = request.calldata();
    let min_intrinsic = intrinsic_gas(&calldata, is_create);
    let requested_gas: u64 = request
        .gas
        .map(|g| g.try_into().unwrap_or(BLOCK_GAS_LIMIT))
        .unwrap_or(BLOCK_GAS_LIMIT);
    let high_limit = requested_gas.max(min_intrinsic);

    // First verify that the transaction succeeds at the upper gas bound.
    let high_tx = call_request_to_tx(&request, high_limit);
    let high_outcome = simulate_tx(&accounts, &high_tx, &block_ctx, block_hashes.clone(), false)
        .map_err(invalid_input)?;
    if high_outcome.status == 0 {
        return Err(invalid_input(
            high_outcome
                .error_reason
                .unwrap_or_else(|| "execution reverted".to_owned()),
        ));
    }

    // Fast path: if the transaction consumed only its intrinsic gas, no binary
    // search is needed (for example, a plain ETH transfer always costs 21,000 gas).
    if high_outcome.gas_used <= min_intrinsic {
        return Ok(quantity(min_intrinsic));
    }

    // Binary search for the lowest gas limit that succeeds, because EIP-150
    // (63/64th rule) and SSTORE stipend checks can require a slightly higher gas
    // limit than the final `gas_used`.
    let mut low = high_outcome.gas_used;
    let mut high = high_limit;

    // Check if `low` itself already works (common for single-frame transactions
    // without refunds or nested calls).
    let low_tx = call_request_to_tx(&request, low);
    if let Ok(outcome) = simulate_tx(&accounts, &low_tx, &block_ctx, block_hashes.clone(), false) {
        if outcome.status == 1 {
            return Ok(quantity(low));
        }
    }

    while low < high {
        let mid = low + (high - low) / 2;
        let mid_tx = call_request_to_tx(&request, mid);
        let works = simulate_tx(&accounts, &mid_tx, &block_ctx, block_hashes.clone(), false)
            .map(|o| o.status == 1)
            .unwrap_or(false);
        if works {
            high = mid;
        } else {
            low = mid + 1;
        }
    }

    Ok(quantity(high))
}

mod handlers;

use std::net::SocketAddr;

use jsonrpsee::{
    RpcModule,
    server::{ServerBuilder, ServerHandle},
};
use node::Chain;
use primitives::constants::RPC_ADDRESS;

use crate::handlers::{
    block_number_handler, call_handler, chain_id_handler, estimate_gas_handler,
    gas_price_handler, get_balance_handler, get_block_by_hash_handler,
    get_block_by_number_handler, get_code_handler, get_logs_handler, get_storage_at_handler,
    get_transaction_by_hash_handler, get_transaction_count_handler,
    get_transaction_receipt_handler, send_raw_transaction_handler,
};

/// What every RPC handler is given access to: the live chain.
pub struct RPCContext {
    pub chain: Chain,
}

impl RPCContext {
    pub fn new(chain: Chain) -> Self {
        Self { chain }
    }
}

/// Binds the JSON-RPC server, registers its methods, and starts serving.
///
/// Returns the handle that controls the server and the address it actually bound
/// to, which matters when `address` asked for port 0 and the OS chose one.
pub async fn start_server(
    rpc_context: RPCContext,
    address: &str,
) -> Result<(ServerHandle, SocketAddr), anyhow::Error> {
    let server = ServerBuilder::default().build(address).await?;
    let bound = server.local_addr()?;
    let mut module = RpcModule::new(rpc_context);

    module.register_method("eth_chainId", |_params, _context, _extensions| {
        chain_id_handler()
    })?;

    module.register_method("eth_gasPrice", |_params, _context, _extensions| {
        gas_price_handler()
    })?;

    module.register_method("eth_blockNumber", |_params, context, _extensions| {
        block_number_handler(context)
    })?;

    module.register_method("eth_getBlockByNumber", |params, context, _extensions| {
        get_block_by_number_handler(params, context)
    })?;

    module.register_method("eth_getBlockByHash", |params, context, _extensions| {
        get_block_by_hash_handler(params, context)
    })?;

    module.register_method(
        "eth_getTransactionByHash",
        |params, context, _extensions| get_transaction_by_hash_handler(params, context),
    )?;

    module.register_method(
        "eth_getTransactionReceipt",
        |params, context, _extensions| get_transaction_receipt_handler(params, context),
    )?;

    module.register_method("eth_getBalance", |params, context, _extensions| {
        get_balance_handler(params, context)
    })?;

    module.register_method("eth_getTransactionCount", |params, context, _extensions| {
        get_transaction_count_handler(params, context)
    })?;

    module.register_method("eth_getCode", |params, context, _extensions| {
        get_code_handler(params, context)
    })?;

    module.register_method("eth_getStorageAt", |params, context, _extensions| {
        get_storage_at_handler(params, context)
    })?;

    module.register_method("eth_getLogs", |params, context, _extensions| {
        get_logs_handler(params, context)
    })?;

    module.register_method("eth_sendRawTransaction", |params, context, _extensions| {
        send_raw_transaction_handler(params, context)
    })?;

    module.register_method("eth_call", |params, context, _extensions| {
        call_handler(params, context)
    })?;

    module.register_method("eth_estimateGas", |params, context, _extensions| {
        estimate_gas_handler(params, context)
    })?;

    tracing::info!(
        address = %bound,
        methods = module.method_names().count(),
        "JSON-RPC server listening"
    );

    Ok((server.start(module), bound))
}

/// The address the node binds to when none is given.
pub const DEFAULT_RPC_ADDRESS: &str = RPC_ADDRESS;

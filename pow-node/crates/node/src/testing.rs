use alloy::{
    consensus::{SignableTransaction, TxLegacy},
    eips::Encodable2718,
    primitives::{Address, Bytes, TxKind, U256},
    signers::{SignerSync, local::PrivateKeySigner},
};
use primitives::constants::{CHAIN_ID, GAS_PRICE, TRANSFER_GAS};

/// The private key of the first pre-funded development account
/// (`0xf39F...2266`). This is the standard Anvil/Hardhat test key: it is public
/// knowledge and must never hold real funds.
pub const DEV_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// The second development account's key (`0x7099...79C8`).
pub const DEV_PRIVATE_KEY_1: &str =
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

/// Signs an ETH transfer and encodes it the way `eth_sendRawTransaction` expects.
pub fn sign_transfer(
    private_key: &str,
    to: Address,
    value: U256,
    nonce: u64,
) -> Result<Bytes, anyhow::Error> {
    sign_transfer_with(private_key, to, value, nonce, GAS_PRICE, TRANSFER_GAS)
}

/// Signs a transfer with explicit gas parameters, for exercising the node's
/// validation rules.
pub fn sign_transfer_with(
    private_key: &str,
    to: Address,
    value: U256,
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
) -> Result<Bytes, anyhow::Error> {
    let signer: PrivateKeySigner = private_key.parse()?;

    // 1. The unsigned transaction.
    let tx = TxLegacy {
        chain_id: Some(CHAIN_ID),
        nonce,
        gas_price,
        gas_limit,
        to: TxKind::Call(to),
        value,
        input: Bytes::new(),
    };

    // 2 and 3. Sign the signature hash, which commits to every field above.
    let signature = signer.sign_hash_sync(&tx.signature_hash())?;

    // 4. Attach the signature and encode for the wire.
    let signed = tx.into_signed(signature);
    let mut encoded = Vec::new();
    signed.encode_2718(&mut encoded);

    Ok(Bytes::from(encoded))
}

/// Signs a contract creation transaction (`TxKind::Create`) and encodes it for
/// `eth_sendRawTransaction`.
pub fn sign_deploy(
    private_key: &str,
    initcode: Bytes,
    value: U256,
    nonce: u64,
    gas_limit: u64,
) -> Result<Bytes, anyhow::Error> {
    let signer: PrivateKeySigner = private_key.parse()?;
    let tx = TxLegacy {
        chain_id: Some(CHAIN_ID),
        nonce,
        gas_price: GAS_PRICE,
        gas_limit,
        to: TxKind::Create,
        value,
        input: initcode,
    };
    let signature = signer.sign_hash_sync(&tx.signature_hash())?;
    let signed = tx.into_signed(signature);
    let mut encoded = Vec::new();
    signed.encode_2718(&mut encoded);
    Ok(Bytes::from(encoded))
}

/// Signs a contract call transaction (`TxKind::Call(to)` with calldata) and
/// encodes it for `eth_sendRawTransaction`.
pub fn sign_call(
    private_key: &str,
    to: Address,
    calldata: Bytes,
    value: U256,
    nonce: u64,
    gas_limit: u64,
) -> Result<Bytes, anyhow::Error> {
    let signer: PrivateKeySigner = private_key.parse()?;
    let tx = TxLegacy {
        chain_id: Some(CHAIN_ID),
        nonce,
        gas_price: GAS_PRICE,
        gas_limit,
        to: TxKind::Call(to),
        value,
        input: calldata,
    };
    let signature = signer.sign_hash_sync(&tx.signature_hash())?;
    let signed = tx.into_signed(signature);
    let mut encoded = Vec::new();
    signed.encode_2718(&mut encoded);
    Ok(Bytes::from(encoded))
}

/// The address a private key controls.
pub fn address_of(private_key: &str) -> Result<Address, anyhow::Error> {
    let signer: PrivateKeySigner = private_key.parse()?;
    Ok(signer.address())
}

/// One ETH, in wei.
pub fn one_eth() -> U256 {
    U256::from(10u64).pow(U256::from(18))
}

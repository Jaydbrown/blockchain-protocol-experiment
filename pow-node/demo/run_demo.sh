#!/usr/bin/env bash
set -euo pipefail

RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
PRIV_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

echo "1. Checking chain ID and gas price..."
cast chain-id --rpc-url "$RPC_URL"
cast gas-price --rpc-url "$RPC_URL"

echo "2. Deploying test contract (stores 42 at slot 0 and emits LOG0 on call)..."
DEPLOY_OUT=$(cast send --legacy --rpc-url "$RPC_URL" --private-key "$PRIV_KEY" --create 0x600b600c600039600b6000f3602a60005560006000a000 --json)
CONTRACT_ADDR=$(echo "$DEPLOY_OUT" | jq -r '.contractAddress')
echo "Deployed at: $CONTRACT_ADDR"

echo "3. Verifying deployed bytecode via eth_getCode..."
cast code "$CONTRACT_ADDR" --rpc-url "$RPC_URL"

echo "4. Calling contract to write storage slot 0 = 42 and emit LOG0..."
cast send "$CONTRACT_ADDR" --legacy --rpc-url "$RPC_URL" --private-key "$PRIV_KEY"

echo "5. Reading storage slot 0 via eth_getStorageAt..."
cast storage "$CONTRACT_ADDR" 0 --rpc-url "$RPC_URL"

echo "6. Querying emitted logs via eth_getLogs..."
cast logs --from-block earliest --to-block latest --address "$CONTRACT_ADDR" --rpc-url "$RPC_URL"

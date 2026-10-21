# EVM Implementation Notes (`pow-node`)

## Part 0 — Codebase Orientation Answers

1. **Where the three "no EVM" rejections live in `pool.rs`:**
   - In `crates/node/src/pool.rs` inside `decode_and_check(raw: &Bytes)`:
     1. `TxKind::Create` was rejected (`"contract creation is not supported: this node has no EVM..."`).
     2. Non-empty calldata (`!envelope.input().is_empty()`) was rejected (`"transaction carries ... bytes of calldata: this node has no EVM..."`).
     3. The gas limit check compared `gas < TRANSFER_GAS` (`21,000`) instead of computing the transaction's true intrinsic gas (`intrinsic_gas(&input, is_create)`).
2. **How `execute_block` in `executor.rs` handles a failing transaction today, and why that must change:**
   - Previously, `execute_block` called `apply_transfer` and dropped any `Err` with a warning (`"dropping transaction that no longer applies"`), because only plain transfers existed and mempool validation guaranteed validity barring nonce/balance races.
   - With an EVM, a transaction that passes pre-execution validation (valid signature, matching nonce, sufficient upfront balance for `value + gas_limit * gas_price`, and `gas_limit >= intrinsic_gas`) can still fail *inside* EVM execution via `REVERT` (`0xfd`) or `Halt` (`OutOfGas`, `INVALID` `0xfe`, stack underflow/overflow, invalid jump destination, static-call violation). Those transactions **must be included in the block** with `status = 0`, sender nonce incremented, contract state changes rolled back, and gas charged (`gas_used` on `REVERT`, or full `gas_limit` on `Halt`).
3. **Why the miner snapshots `accounts` before releasing the read lock (`miner.rs`):**
   - Proof-of-work hashing (`pow::mine`) is a CPU-bound loop that can take seconds. Holding the `RwLock` across mining would block all incoming JSON-RPC requests (`eth_getBalance`, `eth_call`, `eth_sendRawTransaction`). Instead, the miner clones `accounts_snapshot()`, `head()`, `peek_mempool_batch()`, and `block_hashes_snapshot()` under a brief read lock, executes the block and mines the PoW seal lock-free, and re-acquires the write lock only to commit the sealed block if the chain head has not moved.
4. **How `BlockState::commit_block` preserves historical state for `eth_getBalance` at old block numbers:**
   - `BlockState` maintains `history: HashMap<u64, HashMap<Address, Account>>`. Whenever `commit_block` seals block `N`, it stores a full snapshot of the post-block `accounts` map at key `N` in `history`. Because `Account` now includes `code: Bytes` and `storage: HashMap<U256, U256>`, historical queries (`eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt`, `eth_call`, and `eth_estimateGas`) at any past block tag `0x0..=head` automatically read the exact historical account, bytecode, and storage state at that block height.

---

## Architecture & Design Decisions

### 1. `BreejaDb` (`Database` + `DatabaseCommit` in `crates/node/src/evm.rs`)
- Implements the `Database` and `DatabaseCommit` traits directly over Breeja's `HashMap<Address, Account>` world-state (`BreejaDb<'a>`).
- `Database::basic` returns `Ok(Some(AccountInfo))` for existing accounts (computing `keccak256(&account.code)` when code is present, or `KECCAK_EMPTY` otherwise) and `Ok(None)` for unknown addresses.
- `Database::storage` returns the 32-byte `U256` value at `(address, slot)` or `U256::ZERO`.
- `Database::block_hash` resolves historical block hashes from `BlockState::block_hashes_snapshot()`.
- `DatabaseCommit::commit` writes touched accounts back into `HashMap<Address, Account>`, updating `balance`, `nonce`, `code`, and `storage` (removing zeroed storage slots so `storage_root_of` remains canonical and deterministic).

### 2. Shanghai EVM Interpreter (Appendix B)
- Configured to Shanghai specification rules:
  - **Intrinsic gas**: `21,000` base + `4` per zero byte of calldata/initcode + `16` per non-zero byte + `32,000` `TxKind::Create` base + EIP-3860 initcode word cost (`2 * ceil(len / 32)`).
  - **Execution**: 1024-element `U256` stack, word-aligned expandable memory with quadratic cost (`3 * words + words^2 / 512`), pre-analyzed `JUMPDEST` bitmaps ignoring `0x5b` inside `PUSH1`..`PUSH32` immediate data, `PUSH0` (`0x5f`, EIP-3855), EIP-2929 warm/cold address and storage access tracking, EIP-3651 warm coinbase, EIP-2200/EIP-3529 `SSTORE` gas and refund rules (capped at `gas_used / 5`), and nested frames (`CALL`, `STATICCALL`, `DELEGATECALL`, `CALLCODE`, `CREATE`, `CREATE2`) with EIP-150 63/64th gas forwarding and journaled state checkpoints.
  - **Exact Gas Parity**:
    - Plain ETH transfer: `21,000` gas (`0x5208`).
    - Milestone 3 test contract deployment (`0x600b600c600039600b6000f3602a60005560006000a000`): `55,522` gas.
    - Milestone 3 test contract call (`0x602a60005560006000a000`): `43,487` gas.

### 3. State Root Commitment & Receipts Bloom Filter (`crates/primitives/src/node.rs`)
- `Account` manually implements `alloy_rlp::Encodable`, computing `storage_root = storage_root_of(&self.storage)` (sorted `(slot, value)` pairs hashed with `keccak256`) and `code_hash = keccak256(&self.code)` so `state_root_of(&accounts)` commits to balances, nonces, deployed bytecode, and contract storage.
- `compute_logs_bloom` implements the Ethereum Yellow Paper 2048-bit (256-byte) `M3:2048` Bloom filter over every log's `address` and `topics`.

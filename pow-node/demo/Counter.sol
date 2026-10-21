// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Counter — Breeja EVM Final Project Demo Contract
/// @notice Exercises storage writes, view reads, event logs, and reverts.
contract Counter {
    uint256 private count;

    event Incremented(address indexed by, uint256 newCount);

    constructor(uint256 initial) {
        count = initial;
    }

    function increment() external {
        count += 1;
        emit Incremented(msg.sender, count);
    }

    function get() external view returns (uint256) {
        return count;
    }

    function resetIfNonZero() external {
        require(count > 0, "already zero");
        count = 0;
    }
}

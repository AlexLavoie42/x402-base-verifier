// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract TxOriginGate {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function enter() external view returns (bool) {
        return tx.origin == owner;
    }
}

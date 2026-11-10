// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract LogicV1 {
    address public admin;
    uint256 public totalShards;
    uint256 public immutable hardCap;

    constructor(uint256 cap) {
        admin = msg.sender;
        hardCap = cap;
    }

    function initialize(address admin_) external {
        admin = admin_;
        totalShards = 1;
    }
}

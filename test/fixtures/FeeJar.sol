// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract FeeJar {
    address public owner;
    uint256 public fee;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setFee(uint256 newFee) external onlyOwner {
        fee = newFee;
    }
}

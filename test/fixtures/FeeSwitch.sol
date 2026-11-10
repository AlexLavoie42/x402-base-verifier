// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract FeeSwitch {
    address public owner;
    address public feeTo;

    event FeeToUpdated(address indexed newFeeTo);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setFeeTo(address newFeeTo) external onlyOwner {
        feeTo = newFeeTo;
        emit FeeToUpdated(newFeeTo);
    }
}

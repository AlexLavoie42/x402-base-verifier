// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract LazyPayee {
    IERC20 public immutable token;
    mapping(address => uint256) public owed;

    constructor(IERC20 token_) {
        token = token_;
    }

    function payout(uint256 amount) external {
        token.transfer(msg.sender, amount);
        owed[msg.sender] -= amount;
    }
}

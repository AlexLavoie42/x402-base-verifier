// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

contract WildSpender {
    IERC20 public immutable token;

    constructor(IERC20 token_) {
        token = token_;
    }

    function grant(address spender) external {
        token.approve(spender, type(uint256).max);
    }
}

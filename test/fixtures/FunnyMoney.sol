// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract FunnyMoney {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}

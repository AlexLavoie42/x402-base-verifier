// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Airdropper {
    mapping(address => uint256) public claims;

    function airdrop(address[] calldata users, uint256 amount) external {
        for (uint256 i = 0; i < users.length; i++) {
            claims[users[i]] = amount;
        }
    }
}

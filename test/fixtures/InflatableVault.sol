// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract InflatableVault {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 public totalAssets;

    function deposit(uint256 amount) external {
        uint256 newShares = amount * totalShares / totalAssets;
        totalShares += newShares;
        shares[msg.sender] += newShares;
        totalAssets += amount;
    }
}

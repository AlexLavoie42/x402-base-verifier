// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract RiggedRaffle {
    uint256 public seed;

    function drawWinner(address[] calldata players) external returns (address winner) {
        uint256 roll = uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao, players.length)));
        winner = players[roll % players.length];
        seed = roll;
    }
}

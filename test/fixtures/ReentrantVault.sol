// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract ReentrantVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        (bool sent, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
}

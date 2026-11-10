// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract OldWallet {
    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}

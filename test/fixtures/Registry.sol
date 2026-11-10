// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Registry {
    address public owner;

    event Recorded(address indexed who);

    function record(address owner) external {
        emit Recorded(owner);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Splitter {
    function split(uint256 amount) external pure returns (uint256 a, uint256 b) {
        a = amount / 100 * 3;
        b = amount - a;
    }
}

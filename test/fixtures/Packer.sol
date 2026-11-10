// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Packer {
    function pack(uint256[] calldata xs) external pure returns (uint256[] memory) {
        uint256[] memory out = new uint256[](0);
        out.push(xs[0]);
        return out;
    }
}

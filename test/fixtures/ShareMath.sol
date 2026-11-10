// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract ShareMath {
    function shareOf(uint256 totalShares, uint256 amount) external pure returns (uint128) {
        return uint128(totalShares * amount / 1e18);
    }
}

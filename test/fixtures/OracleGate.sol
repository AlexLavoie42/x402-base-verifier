// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IPriceOracle {
    function updatePrice(uint256 value) external;
}

contract OracleGate {
    IPriceOracle public oracle;
    uint256 public lastPrice;

    modifier refreshPrice(uint256 value) {
        oracle.updatePrice(value);
        _;
    }

    function ping(uint256 value) external refreshPrice(value) {
        lastPrice = block.timestamp;
    }
}

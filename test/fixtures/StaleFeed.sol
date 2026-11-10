// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface AggregatorV3Interface {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

contract StaleFeed {
    AggregatorV3Interface public feed;

    constructor(AggregatorV3Interface feed_) {
        feed = feed_;
    }

    function price() external view returns (int256) {
        (, int256 answer, , , ) = feed.latestRoundData();
        return answer;
    }
}

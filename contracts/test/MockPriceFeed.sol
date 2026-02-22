// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MockPriceFeed
/// @notice Mock Chainlink AggregatorV3Interface for testing -- returns a fixed ETH/USD price
contract MockPriceFeed {
    int256 private _price;
    uint8 private _decimals;

    constructor(int256 price_, uint8 decimals_) {
        _price = price_;
        _decimals = decimals_;
    }

    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        return (1, _price, block.timestamp, block.timestamp, 1);
    }

    function decimals() external view returns (uint8) {
        return _decimals;
    }

    /// @notice Update the mock price (useful for testing price changes)
    function setPrice(int256 newPrice) external {
        _price = newPrice;
    }
}

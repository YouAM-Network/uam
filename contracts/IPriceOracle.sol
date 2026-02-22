// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPriceOracle {
    /// @notice Get annual lease price in wei for a name
    /// @param name The namespace to price
    /// @param existingCount How many names the account already owns (for quadratic)
    /// @return priceWei Annual lease cost in wei
    function getPrice(string calldata name, uint256 existingCount) external view returns (uint256 priceWei);

    /// @notice Get minimum transfer fee in wei (flat USD fee converted to ETH)
    /// @return feeWei Transfer fee in wei
    function getTransferFee() external view returns (uint256 feeWei);

    /// @notice Get Dutch auction price (decays over time)
    /// @param name The namespace
    /// @param auctionStart Block timestamp when auction began
    /// @param ceilingPrice Starting price in wei
    /// @param floorPrice Minimum price in wei
    /// @param duration Auction duration in seconds
    /// @return priceWei Current auction price
    function getAuctionPrice(
        string calldata name,
        uint256 auctionStart,
        uint256 ceilingPrice,
        uint256 floorPrice,
        uint256 duration
    ) external view returns (uint256 priceWei);
}

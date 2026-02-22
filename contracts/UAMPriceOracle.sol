// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPriceOracle} from "./IPriceOracle.sol";

/// @notice Minimal Chainlink AggregatorV3Interface for ETH/USD price feed
interface AggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);

    function decimals() external view returns (uint8);
}

/// @title UAMPriceOracle
/// @notice Tiered annual lease pricing with quadratic anti-squatting and Dutch auction support
/// @dev Uses Chainlink ETH/USD price feed (8 decimal precision) for USD-to-ETH conversion
contract UAMPriceOracle is IPriceOracle {
    // ─── Ownership ───────────────────────────────────────────────
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Unauthorized");
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid owner");
        owner = newOwner;
    }

    // ─── State ───────────────────────────────────────────────────
    AggregatorV3Interface public immutable priceFeed;

    // USD prices in cents (to avoid decimals)
    // Tier 1-2 chars: $1000/yr = 100_000 cents
    // Tier 3 chars:   $300/yr  =  30_000 cents
    // Tier 4 chars:   $100/yr  =  10_000 cents
    // Tier 5+ chars:  $5/yr    =     500 cents
    uint256 public constant TIER_1_2_PRICE_CENTS = 100_000;
    uint256 public constant TIER_3_PRICE_CENTS = 30_000;
    uint256 public constant TIER_4_PRICE_CENTS = 10_000;
    uint256 public constant TIER_5_PLUS_PRICE_CENTS = 500;

    // Minimum transfer fee: $10 = 1000 cents
    uint256 public constant TRANSFER_FEE_CENTS = 1_000;

    // ─── Constructor ─────────────────────────────────────────────
    constructor(address _priceFeed) {
        owner = msg.sender;
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    // ─── IPriceOracle ────────────────────────────────────────────

    /// @inheritdoc IPriceOracle
    function getPrice(string calldata name, uint256 existingCount) external view override returns (uint256 priceWei) {
        uint256 nameLength = bytes(name).length;
        uint256 baseCents = _basePriceCents(nameLength);

        // Quadratic: first name = 1x, second = 2x, third = 3x, ...
        uint256 multiplier = existingCount + 1;
        uint256 totalCents = baseCents * multiplier;

        priceWei = _centsToWei(totalCents);
    }

    /// @inheritdoc IPriceOracle
    function getTransferFee() external view override returns (uint256 feeWei) {
        feeWei = _centsToWei(TRANSFER_FEE_CENTS);
    }

    /// @inheritdoc IPriceOracle
    function getAuctionPrice(
        string calldata, /* name */
        uint256 auctionStart,
        uint256 ceilingPrice,
        uint256 floorPrice,
        uint256 duration
    ) external view override returns (uint256 priceWei) {
        require(ceilingPrice >= floorPrice, "Ceiling < floor");
        require(duration > 0, "Duration zero");

        uint256 elapsed = block.timestamp - auctionStart;

        if (elapsed >= duration) {
            return floorPrice;
        }

        // Linear decay: ceiling - ((ceiling - floor) * elapsed / duration)
        uint256 decay = ((ceilingPrice - floorPrice) * elapsed) / duration;
        priceWei = ceilingPrice - decay;
    }

    // ─── Internal ────────────────────────────────────────────────

    /// @notice Get base USD price in cents for a name based on character length
    function _basePriceCents(uint256 nameLength) internal pure returns (uint256) {
        if (nameLength <= 2) {
            return TIER_1_2_PRICE_CENTS;
        } else if (nameLength == 3) {
            return TIER_3_PRICE_CENTS;
        } else if (nameLength == 4) {
            return TIER_4_PRICE_CENTS;
        } else {
            return TIER_5_PLUS_PRICE_CENTS;
        }
    }

    /// @notice Convert USD cents to wei using Chainlink ETH/USD price feed
    /// @dev Chainlink returns price with 8 decimals (e.g., 200000000000 = $2000.00)
    ///      Formula: (cents / 100) / ethPrice * 1e18
    ///      Rearranged to avoid precision loss: (cents * 1e18 * 1e8) / (100 * ethPrice)
    function _centsToWei(uint256 cents) internal view returns (uint256) {
        (, int256 ethPrice,,,) = priceFeed.latestRoundData();
        require(ethPrice > 0, "Invalid price feed");

        uint8 feedDecimals = priceFeed.decimals();

        // cents * 1e18 / (100 * (ethPrice / 10^feedDecimals))
        // = cents * 1e18 * 10^feedDecimals / (100 * ethPrice)
        return (cents * 1e18 * (10 ** feedDecimals)) / (100 * uint256(ethPrice));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// DEPLOYMENT STEPS:
// 1. Fund deployer wallet on Base Sepolia: https://www.alchemy.com/faucets/base-sepolia
// 2. Set env vars: PRIVATE_KEY, BASE_SEPOLIA_RPC_URL, BASESCAN_API_KEY
// 3. Run: make deploy-sepolia
// 4. Update deployments/sepolia.json with deployed addresses from output
// 5. Run: make abi (generates ABI JSON for SDK consumption)
// 6. Optionally run fork tests: REGISTRY_ADDRESS=0x... BASE_SEPOLIA_RPC_URL=... forge test --match-path test/Integration.t.sol

import {Script, console} from "forge-std/Script.sol";
import {UAMPriceOracle} from "../UAMPriceOracle.sol";
import {UAMNameRegistry} from "../UAMNameRegistry.sol";

/// @title Deploy UAM Name Registry to Base Sepolia
/// @notice Deploys UAMPriceOracle (with Chainlink ETH/USD feed) and UAMNameRegistry
/// @dev Reads PRIVATE_KEY from environment. Uses Base Sepolia Chainlink ETH/USD price feed
///      by default, or deploys a MockPriceFeed as fallback if PRICE_FEED_ADDRESS is set to 0x0.
contract DeploySepolia is Script {
    // Base Sepolia Chainlink ETH/USD price feed
    address constant BASE_SEPOLIA_ETH_USD_FEED = 0x4adC67D868764F3Fc48Ed4b29f11f7e7380B9027;

    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");

        // Use Chainlink feed by default, allow override via env var
        address priceFeedAddr = vm.envOr("PRICE_FEED_ADDRESS", BASE_SEPOLIA_ETH_USD_FEED);

        vm.startBroadcast(deployerKey);

        // Deploy a mock if explicitly set to zero address (for testing without Chainlink)
        if (priceFeedAddr == address(0)) {
            MockPriceFeedForSepolia mock = new MockPriceFeedForSepolia(200_000_000_000, 8);
            priceFeedAddr = address(mock);
            console.log("Deployed MockPriceFeed:", priceFeedAddr);
        }

        // Deploy price oracle with Chainlink (or mock) feed
        UAMPriceOracle oracle = new UAMPriceOracle(priceFeedAddr);
        console.log("Deployed UAMPriceOracle:", address(oracle));

        // Deploy name registry with the oracle
        UAMNameRegistry registry = new UAMNameRegistry(address(oracle));
        console.log("Deployed UAMNameRegistry:", address(registry));

        vm.stopBroadcast();

        // Log summary for deployment artifact update
        console.log("--- Deployment Summary ---");
        console.log("Network: Base Sepolia (chain ID 84532)");
        console.log("Price Feed:", priceFeedAddr);
        console.log("Oracle:", address(oracle));
        console.log("Registry:", address(registry));
    }
}

/// @notice Minimal mock for deployment when no real Chainlink feed is available
contract MockPriceFeedForSepolia {
    int256 private _price;
    uint8 private _decimals;

    constructor(int256 price_, uint8 decimals_) {
        _price = price_;
        _decimals = decimals_;
    }

    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80)
    {
        return (1, _price, block.timestamp, block.timestamp, 1);
    }

    function decimals() external view returns (uint8) {
        return _decimals;
    }
}

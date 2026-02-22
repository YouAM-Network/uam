// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {UAMPriceOracle} from "../UAMPriceOracle.sol";
import {UAMNameRegistry} from "../UAMNameRegistry.sol";

/// @title Deploy UAM Name Registry
/// @notice Deployment script for Base Sepolia testnet or local Anvil
/// @dev Usage:
///   Local:   forge script script/Deploy.s.sol --fork-url http://localhost:8545 --broadcast
///   Testnet: forge script script/Deploy.s.sol --rpc-url $BASE_SEPOLIA_RPC --broadcast --verify
contract DeployScript is Script {
    function run() external {
        // Use env var for Chainlink feed address, default to zero for local (will deploy mock)
        address priceFeedAddr = vm.envOr("PRICE_FEED_ADDRESS", address(0));

        vm.startBroadcast();

        // If no price feed address provided, deploy a mock ($2000/ETH, 8 decimals)
        if (priceFeedAddr == address(0)) {
            // Deploy inline mock for local/testnet
            MockPriceFeedForDeploy mock = new MockPriceFeedForDeploy(200_000_000_000, 8);
            priceFeedAddr = address(mock);
            console.log("Deployed MockPriceFeed:", priceFeedAddr);
        }

        // Deploy price oracle
        UAMPriceOracle oracle = new UAMPriceOracle(priceFeedAddr);
        console.log("Deployed UAMPriceOracle:", address(oracle));

        // Deploy name registry
        UAMNameRegistry registry = new UAMNameRegistry(address(oracle));
        console.log("Deployed UAMNameRegistry:", address(registry));

        vm.stopBroadcast();
    }
}

/// @notice Minimal mock for deployment when no real Chainlink feed is available
contract MockPriceFeedForDeploy {
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

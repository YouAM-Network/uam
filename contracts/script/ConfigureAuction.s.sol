// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// DUTCH AUCTION CONFIGURATION:
// Configures a Dutch auction on the deployed UAMNameRegistry.
// Prices linearly decay from ceiling to floor over the specified duration.
//
// Usage:
//   make configure-auction REGISTRY_ADDRESS=0x...
//
// Default parameters:
//   Ceiling: 10 ETH (premium names start high)
//   Floor:   0.001 ETH (~$5/yr at $2000/ETH, matches 5+ char tier)
//   Duration: 7 days (604800 seconds)

import {Script, console} from "forge-std/Script.sol";
import {UAMNameRegistry} from "../UAMNameRegistry.sol";

/// @title Configure Dutch Auction on UAMNameRegistry
/// @notice Sets ceiling price, floor price, and duration for the initial name drop
contract ConfigureAuction is Script {
    // Default auction parameters
    uint256 constant CEILING_PRICE = 10 ether;       // Starting price
    uint256 constant FLOOR_PRICE = 0.001 ether;       // Minimum price (~$5/yr at $2000/ETH)
    uint256 constant DURATION = 7 days;                // 604800 seconds

    function run() external {
        address registryAddr = vm.envAddress("REGISTRY_ADDRESS");
        UAMNameRegistry registry = UAMNameRegistry(payable(registryAddr));

        uint256 deployerKey = vm.envUint("PRIVATE_KEY");

        // Allow overriding defaults via env vars
        uint256 ceiling = vm.envOr("AUCTION_CEILING", CEILING_PRICE);
        uint256 floor = vm.envOr("AUCTION_FLOOR", FLOOR_PRICE);
        uint256 duration = vm.envOr("AUCTION_DURATION", DURATION);

        vm.startBroadcast(deployerKey);

        registry.configureAuction(ceiling, floor, duration);

        vm.stopBroadcast();

        // Log configuration summary
        console.log("--- Dutch Auction Configured ---");
        console.log("Registry:", registryAddr);
        console.log("Ceiling price (wei):", ceiling);
        console.log("Floor price (wei):", floor);
        console.log("Duration (seconds):", duration);
        console.log("Auction start:", block.timestamp);
        console.log("Expected end:", block.timestamp + duration);
        console.log("");
        console.log("Price decays linearly from ceiling to floor over duration.");
        console.log("After duration, price stays at floor until endAuction() is called.");
    }
}

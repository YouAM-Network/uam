// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// BATCH NAME RESERVATION:
// This script reserves protocol-critical names to the deployer (treasury) address.
// Because commit-reveal requires separate transactions, this uses two script contracts:
//   1. ReserveNamesCommit -- commits all reserved names
//   2. ReserveNamesReveal -- reveals/registers all reserved names (run after 1+ block)
//
// Usage:
//   make reserve-names-commit REGISTRY_ADDRESS=0x...
//   (wait 1 block)
//   make reserve-names-reveal REGISTRY_ADDRESS=0x...

import {Script, console} from "forge-std/Script.sol";
import {UAMNameRegistry} from "../UAMNameRegistry.sol";

/// @title ReserveNamesCommit -- Phase 1: Commit all reserved names
/// @notice Submits commitment hashes for all reserved names
contract ReserveNamesCommit is Script {
    function run() external {
        address registryAddr = vm.envAddress("REGISTRY_ADDRESS");
        UAMNameRegistry registry = UAMNameRegistry(payable(registryAddr));

        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);

        // Reserved names -- protocol-critical, registered to treasury
        string[18] memory reserved = [
            "uam", "protocol", "admin", "system", "relay", "registry",
            "test", "demo", "hello", "support", "help", "info",
            "api", "sdk", "docs", "network", "bridge", "hub"
        ];

        vm.startBroadcast(deployerKey);

        uint256 committed = 0;
        for (uint256 i = 0; i < reserved.length; i++) {
            // Check if name is still available
            if (!registry.available(reserved[i])) {
                console.log("SKIP (already registered):", reserved[i]);
                continue;
            }

            // Unique secret per name
            bytes32 secret = keccak256(abi.encodePacked("reserve", reserved[i]));
            bytes32 commitment = registry.makeCommitment(reserved[i], deployer, secret);

            registry.commit(commitment);
            console.log("Committed:", reserved[i]);
            committed++;
        }

        vm.stopBroadcast();

        console.log("--- Commit Phase Complete ---");
        console.log("Names committed:", committed);
        console.log("");
        console.log("NEXT: Wait at least 1 block, then run:");
        console.log("  make reserve-names-reveal REGISTRY_ADDRESS=", registryAddr);
    }
}

/// @title ReserveNamesReveal -- Phase 2: Reveal and register all reserved names
/// @notice Registers all previously committed reserved names to the deployer address
contract ReserveNamesReveal is Script {
    function run() external {
        address registryAddr = vm.envAddress("REGISTRY_ADDRESS");
        UAMNameRegistry registry = UAMNameRegistry(payable(registryAddr));

        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);

        // Must match the same list used in ReserveNamesCommit
        string[18] memory reserved = [
            "uam", "protocol", "admin", "system", "relay", "registry",
            "test", "demo", "hello", "support", "help", "info",
            "api", "sdk", "docs", "network", "bridge", "hub"
        ];

        // Placeholder public key and relay URL for reserved names
        string memory publicKey = "RESERVED";
        string memory relayUrl = "https://relay.youam.network";

        vm.startBroadcast(deployerKey);

        uint256 registered = 0;
        for (uint256 i = 0; i < reserved.length; i++) {
            // Check if name is still available (may have been registered between commit and reveal)
            if (!registry.available(reserved[i])) {
                console.log("SKIP (not available):", reserved[i]);
                continue;
            }

            // Same secret as used in commit phase
            bytes32 secret = keccak256(abi.encodePacked("reserve", reserved[i]));

            // Register with 0 value -- reserved names should not have premium pricing set
            // If the contract requires payment, this will revert and the name is skipped
            try registry.register{value: 0}(reserved[i], publicKey, relayUrl, secret) {
                console.log("Registered:", reserved[i]);
                registered++;
            } catch {
                console.log("FAILED (likely needs payment):", reserved[i]);
            }
        }

        vm.stopBroadcast();

        console.log("--- Reveal Phase Complete ---");
        console.log("Names registered:", registered);
        console.log("Owner:", deployer);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {UAMNameRegistry} from "../UAMNameRegistry.sol";

/// @title UAMNameRegistry Integration Tests (Fork-based)
/// @notice Tests that run against a live Base Sepolia fork.
///         Requires BASE_SEPOLIA_RPC_URL and REGISTRY_ADDRESS env vars.
///         All tests are skipped (vm.skip) when env vars are not set.
/// @dev Run with:
///   BASE_SEPOLIA_RPC_URL=... REGISTRY_ADDRESS=0x... forge test --match-path test/Integration.t.sol -vvv
contract IntegrationTest is Test {
    UAMNameRegistry public registry;
    bool public shouldSkip;

    // Test account for fork tests
    address public testUser = address(0xF00D);
    bytes32 constant SECRET = keccak256("integration-test-secret");

    function setUp() public {
        // Check if fork env vars are available
        string memory rpcUrl = vm.envOr("BASE_SEPOLIA_RPC_URL", string(""));
        string memory registryAddr = vm.envOr("REGISTRY_ADDRESS", string(""));

        if (bytes(rpcUrl).length == 0 || bytes(registryAddr).length == 0) {
            shouldSkip = true;
            return;
        }

        // Create fork of Base Sepolia
        vm.createSelectFork(rpcUrl);

        // Load deployed registry contract
        registry = UAMNameRegistry(payable(vm.parseAddress(registryAddr)));

        // Fund test user on the fork
        vm.deal(testUser, 10 ether);
    }

    /// @notice Resolving a non-existent name should revert with NameNotFound
    function test_fork_resolve_nonexistent() public {
        if (shouldSkip) {
            vm.skip(true);
            return;
        }

        vm.expectRevert(UAMNameRegistry.NameNotFound.selector);
        registry.resolve("this-name-does-not-exist-xyz123");
    }

    /// @notice Register a name via commit-reveal and then resolve it
    function test_fork_register_and_resolve() public {
        if (shouldSkip) {
            vm.skip(true);
            return;
        }

        string memory testName = "integrationtest42";
        string memory testPubKey = "base64-ed25519-pubkey-test";
        string memory testRelayUrl = "wss://relay.youam.network";

        // Step 1: Check name is available
        bool isAvailable = registry.available(testName);
        if (!isAvailable) {
            // Name already taken from a previous test run -- skip
            vm.skip(true);
            return;
        }

        // Step 2: Commit
        vm.startPrank(testUser);
        bytes32 commitment = registry.makeCommitment(testName, testUser, SECRET);
        registry.commit(commitment);

        // Step 3: Wait for MIN_COMMITMENT_AGE (1 second)
        vm.warp(block.timestamp + 2);

        // Step 4: Register (need to calculate price)
        // Use a generous payment -- overpay and get refund
        registry.register{value: 1 ether}(testName, testPubKey, testRelayUrl, SECRET);
        vm.stopPrank();

        // Step 5: Resolve and verify
        (address owner, string memory pubKey, string memory relayUrl, uint256 expiry) =
            registry.resolve(testName);

        assertEq(owner, testUser, "Owner should be test user");
        assertEq(pubKey, testPubKey, "Public key should match");
        assertEq(relayUrl, testRelayUrl, "Relay URL should match");
        assertGt(expiry, block.timestamp, "Expiry should be in the future");
    }

    /// @notice Check availability before and after registration
    function test_fork_available() public {
        if (shouldSkip) {
            vm.skip(true);
            return;
        }

        string memory testName = "availcheck99";

        // Check initial availability
        bool beforeReg = registry.available(testName);
        if (!beforeReg) {
            // Already registered from previous run
            vm.skip(true);
            return;
        }
        assertTrue(beforeReg, "Name should be available before registration");

        // Register the name
        vm.startPrank(testUser);
        bytes32 commitment = registry.makeCommitment(testName, testUser, SECRET);
        registry.commit(commitment);
        vm.warp(block.timestamp + 2);
        registry.register{value: 1 ether}(testName, "pk", "wss://relay.test", SECRET);
        vm.stopPrank();

        // Check availability after registration
        bool afterReg = registry.available(testName);
        assertFalse(afterReg, "Name should NOT be available after registration");
    }
}

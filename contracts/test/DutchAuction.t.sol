// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {UAMNameRegistry} from "../UAMNameRegistry.sol";
import {UAMPriceOracle} from "../UAMPriceOracle.sol";
import {MockPriceFeed} from "./MockPriceFeed.sol";

/// @title Dutch Auction Test Suite
/// @notice Tests for Dutch auction pricing behavior integrated into UAMNameRegistry.
///         Covers price decay, registration during/after auction, access control, and edge cases.
contract DutchAuctionTest is Test {
    UAMNameRegistry public registry;
    UAMPriceOracle public oracle;
    MockPriceFeed public priceFeed;

    address public deployer = address(this);
    address public alice = address(0xA11CE);
    address public bob = address(0xB0B);

    // ETH/USD = $2000, 8 decimals
    int256 constant ETH_USD_PRICE = 200_000_000_000;
    uint8 constant FEED_DECIMALS = 8;

    // Auction parameters
    uint256 constant CEILING = 10 ether;
    uint256 constant FLOOR = 1 ether;
    uint256 constant DURATION = 7 days;

    bytes32 constant SECRET = keccak256("auction-test-secret");

    function setUp() public {
        // Deploy mock price feed at $2000/ETH
        priceFeed = new MockPriceFeed(ETH_USD_PRICE, FEED_DECIMALS);

        // Deploy price oracle with mock feed
        oracle = new UAMPriceOracle(address(priceFeed));

        // Deploy name registry with oracle
        registry = new UAMNameRegistry(address(oracle));

        // Fund test accounts
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
    }

    // ─── Helpers ──────────────────────────────────────────────────────

    /// @dev Register a name through the full commit-reveal flow
    function _registerName(
        address user,
        string memory name,
        uint256 value
    ) internal {
        bytes32 commitment = registry.makeCommitment(name, user, SECRET);

        vm.prank(user);
        registry.commit(commitment);

        // Advance time by 2 seconds (past MIN_COMMITMENT_AGE)
        vm.warp(block.timestamp + 2);

        vm.prank(user);
        registry.register{value: value}(name, "pk", "https://relay.youam.network", SECRET);
    }

    /// @dev Start a Dutch auction with default parameters
    function _startAuction() internal {
        registry.configureAuction(CEILING, FLOOR, DURATION);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  AUCTION PRICING TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_auction_price_at_start() public {
        _startAuction();

        // At t=0, price should equal ceiling
        uint256 price = registry.getCurrentAuctionPrice("testname");
        assertEq(price, CEILING, "Price at start should equal ceiling");
    }

    function test_auction_price_at_midpoint() public {
        _startAuction();

        // Warp to midpoint
        vm.warp(block.timestamp + DURATION / 2);

        uint256 price = registry.getCurrentAuctionPrice("testname");
        uint256 expectedMidpoint = (CEILING + FLOOR) / 2;
        assertEq(price, expectedMidpoint, "Price at midpoint should be (ceiling + floor) / 2");
    }

    function test_auction_price_at_end() public {
        _startAuction();

        // Warp to end of auction
        vm.warp(block.timestamp + DURATION);

        uint256 price = registry.getCurrentAuctionPrice("testname");
        assertEq(price, FLOOR, "Price at end should equal floor");
    }

    function test_auction_price_decay() public {
        _startAuction();
        uint256 startTime = block.timestamp;

        // Sample 10 evenly-spaced points and verify strict decrease
        uint256 previousPrice = type(uint256).max;

        for (uint256 i = 0; i < 10; i++) {
            uint256 t = startTime + (DURATION * i) / 9;
            vm.warp(t);

            uint256 price = registry.getCurrentAuctionPrice("testname");
            assertTrue(price < previousPrice, "Price should strictly decrease over time");
            previousPrice = price;
        }

        // Final price at end should be floor
        vm.warp(startTime + DURATION);
        uint256 finalPrice = registry.getCurrentAuctionPrice("testname");
        assertEq(finalPrice, FLOOR, "Final price should be floor");
    }

    // ═══════════════════════════════════════════════════════════════════
    //  REGISTRATION DURING/AFTER AUCTION
    // ═══════════════════════════════════════════════════════════════════

    function test_register_during_auction() public {
        _startAuction();

        // Warp to midpoint for a known price
        vm.warp(block.timestamp + DURATION / 2);

        uint256 auctionPrice = registry.getCurrentAuctionPrice("agent");

        // Commit and register during auction
        bytes32 commitment = registry.makeCommitment("agent", alice, SECRET);
        vm.prank(alice);
        registry.commit(commitment);

        // Need to warp at least 1 more second for commit-reveal gap
        vm.warp(block.timestamp + 2);

        // Price may have slightly decreased due to 2 extra seconds, so pay the previously fetched price
        // which should still be sufficient (price only decreases)
        vm.prank(alice);
        registry.register{value: auctionPrice}("agent", "pk", "https://relay.youam.network", SECRET);

        // Verify registration
        (address owner,,,) = registry.resolve("agent");
        assertEq(owner, alice, "Name should be registered to alice");
    }

    function test_register_after_auction() public {
        _startAuction();

        // End the auction
        registry.endAuction();

        // After auction ends, standard tier pricing resumes
        uint256 standardPrice = oracle.getPrice("agent", 0);

        // Commit and register with standard pricing
        _registerName(alice, "agent", standardPrice);

        // Verify registration
        (address owner,,,) = registry.resolve("agent");
        assertEq(owner, alice, "Name should be registered to alice with standard pricing");

        // Verify auction is not active
        assertFalse(registry.auctionActive(), "Auction should not be active");
    }

    // ═══════════════════════════════════════════════════════════════════
    //  ACCESS CONTROL TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_only_owner_configures_auction() public {
        // Non-owner should revert
        vm.prank(alice);
        vm.expectRevert(UAMNameRegistry.Unauthorized.selector);
        registry.configureAuction(CEILING, FLOOR, DURATION);
    }

    function test_only_owner_ends_auction() public {
        _startAuction();

        // Non-owner should revert
        vm.prank(alice);
        vm.expectRevert(UAMNameRegistry.Unauthorized.selector);
        registry.endAuction();
    }

    // ═══════════════════════════════════════════════════════════════════
    //  ERROR HANDLING TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_getCurrentAuctionPrice_reverts_when_inactive() public {
        // Auction not started -- should revert
        vm.expectRevert(UAMNameRegistry.AuctionNotActive.selector);
        registry.getCurrentAuctionPrice("testname");
    }

    function test_getCurrentAuctionPrice_reverts_after_end() public {
        _startAuction();

        // End auction
        registry.endAuction();

        // Should revert since auction is no longer active
        vm.expectRevert(UAMNameRegistry.AuctionNotActive.selector);
        registry.getCurrentAuctionPrice("testname");
    }

    // ═══════════════════════════════════════════════════════════════════
    //  AUCTION EVENTS
    // ═══════════════════════════════════════════════════════════════════

    function test_auction_configured_event() public {
        vm.expectEmit(false, false, false, true);
        emit UAMNameRegistry.AuctionConfigured(CEILING, FLOOR, DURATION, block.timestamp);
        registry.configureAuction(CEILING, FLOOR, DURATION);
    }

    function test_auction_ended_event() public {
        _startAuction();

        vm.expectEmit(false, false, false, true);
        emit UAMNameRegistry.AuctionEnded(block.timestamp);
        registry.endAuction();
    }

    // Allow contract to receive ETH
    receive() external payable {}
}

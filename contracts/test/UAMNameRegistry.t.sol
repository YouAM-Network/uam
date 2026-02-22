// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {UAMNameRegistry} from "../UAMNameRegistry.sol";
import {UAMPriceOracle} from "../UAMPriceOracle.sol";
import {MockPriceFeed} from "./MockPriceFeed.sol";

/// @title UAMNameRegistry Test Suite
/// @notice Comprehensive Foundry tests covering commit-reveal, pricing tiers,
///         quadratic pricing, name validation, premium controls, and royalties.
contract UAMNameRegistryTest is Test {
    UAMNameRegistry public registry;
    UAMPriceOracle public oracle;
    MockPriceFeed public priceFeed;

    address public deployer = address(this);
    address public alice = address(0xA11CE);
    address public bob = address(0xB0B);
    address public carol = address(0xCA201);

    // ETH/USD = $2000, 8 decimals
    int256 constant ETH_USD_PRICE = 200_000_000_000; // $2000.00 * 1e8
    uint8 constant FEED_DECIMALS = 8;

    bytes32 constant SECRET = keccak256("my-secret");

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
        vm.deal(carol, 100 ether);
    }

    // ─── Helpers ──────────────────────────────────────────────────────

    /// @dev Register a name through the full commit-reveal flow
    function _registerName(
        address user,
        string memory name,
        string memory pubKey,
        string memory relayUrl,
        uint256 value
    ) internal {
        bytes32 commitment = registry.makeCommitment(name, user, SECRET);

        vm.prank(user);
        registry.commit(commitment);

        // Advance time by 2 seconds (past MIN_COMMITMENT_AGE of 1 second)
        vm.warp(block.timestamp + 2);

        vm.prank(user);
        registry.register{value: value}(name, pubKey, relayUrl, SECRET);
    }

    /// @dev Get the price for a name given an account's current name count
    function _getPrice(string memory name, uint256 existingCount) internal view returns (uint256) {
        return oracle.getPrice(name, existingCount);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  COMMIT-REVEAL TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_commit_reveal_register() public {
        string memory name = "alice";
        string memory pubKey = "base64pubkey==";
        string memory relayUrl = "https://relay.example.com";

        uint256 price = _getPrice(name, 0);
        _registerName(alice, name, pubKey, relayUrl, price);

        // Verify resolve returns correct data
        (address owner, string memory rPubKey, string memory rRelayUrl, uint256 expiry) =
            registry.resolve(name);

        assertEq(owner, alice);
        assertEq(rPubKey, pubKey);
        assertEq(rRelayUrl, relayUrl);
        assertGt(expiry, block.timestamp);
        // Expiry = registration timestamp + LEASE_DURATION
        // Registration happened at block.timestamp (which is 3 after setUp at 1 + warp 2)
        assertEq(expiry, block.timestamp + registry.LEASE_DURATION());
    }

    function test_register_revert_no_commitment() public {
        vm.prank(alice);
        vm.expectRevert(UAMNameRegistry.CommitmentNotFound.selector);
        registry.register{value: 1 ether}("alice", "pk", "url", SECRET);
    }

    function test_register_revert_commitment_too_new() public {
        string memory name = "alice";
        bytes32 commitment = registry.makeCommitment(name, alice, SECRET);

        vm.prank(alice);
        registry.commit(commitment);

        // Do NOT advance time -- same block
        vm.prank(alice);
        vm.expectRevert(UAMNameRegistry.CommitmentTooNew.selector);
        registry.register{value: 1 ether}(name, "pk", "url", SECRET);
    }

    function test_register_revert_commitment_expired() public {
        string memory name = "alice";
        bytes32 commitment = registry.makeCommitment(name, alice, SECRET);

        vm.prank(alice);
        registry.commit(commitment);

        // Advance past MAX_COMMITMENT_AGE (24 hours)
        vm.warp(block.timestamp + 24 hours + 1);

        vm.prank(alice);
        vm.expectRevert(UAMNameRegistry.CommitmentExpired.selector);
        registry.register{value: 1 ether}(name, "pk", "url", SECRET);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  PRICING TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_pricing_by_length() public view {
        // At $2000/ETH, prices in wei:
        // 1-2 char: $1000/yr = 0.5 ETH = 500000000000000000 wei
        // 3 char: $300/yr = 0.15 ETH
        // 4 char: $100/yr = 0.05 ETH
        // 5+ char: $5/yr = 0.0025 ETH

        uint256 price1 = _getPrice("a", 0);      // 1 char
        uint256 price2 = _getPrice("ab", 0);      // 2 chars
        uint256 price3 = _getPrice("abc", 0);     // 3 chars
        uint256 price4 = _getPrice("abcd", 0);    // 4 chars
        uint256 price5 = _getPrice("abcde", 0);   // 5 chars
        uint256 price10 = _getPrice("abcdefghij", 0); // 10 chars

        // 1-2 char: $1000 at $2000/ETH = 0.5 ETH
        assertEq(price1, 0.5 ether);
        assertEq(price2, 0.5 ether);

        // 3 char: $300 at $2000/ETH = 0.15 ETH
        assertEq(price3, 0.15 ether);

        // 4 char: $100 at $2000/ETH = 0.05 ETH
        assertEq(price4, 0.05 ether);

        // 5+ char: $5 at $2000/ETH = 0.0025 ETH
        assertEq(price5, 0.0025 ether);
        assertEq(price10, 0.0025 ether);
    }

    function test_quadratic_pricing() public view {
        string memory name = "agent";

        uint256 price1st = _getPrice(name, 0); // first name: 1x
        uint256 price2nd = _getPrice(name, 1); // second name: 2x
        uint256 price3rd = _getPrice(name, 2); // third name: 3x

        assertEq(price2nd, price1st * 2);
        assertEq(price3rd, price1st * 3);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  NAME VALIDATION TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_name_validation() public {
        // Valid names should succeed
        uint256 price = _getPrice("a", 0);
        _registerName(alice, "a", "pk", "url", price);

        // Verify it was registered
        (address owner,,,) = registry.resolve("a");
        assertEq(owner, alice);
    }

    function test_name_validation_revert_uppercase() public {
        bytes32 commitment = registry.makeCommitment("Alice", alice, SECRET);
        vm.prank(alice);
        registry.commit(commitment);
        vm.warp(block.timestamp + 2);

        vm.prank(alice);
        vm.expectRevert(UAMNameRegistry.InvalidName.selector);
        registry.register{value: 1 ether}("Alice", "pk", "url", SECRET);
    }

    function test_name_validation_revert_special_chars() public {
        bytes32 commitment = registry.makeCommitment("al!ce", alice, SECRET);
        vm.prank(alice);
        registry.commit(commitment);
        vm.warp(block.timestamp + 2);

        vm.prank(alice);
        vm.expectRevert(UAMNameRegistry.InvalidName.selector);
        registry.register{value: 1 ether}("al!ce", "pk", "url", SECRET);
    }

    function test_name_validation_revert_empty() public {
        bytes32 commitment = registry.makeCommitment("", alice, SECRET);
        vm.prank(alice);
        registry.commit(commitment);
        vm.warp(block.timestamp + 2);

        vm.prank(alice);
        vm.expectRevert(UAMNameRegistry.InvalidName.selector);
        registry.register{value: 1 ether}("", "pk", "url", SECRET);
    }

    function test_name_validation_revert_too_long() public {
        // 65 characters -- 1 over the 64-char limit
        string memory longName = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01234";
        bytes32 commitment = registry.makeCommitment(longName, alice, SECRET);
        vm.prank(alice);
        registry.commit(commitment);
        vm.warp(block.timestamp + 2);

        vm.prank(alice);
        vm.expectRevert(UAMNameRegistry.InvalidName.selector);
        registry.register{value: 1 ether}(longName, "pk", "url", SECRET);
    }

    function test_name_validation_revert_starts_with_hyphen() public {
        bytes32 commitment = registry.makeCommitment("-alice", alice, SECRET);
        vm.prank(alice);
        registry.commit(commitment);
        vm.warp(block.timestamp + 2);

        vm.prank(alice);
        vm.expectRevert(UAMNameRegistry.InvalidName.selector);
        registry.register{value: 1 ether}("-alice", "pk", "url", SECRET);
    }

    function test_name_validation_revert_ends_with_hyphen() public {
        bytes32 commitment = registry.makeCommitment("alice-", alice, SECRET);
        vm.prank(alice);
        registry.commit(commitment);
        vm.warp(block.timestamp + 2);

        vm.prank(alice);
        vm.expectRevert(UAMNameRegistry.InvalidName.selector);
        registry.register{value: 1 ether}("alice-", "pk", "url", SECRET);
    }

    function test_name_validation_hyphen_underscore_middle() public {
        // Valid: hyphens and underscores in the middle
        uint256 price = _getPrice("my-agent", 0);
        _registerName(bob, "my-agent", "pk", "url", price);
        (address owner,,,) = registry.resolve("my-agent");
        assertEq(owner, bob);

        uint256 price2 = _getPrice("my_agent", 0);
        _registerName(carol, "my_agent", "pk", "url", price2);
        (address owner2,,,) = registry.resolve("my_agent");
        assertEq(owner2, carol);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  EXPIRY AND RENEWAL TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_resolve_expired_name() public {
        uint256 price = _getPrice("agent", 0);
        _registerName(alice, "agent", "pk", "url", price);

        // Warp past expiry + grace period
        vm.warp(block.timestamp + 365 days + 30 days + 1);

        vm.expectRevert(UAMNameRegistry.NameNotFound.selector);
        registry.resolve("agent");
    }

    function test_resolve_within_grace_period() public {
        uint256 price = _getPrice("agent", 0);
        _registerName(alice, "agent", "pk", "url", price);

        // Get the current expiry
        (,,, uint256 expiry) = registry.resolve("agent");

        // Warp to within grace period (past expiry but within grace)
        vm.warp(expiry + 15 days);

        // Should still resolve during grace period
        (address owner,,,) = registry.resolve("agent");
        assertEq(owner, alice);
    }

    function test_renew() public {
        uint256 price = _getPrice("agent", 0);
        _registerName(alice, "agent", "pk", "url", price);

        (,,, uint256 expiryBefore) = registry.resolve("agent");

        // Renew -- price is based on current nameCount
        uint256 renewPrice = _getPrice("agent", 1); // alice now has 1 name

        vm.prank(alice);
        registry.renew{value: renewPrice}("agent");

        (,,, uint256 expiryAfter) = registry.resolve("agent");

        // Expiry extended from old expiry (not from now)
        assertEq(expiryAfter, expiryBefore + registry.LEASE_DURATION());
    }

    // ═══════════════════════════════════════════════════════════════════
    //  UPDATE AND TRANSFER TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_update_record() public {
        uint256 price = _getPrice("agent", 0);
        _registerName(alice, "agent", "pk1", "url1", price);

        vm.prank(alice);
        registry.updateRecord("agent", "pk2", "url2");

        (, string memory pubKey, string memory relayUrl,) = registry.resolve("agent");
        assertEq(pubKey, "pk2");
        assertEq(relayUrl, "url2");
    }

    function test_update_record_revert_not_owner() public {
        uint256 price = _getPrice("agent", 0);
        _registerName(alice, "agent", "pk", "url", price);

        vm.prank(bob);
        vm.expectRevert(UAMNameRegistry.Unauthorized.selector);
        registry.updateRecord("agent", "pk2", "url2");
    }

    function test_transfer() public {
        uint256 price = _getPrice("agent", 0);
        _registerName(alice, "agent", "pk", "url", price);

        assertEq(registry.nameCount(alice), 1);
        assertEq(registry.nameCount(bob), 0);

        // Transfer requires minimum $10 fee
        uint256 transferFee = oracle.getTransferFee();

        vm.prank(alice);
        registry.transfer{value: transferFee}("agent", bob);

        (address owner,,,) = registry.resolve("agent");
        assertEq(owner, bob);
        assertEq(registry.nameCount(alice), 0);
        assertEq(registry.nameCount(bob), 1);
    }

    function test_transfer_revert_insufficient_fee() public {
        uint256 price = _getPrice("agent", 0);
        _registerName(alice, "agent", "pk", "url", price);

        uint256 transferFee = oracle.getTransferFee();

        vm.prank(alice);
        vm.expectRevert(UAMNameRegistry.InsufficientPayment.selector);
        registry.transfer{value: transferFee - 1}("agent", bob);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  AVAILABILITY TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_available() public {
        // Before registration
        assertTrue(registry.available("agent"));

        // After registration
        uint256 price = _getPrice("agent", 0);
        _registerName(alice, "agent", "pk", "url", price);
        assertFalse(registry.available("agent"));

        // After expiry + grace period
        vm.warp(block.timestamp + 365 days + 30 days + 1);
        assertTrue(registry.available("agent"));
    }

    // ═══════════════════════════════════════════════════════════════════
    //  FRONT-RUNNING PROTECTION TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_frontrun_protection() public {
        // Alice commits
        bytes32 commitment = registry.makeCommitment("agent", alice, SECRET);
        vm.prank(alice);
        registry.commit(commitment);

        vm.warp(block.timestamp + 2);

        // Bob tries to use Alice's commitment (register as bob, but commitment is for alice)
        // The commitment hash is keccak256(name, alice, secret), not keccak256(name, bob, secret)
        // So bob's register() computes keccak256("agent", bob, SECRET) which won't match alice's commitment
        vm.prank(bob);
        vm.expectRevert(UAMNameRegistry.CommitmentNotFound.selector);
        registry.register{value: 1 ether}("agent", "pk", "url", SECRET);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  REFUND TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_refund_excess() public {
        uint256 price = _getPrice("agent", 0);
        uint256 overpay = price + 1 ether;
        uint256 balanceBefore = alice.balance;

        _registerName(alice, "agent", "pk", "url", overpay);

        // Alice should have been refunded the excess
        uint256 balanceAfter = alice.balance;
        assertEq(balanceBefore - balanceAfter, price);
    }

    function test_register_revert_insufficient_payment() public {
        uint256 price = _getPrice("agent", 0);

        bytes32 commitment = registry.makeCommitment("agent", alice, SECRET);
        vm.prank(alice);
        registry.commit(commitment);
        vm.warp(block.timestamp + 2);

        vm.prank(alice);
        vm.expectRevert(UAMNameRegistry.InsufficientPayment.selector);
        registry.register{value: price - 1}("agent", "pk", "url", SECRET);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  PREMIUM NAME TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_premium_name() public {
        string memory name = "premium";
        uint256 premiumPrice = 2 ether;

        // Contract owner sets premium price
        registry.setPremium(name, premiumPrice);

        // Verify isPremium
        (bool isPrem, uint256 pPrice) = registry.isPremium(name);
        assertTrue(isPrem);
        assertEq(pPrice, premiumPrice);

        // Register at premium price (bypasses tier pricing)
        _registerName(alice, name, "pk", "url", premiumPrice);

        (address owner,,,) = registry.resolve(name);
        assertEq(owner, alice);
    }

    function test_premium_name_insufficient_payment() public {
        string memory name = "premium";
        uint256 premiumPrice = 2 ether;
        registry.setPremium(name, premiumPrice);

        bytes32 commitment = registry.makeCommitment(name, alice, SECRET);
        vm.prank(alice);
        registry.commit(commitment);
        vm.warp(block.timestamp + 2);

        // Try to pay less than premium price
        vm.prank(alice);
        vm.expectRevert(UAMNameRegistry.InsufficientPayment.selector);
        registry.register{value: premiumPrice - 1}(name, "pk", "url", SECRET);
    }

    function test_premium_batch() public {
        string[] memory names = new string[](3);
        names[0] = "gold";
        names[1] = "silver";
        names[2] = "bronze";

        uint256[] memory prices = new uint256[](3);
        prices[0] = 5 ether;
        prices[1] = 3 ether;
        prices[2] = 1 ether;

        registry.setPremiumBatch(names, prices);

        (bool isPrem1, uint256 p1) = registry.isPremium("gold");
        assertTrue(isPrem1);
        assertEq(p1, 5 ether);

        (bool isPrem2, uint256 p2) = registry.isPremium("silver");
        assertTrue(isPrem2);
        assertEq(p2, 3 ether);

        (bool isPrem3, uint256 p3) = registry.isPremium("bronze");
        assertTrue(isPrem3);
        assertEq(p3, 1 ether);
    }

    function test_premium_remove() public {
        string memory name = "premium";
        uint256 premiumPrice = 2 ether;

        // Set premium
        registry.setPremium(name, premiumPrice);
        (bool isPrem,) = registry.isPremium(name);
        assertTrue(isPrem);

        // Remove premium (set price to 0)
        registry.setPremium(name, 0);
        (bool isPrem2, uint256 p2) = registry.isPremium(name);
        assertFalse(isPrem2);
        assertEq(p2, 0);

        // Registration should now use tier pricing (7 chars = 5+ tier = $5/yr)
        uint256 tierPrice = _getPrice(name, 0);
        _registerName(alice, name, "pk", "url", tierPrice);

        (address owner,,,) = registry.resolve(name);
        assertEq(owner, alice);
    }

    function test_premium_set_only_owner() public {
        vm.prank(alice);
        vm.expectRevert(UAMNameRegistry.Unauthorized.selector);
        registry.setPremium("test", 1 ether);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  TRANSFER WITH PAYMENT / ROYALTY TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_transfer_with_payment_royalty() public {
        string memory name = "vip";
        uint256 premiumPrice = 1 ether;

        // Set as premium
        registry.setPremium(name, premiumPrice);

        // Alice registers the premium name
        _registerName(alice, name, "pk", "url", premiumPrice);

        // Alice transfers to bob with payment -- bob pays 10 ETH
        uint256 paymentAmount = 10 ether;
        uint256 aliceBalBefore = alice.balance;
        uint256 ownerBalBefore = deployer.balance;

        vm.prank(alice);
        registry.transferWithPayment{value: paymentAmount}(name, bob);

        // Royalty = 5% of 10 ETH = 0.5 ETH
        uint256 expectedRoyalty = (paymentAmount * 500) / 10000;
        uint256 expectedSellerProceeds = paymentAmount - expectedRoyalty;

        // Check contract owner received royalty
        assertEq(deployer.balance - ownerBalBefore, expectedRoyalty);

        // Check alice received seller proceeds
        // Alice also paid paymentAmount, so net = sellerProceeds - paymentAmount
        // But wait: alice is the seller AND the msg.sender paying...
        // The contract sends sellerProceeds to seller (alice) and debits msg.value from alice
        assertEq(alice.balance, aliceBalBefore - paymentAmount + expectedSellerProceeds);

        // Verify ownership changed
        (address owner,,,) = registry.resolve(name);
        assertEq(owner, bob);
    }

    function test_transfer_with_payment_non_premium() public {
        string memory name = "regular";
        uint256 price = _getPrice(name, 0);

        // Alice registers a non-premium name
        _registerName(alice, name, "pk", "url", price);

        uint256 aliceBalBefore = alice.balance;
        uint256 paymentAmount = 5 ether;

        // Alice transfers to bob with payment (must meet minimum transfer fee)
        vm.prank(alice);
        registry.transferWithPayment{value: paymentAmount}(name, bob);

        // Non-premium: all proceeds go to seller, no royalty
        // Alice is both sender and seller, so she gets paymentAmount back minus the value she sent
        assertEq(alice.balance, aliceBalBefore); // net zero: paid 5, received 5

        (address owner,,,) = registry.resolve(name);
        assertEq(owner, bob);
    }

    function test_transfer_with_payment_revert_below_minimum() public {
        string memory name = "cheap";
        uint256 price = _getPrice(name, 0);
        _registerName(alice, name, "pk", "url", price);

        uint256 transferFee = oracle.getTransferFee();

        // Try to transfer with less than minimum fee
        vm.prank(alice);
        vm.expectRevert(UAMNameRegistry.InsufficientPayment.selector);
        registry.transferWithPayment{value: transferFee - 1}(name, bob);
    }

    function test_set_royalty_bps() public {
        // Default is 500 (5%)
        assertEq(registry.royaltyBps(), 500);

        // Owner sets to 1000 (10%)
        registry.setRoyaltyBps(1000);
        assertEq(registry.royaltyBps(), 1000);

        // Non-owner reverts
        vm.prank(alice);
        vm.expectRevert(UAMNameRegistry.Unauthorized.selector);
        registry.setRoyaltyBps(200);
    }

    function test_royalty_cap() public {
        // Setting to 2500 (25%) should succeed
        registry.setRoyaltyBps(2500);
        assertEq(registry.royaltyBps(), 2500);

        // Setting above 2500 should revert
        vm.expectRevert(UAMNameRegistry.InvalidRoyalty.selector);
        registry.setRoyaltyBps(2501);
    }

    function test_royalty_updated_rate() public {
        string memory name = "vip2";
        uint256 premiumPrice = 1 ether;
        registry.setPremium(name, premiumPrice);

        _registerName(alice, name, "pk", "url", premiumPrice);

        // Change royalty to 10%
        registry.setRoyaltyBps(1000);

        uint256 paymentAmount = 10 ether;
        uint256 ownerBalBefore = deployer.balance;

        vm.prank(alice);
        registry.transferWithPayment{value: paymentAmount}(name, bob);

        // 10% of 10 ETH = 1 ETH royalty
        uint256 expectedRoyalty = (paymentAmount * 1000) / 10000;
        assertEq(deployer.balance - ownerBalBefore, expectedRoyalty);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  WITHDRAW TEST
    // ═══════════════════════════════════════════════════════════════════

    function test_withdraw() public {
        // Register a name to accumulate fees
        uint256 price = _getPrice("agent", 0);
        _registerName(alice, "agent", "pk", "url", price);

        uint256 contractBal = address(registry).balance;
        assertGt(contractBal, 0);

        uint256 ownerBalBefore = deployer.balance;
        registry.withdraw();

        assertEq(address(registry).balance, 0);
        assertEq(deployer.balance, ownerBalBefore + contractBal);
    }

    function test_withdraw_only_owner() public {
        vm.prank(alice);
        vm.expectRevert(UAMNameRegistry.Unauthorized.selector);
        registry.withdraw();
    }

    // ═══════════════════════════════════════════════════════════════════
    //  DUTCH AUCTION TEST
    // ═══════════════════════════════════════════════════════════════════

    function test_dutch_auction_pricing() public {
        uint256 ceiling = 10 ether;
        uint256 floor = 1 ether;
        uint256 duration = 1 hours;
        uint256 startTime = block.timestamp;

        // At start: price = ceiling
        uint256 priceStart = oracle.getAuctionPrice("test", startTime, ceiling, floor, duration);
        assertEq(priceStart, ceiling);

        // At midpoint: price = midpoint
        vm.warp(startTime + 30 minutes);
        uint256 priceMid = oracle.getAuctionPrice("test", startTime, ceiling, floor, duration);
        assertEq(priceMid, (ceiling + floor) / 2);

        // At end: price = floor
        vm.warp(startTime + duration);
        uint256 priceEnd = oracle.getAuctionPrice("test", startTime, ceiling, floor, duration);
        assertEq(priceEnd, floor);

        // Past end: still floor
        vm.warp(startTime + duration + 1 hours);
        uint256 pricePast = oracle.getAuctionPrice("test", startTime, ceiling, floor, duration);
        assertEq(pricePast, floor);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  EDGE CASE TESTS
    // ═══════════════════════════════════════════════════════════════════

    function test_register_expired_name_by_new_owner() public {
        // Alice registers, then name expires
        uint256 price = _getPrice("agent", 0);
        _registerName(alice, "agent", "pk", "url", price);

        // Warp past expiry + grace
        vm.warp(block.timestamp + 365 days + 30 days + 1);

        // Bob can now register the expired name
        uint256 price2 = _getPrice("agent", 0);
        _registerName(bob, "agent", "pk2", "url2", price2);

        (address owner,,,) = registry.resolve("agent");
        assertEq(owner, bob);

        // Alice's nameCount should have been decremented
        assertEq(registry.nameCount(alice), 0);
        assertEq(registry.nameCount(bob), 1);
    }

    function test_name_not_available_during_grace_period() public {
        uint256 price = _getPrice("agent", 0);
        _registerName(alice, "agent", "pk", "url", price);

        (,,, uint256 expiry) = registry.resolve("agent");

        // Warp into grace period (past expiry but within grace)
        vm.warp(expiry + 15 days);

        // Name should NOT be available during grace period
        assertFalse(registry.available("agent"));

        // Another user should not be able to register it
        bytes32 commitment = registry.makeCommitment("agent", bob, SECRET);
        vm.prank(bob);
        registry.commit(commitment);
        vm.warp(block.timestamp + 2);

        vm.prank(bob);
        vm.expectRevert(UAMNameRegistry.NameNotAvailable.selector);
        registry.register{value: 1 ether}("agent", "pk2", "url2", SECRET);
    }

    function test_transfer_with_payment_zero_value_reverts() public {
        string memory name = "free";
        uint256 price = _getPrice(name, 0);
        _registerName(alice, name, "pk", "url", price);

        // Transfer with 0 payment should now revert (minimum $10 fee required)
        vm.prank(alice);
        vm.expectRevert(UAMNameRegistry.InsufficientPayment.selector);
        registry.transferWithPayment{value: 0}(name, bob);
    }

    // Receive ETH for royalty payments in tests
    receive() external payable {}
}

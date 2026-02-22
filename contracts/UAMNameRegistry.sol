// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPriceOracle} from "./IPriceOracle.sol";

/// @title UAMNameRegistry
/// @notice On-chain namespace registry for UAM Tier 3 addressing.
///         Supports commit-reveal registration, tiered lease pricing,
///         premium names, transfer royalties, and full CRUD operations.
contract UAMNameRegistry {
    // ─── Errors ────────────────────────────────────────────────────
    error NameNotFound();
    error NameNotAvailable();
    error CommitmentNotFound();
    error CommitmentTooNew();
    error CommitmentExpired();
    error Unauthorized();
    error InsufficientPayment();
    error InvalidName();
    error ExpiredName();
    error InvalidRoyalty();

    // ─── Errors (Auction) ─────────────────────────────────────────
    error AuctionNotActive();

    // ─── Events ────────────────────────────────────────────────────
    event NameCommitted(bytes32 indexed commitment, address indexed committer);
    event NameRegistered(string name, address indexed owner, uint256 expiry);
    event NameRenewed(string name, uint256 newExpiry);
    event NameUpdated(string name);
    event NameTransferred(string name, address indexed from, address indexed to);
    event PremiumSet(string name, uint256 priceWei);
    event RoyaltyPaid(string name, uint256 royaltyAmount);
    event AuctionConfigured(uint256 ceiling, uint256 floor, uint256 duration, uint256 startTime);
    event AuctionEnded(uint256 timestamp);

    // ─── Types ─────────────────────────────────────────────────────
    struct NameRecord {
        address owner;
        string publicKey;     // Base64 Ed25519 public key
        string relayUrl;      // Agent's relay URL
        uint256 expiry;       // Lease expiration timestamp
        uint256 registeredAt; // Original registration timestamp
    }

    struct Commitment {
        address committer;
        uint256 timestamp;    // Block timestamp of commit
    }

    // ─── Constants ─────────────────────────────────────────────────
    uint256 public constant LEASE_DURATION = 365 days;
    uint256 public constant GRACE_PERIOD = 30 days;
    uint256 public constant MIN_COMMITMENT_AGE = 1;        // 1 second minimum
    uint256 public constant MAX_COMMITMENT_AGE = 24 hours;  // Commitment expiry

    // ─── State ─────────────────────────────────────────────────────
    address public owner;
    IPriceOracle public immutable priceOracle;

    mapping(bytes32 => NameRecord) public records;          // keccak256(name) => record
    mapping(bytes32 => Commitment) public commitments;      // commitment hash => who/when
    mapping(address => uint256) public nameCount;            // owner => count of names owned
    mapping(bytes32 => uint256) public premiumPrices;        // keccak256(name) => price in wei (0 = not premium)

    uint256 public royaltyBps = 500; // 5% default royalty on premium name transfers

    // ─── Dutch Auction State ─────────────────────────────────────
    bool public auctionActive;
    uint256 public auctionStart;
    uint256 public auctionCeilingPrice;
    uint256 public auctionFloorPrice;
    uint256 public auctionDuration;

    // ─── Modifiers ─────────────────────────────────────────────────
    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    // ─── Constructor ───────────────────────────────────────────────
    constructor(address _priceOracle) {
        owner = msg.sender;
        priceOracle = IPriceOracle(_priceOracle);
    }

    // ─── Ownership ─────────────────────────────────────────────────
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid owner");
        owner = newOwner;
    }

    // ─── Commit-Reveal ─────────────────────────────────────────────

    /// @notice Compute commitment hash for front-running protection
    function makeCommitment(string calldata name, address _owner, bytes32 secret)
        external
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(name, _owner, secret));
    }

    /// @notice Submit a commitment (step 1 of commit-reveal)
    function commit(bytes32 commitment) external {
        commitments[commitment] = Commitment({committer: msg.sender, timestamp: block.timestamp});
        emit NameCommitted(commitment, msg.sender);
    }

    // ─── Registration ──────────────────────────────────────────────

    /// @notice Register a name (step 2 of commit-reveal)
    function register(
        string calldata name,
        string calldata publicKey,
        string calldata relayUrl,
        bytes32 secret
    ) external payable {
        // Validate name format
        _validateName(name);

        // Verify commitment
        bytes32 commitmentHash = keccak256(abi.encodePacked(name, msg.sender, secret));
        Commitment storage c = commitments[commitmentHash];

        if (c.committer == address(0)) revert CommitmentNotFound();
        if (c.committer != msg.sender) revert CommitmentNotFound(); // Different address cannot use
        if (block.timestamp < c.timestamp + MIN_COMMITMENT_AGE) revert CommitmentTooNew();
        if (block.timestamp > c.timestamp + MAX_COMMITMENT_AGE) revert CommitmentExpired();

        // Check availability
        bytes32 nameHash = keccak256(abi.encodePacked(name));
        NameRecord storage existing = records[nameHash];
        if (existing.owner != address(0) && existing.expiry + GRACE_PERIOD > block.timestamp) {
            revert NameNotAvailable();
        }

        // If reclaiming an expired name, decrement old owner's count
        if (existing.owner != address(0) && existing.expiry + GRACE_PERIOD <= block.timestamp) {
            nameCount[existing.owner]--;
        }

        // Calculate price -- premium names bypass tier pricing; auction pricing when active
        uint256 price;
        uint256 premiumPrice = premiumPrices[nameHash];
        if (premiumPrice > 0) {
            price = premiumPrice;
        } else if (auctionActive) {
            price = priceOracle.getAuctionPrice(name, auctionStart, auctionCeilingPrice, auctionFloorPrice, auctionDuration);
        } else {
            price = priceOracle.getPrice(name, nameCount[msg.sender]);
        }

        if (msg.value < price) revert InsufficientPayment();

        // Store record
        records[nameHash] = NameRecord({
            owner: msg.sender,
            publicKey: publicKey,
            relayUrl: relayUrl,
            expiry: block.timestamp + LEASE_DURATION,
            registeredAt: block.timestamp
        });

        nameCount[msg.sender]++;

        // Delete used commitment
        delete commitments[commitmentHash];

        // Refund excess
        if (msg.value > price) {
            (bool ok,) = msg.sender.call{value: msg.value - price}("");
            require(ok, "Refund failed");
        }

        emit NameRegistered(name, msg.sender, block.timestamp + LEASE_DURATION);
    }

    // ─── Resolution ────────────────────────────────────────────────

    /// @notice Resolve a name to its record
    function resolve(string calldata name)
        external
        view
        returns (address _owner, string memory publicKey, string memory relayUrl, uint256 expiry)
    {
        bytes32 nameHash = keccak256(abi.encodePacked(name));
        NameRecord storage r = records[nameHash];

        // Name must exist and not be expired past grace period
        if (r.owner == address(0)) revert NameNotFound();
        if (block.timestamp > r.expiry + GRACE_PERIOD) revert NameNotFound();

        return (r.owner, r.publicKey, r.relayUrl, r.expiry);
    }

    // ─── Renewal ───────────────────────────────────────────────────

    /// @notice Renew a name lease
    function renew(string calldata name) external payable {
        bytes32 nameHash = keccak256(abi.encodePacked(name));
        NameRecord storage r = records[nameHash];

        if (r.owner != msg.sender) revert Unauthorized();
        if (block.timestamp > r.expiry + GRACE_PERIOD) revert ExpiredName();

        // Calculate renewal cost
        uint256 price;
        uint256 premiumPrice = premiumPrices[nameHash];
        if (premiumPrice > 0) {
            price = premiumPrice;
        } else {
            price = priceOracle.getPrice(name, nameCount[msg.sender]);
        }

        if (msg.value < price) revert InsufficientPayment();

        // Extend from current expiry (not from now)
        r.expiry = r.expiry + LEASE_DURATION;

        // Refund excess
        if (msg.value > price) {
            (bool ok,) = msg.sender.call{value: msg.value - price}("");
            require(ok, "Refund failed");
        }

        emit NameRenewed(name, r.expiry);
    }

    // ─── Updates ───────────────────────────────────────────────────

    /// @notice Update record fields (owner only)
    function updateRecord(string calldata name, string calldata publicKey, string calldata relayUrl)
        external
    {
        bytes32 nameHash = keccak256(abi.encodePacked(name));
        NameRecord storage r = records[nameHash];

        if (r.owner != msg.sender) revert Unauthorized();
        if (block.timestamp > r.expiry) revert ExpiredName();

        r.publicKey = publicKey;
        r.relayUrl = relayUrl;

        emit NameUpdated(name);
    }

    // ─── Transfers ─────────────────────────────────────────────────

    /// @notice Transfer name ownership (requires minimum $10 transfer fee)
    function transfer(string calldata name, address newOwner) external payable {
        bytes32 nameHash = keccak256(abi.encodePacked(name));
        NameRecord storage r = records[nameHash];

        if (r.owner != msg.sender) revert Unauthorized();
        if (block.timestamp > r.expiry) revert ExpiredName();

        // Enforce minimum transfer fee
        uint256 minFee = priceOracle.getTransferFee();
        if (msg.value < minFee) revert InsufficientPayment();

        nameCount[msg.sender]--;
        nameCount[newOwner]++;
        r.owner = newOwner;

        // Transfer fee goes to contract owner
        (bool ok,) = owner.call{value: msg.value}("");
        require(ok, "Fee transfer failed");

        emit NameTransferred(name, msg.sender, newOwner);
    }

    /// @notice Transfer with payment -- charges royalty on premium names, enforces minimum $10 fee
    /// @dev Buyer (msg.sender) pays. Royalty goes to contract owner, remainder to seller.
    function transferWithPayment(string calldata name, address newOwner) external payable {
        bytes32 nameHash = keccak256(abi.encodePacked(name));
        NameRecord storage r = records[nameHash];

        if (r.owner != msg.sender) revert Unauthorized();
        if (block.timestamp > r.expiry) revert ExpiredName();

        // Enforce minimum transfer fee
        uint256 minFee = priceOracle.getTransferFee();
        if (msg.value < minFee) revert InsufficientPayment();

        address seller = r.owner;

        // Update ownership
        nameCount[msg.sender]--;
        nameCount[newOwner]++;
        r.owner = newOwner;

        // Handle royalty for premium names
        if (premiumPrices[nameHash] > 0 && msg.value > 0) {
            uint256 royalty = (msg.value * royaltyBps) / 10000;
            uint256 sellerProceeds = msg.value - royalty;

            // Pay contract owner the royalty
            if (royalty > 0) {
                (bool ok1,) = owner.call{value: royalty}("");
                require(ok1, "Royalty transfer failed");
            }

            // Pay seller the remainder
            if (sellerProceeds > 0) {
                (bool ok2,) = seller.call{value: sellerProceeds}("");
                require(ok2, "Seller payment failed");
            }

            emit RoyaltyPaid(name, royalty);
        } else if (msg.value > 0) {
            // Non-premium: all proceeds to seller
            (bool ok,) = seller.call{value: msg.value}("");
            require(ok, "Seller payment failed");
        }

        emit NameTransferred(name, msg.sender, newOwner);
    }

    // ─── Availability ──────────────────────────────────────────────

    /// @notice Check if a name is available for registration
    function available(string calldata name) external view returns (bool) {
        bytes32 nameHash = keccak256(abi.encodePacked(name));
        NameRecord storage r = records[nameHash];
        return r.owner == address(0) || block.timestamp > r.expiry + GRACE_PERIOD;
    }

    // ─── Premium Controls ──────────────────────────────────────────

    /// @notice Set a name as premium with a fixed price
    function setPremium(string calldata name, uint256 priceWei) external onlyOwner {
        bytes32 nameHash = keccak256(abi.encodePacked(name));
        premiumPrices[nameHash] = priceWei;
        emit PremiumSet(name, priceWei);
    }

    /// @notice Batch set premium names
    function setPremiumBatch(string[] calldata names, uint256[] calldata prices) external onlyOwner {
        require(names.length == prices.length, "Length mismatch");
        for (uint256 i = 0; i < names.length; i++) {
            bytes32 nameHash = keccak256(abi.encodePacked(names[i]));
            premiumPrices[nameHash] = prices[i];
            emit PremiumSet(names[i], prices[i]);
        }
    }

    /// @notice Check if a name is premium and its price
    function isPremium(string calldata name) external view returns (bool, uint256) {
        bytes32 nameHash = keccak256(abi.encodePacked(name));
        uint256 price = premiumPrices[nameHash];
        return (price > 0, price);
    }

    // ─── Royalty Controls ──────────────────────────────────────────

    /// @notice Set royalty basis points for premium name transfers
    function setRoyaltyBps(uint256 bps) external onlyOwner {
        if (bps > 2500) revert InvalidRoyalty();
        royaltyBps = bps;
    }

    // ─── Dutch Auction Controls ─────────────────────────────────────

    /// @notice Configure and start a Dutch auction for name registrations
    /// @param ceiling Starting (maximum) price in wei
    /// @param floor Ending (minimum) price in wei
    /// @param duration Auction duration in seconds
    function configureAuction(uint256 ceiling, uint256 floor, uint256 duration) external onlyOwner {
        require(ceiling >= floor, "Ceiling < floor");
        require(duration > 0, "Duration zero");

        auctionCeilingPrice = ceiling;
        auctionFloorPrice = floor;
        auctionDuration = duration;
        auctionStart = block.timestamp;
        auctionActive = true;

        emit AuctionConfigured(ceiling, floor, duration, block.timestamp);
    }

    /// @notice End the Dutch auction, reverting to standard pricing
    function endAuction() external onlyOwner {
        auctionActive = false;
        emit AuctionEnded(block.timestamp);
    }

    /// @notice Get the current Dutch auction price for a name (for frontend display)
    /// @param name The namespace to price
    /// @return priceWei Current auction price in wei
    function getCurrentAuctionPrice(string calldata name) external view returns (uint256 priceWei) {
        if (!auctionActive) revert AuctionNotActive();
        return priceOracle.getAuctionPrice(name, auctionStart, auctionCeilingPrice, auctionFloorPrice, auctionDuration);
    }

    // ─── Admin ─────────────────────────────────────────────────────

    /// @notice Withdraw accumulated fees (contract owner only)
    function withdraw() external onlyOwner {
        (bool ok,) = owner.call{value: address(this).balance}("");
        require(ok, "Withdraw failed");
    }

    // ─── Internal ──────────────────────────────────────────────────

    /// @notice Validate name format: 1-64 chars, [a-z0-9][a-z0-9_-]*[a-z0-9] or single [a-z0-9]
    function _validateName(string calldata name) internal pure {
        bytes memory b = bytes(name);
        uint256 len = b.length;

        if (len == 0 || len > 64) revert InvalidName();

        // Single character: must be alphanumeric
        if (len == 1) {
            if (!_isAlphanumeric(b[0])) revert InvalidName();
            return;
        }

        // Multi-character: first and last must be alphanumeric
        if (!_isAlphanumeric(b[0])) revert InvalidName();
        if (!_isAlphanumeric(b[len - 1])) revert InvalidName();

        // Middle characters: alphanumeric, hyphen, or underscore
        for (uint256 i = 1; i < len - 1; i++) {
            bytes1 c = b[i];
            if (!_isAlphanumeric(c) && c != 0x2D && c != 0x5F) {
                // 0x2D = '-', 0x5F = '_'
                revert InvalidName();
            }
        }
    }

    /// @notice Check if a byte is lowercase alphanumeric [a-z0-9]
    function _isAlphanumeric(bytes1 c) internal pure returns (bool) {
        return (c >= 0x61 && c <= 0x7A) // a-z
            || (c >= 0x30 && c <= 0x39); // 0-9
    }

    // Allow contract to receive ETH (for royalty/payment flows)
    receive() external payable {}
}

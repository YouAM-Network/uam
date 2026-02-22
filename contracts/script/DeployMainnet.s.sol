// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// MAINNET DEPLOYMENT:
// 1. Ensure deployer wallet is funded with ETH on Base L2
// 2. Set env vars: PRIVATE_KEY, BASE_RPC_URL, BASESCAN_API_KEY
// 3. Run: make deploy-mainnet
// 4. Update deployments/mainnet.json with deployed addresses
// 5. Run: make reserve-names-commit (after deploy)
// 6. Wait 1 block for commit-reveal gap
// 7. Run: make reserve-names-reveal

import {Script, console} from "forge-std/Script.sol";
import {UAMPriceOracle} from "../UAMPriceOracle.sol";
import {UAMNameRegistry} from "../UAMNameRegistry.sol";

/// @title Deploy UAM Name Registry to Base L2 Mainnet
/// @notice Deploys UAMPriceOracle (with Chainlink ETH/USD feed) and UAMNameRegistry
/// @dev Reads PRIVATE_KEY from environment. Uses Base L2 Chainlink ETH/USD price feed.
contract DeployMainnet is Script {
    // Base L2 Mainnet Chainlink ETH/USD price feed
    // https://docs.chain.link/data-feeds/price-feeds/addresses?network=base
    address constant BASE_MAINNET_ETH_USD_FEED = 0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70;

    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerKey);

        // Deploy price oracle with Chainlink Base mainnet feed
        UAMPriceOracle oracle = new UAMPriceOracle(BASE_MAINNET_ETH_USD_FEED);
        console.log("Deployed UAMPriceOracle:", address(oracle));

        // Deploy name registry with the oracle
        UAMNameRegistry registry = new UAMNameRegistry(address(oracle));
        console.log("Deployed UAMNameRegistry:", address(registry));

        vm.stopBroadcast();

        // Log summary for deployment artifact update
        console.log("--- Deployment Summary ---");
        console.log("Network: Base L2 Mainnet (chain ID 8453)");
        console.log("Price Feed:", BASE_MAINNET_ETH_USD_FEED);
        console.log("Oracle:", address(oracle));
        console.log("Registry:", address(registry));
        console.log("");
        console.log("NEXT STEPS:");
        console.log("1. Update deployments/mainnet.json with addresses above");
        console.log("2. Run: make reserve-names-commit REGISTRY_ADDRESS=<address>");
        console.log("3. Wait 1 block");
        console.log("4. Run: make reserve-names-reveal REGISTRY_ADDRESS=<address>");
    }
}

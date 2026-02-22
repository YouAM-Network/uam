# UAM Name Registry - Contract Build & Deployment
# Requires: foundry (forge), jq

FORGE := $(shell which forge 2>/dev/null || echo "$(HOME)/.foundry/bin/forge")

# Build
build:
	$(FORGE) build

# Test (unit tests, excludes fork-based integration tests)
test:
	$(FORGE) test --no-match-path test/Integration.t.sol -vvv

# Test all (including fork-based integration tests -- requires BASE_SEPOLIA_RPC_URL)
test-all:
	$(FORGE) test -vvv

# Deploy to Base Sepolia
# Required env vars: PRIVATE_KEY, BASE_SEPOLIA_RPC_URL, BASESCAN_API_KEY
deploy-sepolia:
	$(FORGE) script script/DeploySepolia.s.sol:DeploySepolia \
		--rpc-url base_sepolia \
		--broadcast \
		--verify

# Deploy to local Anvil (for development)
deploy-local:
	$(FORGE) script script/Deploy.s.sol:DeployScript \
		--fork-url http://localhost:8545 \
		--broadcast

# Verify contract on BaseScan (if deploy didn't auto-verify)
verify-sepolia:
	$(FORGE) verify-contract $(CONTRACT_ADDRESS) UAMNameRegistry \
		--chain base-sepolia \
		--etherscan-api-key $(BASESCAN_API_KEY)

# Generate ABI JSON for SDK consumption
abi:
	$(FORGE) build
	mkdir -p deployments
	cat out/UAMNameRegistry.sol/UAMNameRegistry.json | jq '.abi' > deployments/UAMNameRegistry.abi.json
	@echo "ABI written to deployments/UAMNameRegistry.abi.json"

# Deploy to Base L2 Mainnet
# Required env vars: PRIVATE_KEY, BASE_RPC_URL, BASESCAN_API_KEY
deploy-mainnet:
	$(FORGE) script script/DeployMainnet.s.sol:DeployMainnet \
		--rpc-url base \
		--broadcast \
		--verify \
		--slow

# Reserve names -- Phase 1: Commit (run after deploy-mainnet)
# Required env vars: PRIVATE_KEY, REGISTRY_ADDRESS, BASE_RPC_URL
reserve-names-commit:
	REGISTRY_ADDRESS=$(REGISTRY_ADDRESS) $(FORGE) script script/ReserveNames.s.sol:ReserveNamesCommit \
		--rpc-url base \
		--broadcast

# Reserve names -- Phase 2: Reveal (run after waiting 1+ block from commit)
# Required env vars: PRIVATE_KEY, REGISTRY_ADDRESS, BASE_RPC_URL
reserve-names-reveal:
	REGISTRY_ADDRESS=$(REGISTRY_ADDRESS) $(FORGE) script script/ReserveNames.s.sol:ReserveNamesReveal \
		--rpc-url base \
		--broadcast

# Configure Dutch auction (run after deploy-mainnet)
# Required env vars: PRIVATE_KEY, REGISTRY_ADDRESS, BASE_RPC_URL
configure-auction:
	REGISTRY_ADDRESS=$(REGISTRY_ADDRESS) $(FORGE) script script/ConfigureAuction.s.sol:ConfigureAuction \
		--rpc-url base \
		--broadcast

# Clean build artifacts
clean:
	$(FORGE) clean

.PHONY: build test test-all deploy-sepolia deploy-local verify-sepolia abi clean deploy-mainnet reserve-names-commit reserve-names-reveal configure-auction

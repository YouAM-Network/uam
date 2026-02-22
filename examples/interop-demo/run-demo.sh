#!/usr/bin/env bash
# UAM Interop Demo: Python <-> TypeScript across Federated Relays
#
# This script orchestrates the full demo:
#   1. Builds the relay Docker image
#   2. Starts two federated relays (alpha.demo, beta.demo)
#   3. Runs a Python agent on relay-alpha
#   4. Runs a TypeScript agent on relay-beta
#   5. Both agents exchange encrypted messages across relays
#
# Usage:
#   ./run-demo.sh              # Full demo with Docker
#   ./run-demo.sh --no-docker  # Skip Docker, expect relays already running

set -e

# ---- Colors ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ---- Configuration ----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.demo.yml"

RELAY_ALPHA_URL="http://localhost:9001"
RELAY_BETA_URL="http://localhost:9002"
ALPHA_DOMAIN="alpha.demo"
BETA_DOMAIN="beta.demo"
PY_AGENT_NAME="py-demo"
TS_AGENT_NAME="ts-demo"

USE_DOCKER=true

# ---- Parse Arguments ----
for arg in "$@"; do
    case $arg in
        --no-docker)
            USE_DOCKER=false
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--no-docker] [--help]"
            echo ""
            echo "Options:"
            echo "  --no-docker   Skip Docker setup; expects relays already running"
            echo "  --help        Show this help message"
            exit 0
            ;;
    esac
done

# ---- Banner ----
echo -e "${BOLD}${CYAN}"
echo "============================================================"
echo "  UAM Interop Demo"
echo "  Python <-> TypeScript across Federated Relays"
echo "============================================================"
echo -e "${NC}"
echo -e "${BLUE}This demo proves UAM works across:${NC}"
echo "  - Different languages (Python + TypeScript)"
echo "  - Different relays (alpha.demo + beta.demo)"
echo "  - Different frameworks (PyNaCl + libsodium-wrappers)"
echo "  - With zero custom integration code"
echo ""

# ---- Check Prerequisites ----
echo -e "${YELLOW}[1/6] Checking prerequisites...${NC}"

check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "  ${RED}MISSING: $1${NC} -- $2"
        return 1
    fi
    echo -e "  ${GREEN}OK:${NC} $1 $(command -v "$1")"
    return 0
}

MISSING=false
check_command python3 "Required to run the Python agent" || MISSING=true
check_command node "Required to run the TypeScript agent" || MISSING=true

if [ "$USE_DOCKER" = true ]; then
    check_command docker "Required to run federated relays" || MISSING=true
    # Check for docker compose (v2 plugin) or docker-compose (v1 standalone)
    if docker compose version &> /dev/null 2>&1; then
        DOCKER_COMPOSE="docker compose"
        echo -e "  ${GREEN}OK:${NC} docker compose (v2 plugin)"
    elif command -v docker-compose &> /dev/null; then
        DOCKER_COMPOSE="docker-compose"
        echo -e "  ${GREEN}OK:${NC} docker-compose (standalone)"
    else
        echo -e "  ${RED}MISSING: docker compose${NC} -- Required to start federated relays"
        MISSING=true
    fi
fi

if [ "$MISSING" = true ]; then
    echo -e "\n${RED}Missing prerequisites. Please install them and retry.${NC}"
    exit 1
fi
echo ""

# ---- Docker Setup ----
if [ "$USE_DOCKER" = true ]; then
    # Build the relay image
    echo -e "${YELLOW}[2/6] Building relay Docker image...${NC}"
    docker build -f "$PROJECT_ROOT/docker/Dockerfile" -t uam-relay "$PROJECT_ROOT" 2>&1 | tail -5
    echo -e "  ${GREEN}Image built: uam-relay${NC}"
    echo ""

    # Start the two federated relays
    echo -e "${YELLOW}[3/6] Starting federated relays...${NC}"
    $DOCKER_COMPOSE -f "$COMPOSE_FILE" up -d 2>&1
    echo -e "  ${GREEN}Relay Alpha:${NC} $RELAY_ALPHA_URL (domain: $ALPHA_DOMAIN)"
    echo -e "  ${GREEN}Relay Beta:${NC}  $RELAY_BETA_URL (domain: $BETA_DOMAIN)"
    echo ""

    # Wait for relays to be healthy
    echo -e "${YELLOW}[4/6] Waiting for relays to become healthy...${NC}"
    MAX_WAIT=60
    WAITED=0
    ALPHA_HEALTHY=false
    BETA_HEALTHY=false

    while [ $WAITED -lt $MAX_WAIT ]; do
        if [ "$ALPHA_HEALTHY" = false ]; then
            if curl -sf "$RELAY_ALPHA_URL/health" > /dev/null 2>&1; then
                ALPHA_HEALTHY=true
                echo -e "  ${GREEN}Relay Alpha: healthy${NC}"
            fi
        fi
        if [ "$BETA_HEALTHY" = false ]; then
            if curl -sf "$RELAY_BETA_URL/health" > /dev/null 2>&1; then
                BETA_HEALTHY=true
                echo -e "  ${GREEN}Relay Beta:  healthy${NC}"
            fi
        fi
        if [ "$ALPHA_HEALTHY" = true ] && [ "$BETA_HEALTHY" = true ]; then
            break
        fi
        sleep 2
        WAITED=$((WAITED + 2))
        echo -e "  Waiting... (${WAITED}s / ${MAX_WAIT}s)"
    done

    if [ "$ALPHA_HEALTHY" = false ] || [ "$BETA_HEALTHY" = false ]; then
        echo -e "\n${RED}Relays did not become healthy within ${MAX_WAIT}s.${NC}"
        echo "Check logs: $DOCKER_COMPOSE -f $COMPOSE_FILE logs"
        exit 1
    fi
    echo ""
else
    echo -e "${YELLOW}[2/6] Skipping Docker (--no-docker)${NC}"
    echo -e "${YELLOW}[3/6] Skipping relay startup (--no-docker)${NC}"
    echo -e "${YELLOW}[4/6] Checking relays are running...${NC}"
    if ! curl -sf "$RELAY_ALPHA_URL/health" > /dev/null 2>&1; then
        echo -e "  ${RED}Relay Alpha ($RELAY_ALPHA_URL) not responding${NC}"
        exit 1
    fi
    if ! curl -sf "$RELAY_BETA_URL/health" > /dev/null 2>&1; then
        echo -e "  ${RED}Relay Beta ($RELAY_BETA_URL) not responding${NC}"
        exit 1
    fi
    echo -e "  ${GREEN}Both relays healthy${NC}"
    echo ""
fi

# ---- Print Relay Info ----
echo -e "${CYAN}Relay Configuration:${NC}"
echo "  Alpha: $RELAY_ALPHA_URL ($ALPHA_DOMAIN) - Python agent home"
echo "  Beta:  $RELAY_BETA_URL ($BETA_DOMAIN) - TypeScript agent home"
echo "  Federation: enabled (both relays can forward to each other)"
echo ""

# ---- Run the Agents ----
echo -e "${YELLOW}[5/6] Starting agents...${NC}"
echo ""

# Peer addresses
PY_PEER="${TS_AGENT_NAME}::${BETA_DOMAIN}"
TS_PEER="${PY_AGENT_NAME}::${ALPHA_DOMAIN}"

# Start Python agent in background
echo -e "${BOLD}--- Python Agent Output ---${NC}"
cd "$SCRIPT_DIR"
python3 demo.py \
    --relay "$RELAY_ALPHA_URL" \
    --domain "$ALPHA_DOMAIN" \
    --name "$PY_AGENT_NAME" \
    --peer "$PY_PEER" &
PY_PID=$!

# Wait 1 second for Python agent to register
sleep 1

# Start TypeScript agent (foreground)
echo ""
echo -e "${BOLD}--- TypeScript Agent Output ---${NC}"
node ts-agent.mjs \
    --relay "$RELAY_BETA_URL" \
    --domain "$BETA_DOMAIN" \
    --name "$TS_AGENT_NAME" \
    --peer "$TS_PEER"
TS_EXIT=$?

# Wait for Python agent to complete
wait $PY_PID 2>/dev/null
PY_EXIT=$?

echo ""

# ---- Summary ----
echo -e "${YELLOW}[6/6] Demo Results${NC}"
echo -e "${BOLD}${CYAN}"
echo "============================================================"
echo "  Demo Complete!"
echo "============================================================"
echo -e "${NC}"
echo -e "  Python agent ($PY_AGENT_NAME::$ALPHA_DOMAIN):"
if [ $PY_EXIT -eq 0 ]; then
    echo -e "    Status: ${GREEN}SUCCESS${NC}"
else
    echo -e "    Status: ${RED}FAILED (exit $PY_EXIT)${NC}"
fi
echo -e "  TypeScript agent ($TS_AGENT_NAME::$BETA_DOMAIN):"
if [ $TS_EXIT -eq 0 ]; then
    echo -e "    Status: ${GREEN}SUCCESS${NC}"
else
    echo -e "    Status: ${RED}FAILED (exit $TS_EXIT)${NC}"
fi
echo ""
echo -e "  What happened:"
echo "    1. Python agent registered on Relay Alpha ($ALPHA_DOMAIN)"
echo "    2. TypeScript agent registered on Relay Beta ($BETA_DOMAIN)"
echo "    3. Messages encrypted with NaCl Box and signed with Ed25519"
echo "    4. Federation forwarded messages between relays"
echo "    5. Both agents received and decrypted cross-language messages"
echo ""

# ---- Cleanup ----
if [ "$USE_DOCKER" = true ]; then
    echo -e -n "${YELLOW}Shut down relay containers? [Y/n] ${NC}"
    read -r REPLY
    if [ -z "$REPLY" ] || [ "$REPLY" = "y" ] || [ "$REPLY" = "Y" ]; then
        echo "Stopping containers..."
        $DOCKER_COMPOSE -f "$COMPOSE_FILE" down
        echo -e "${GREEN}Containers stopped and removed.${NC}"
    else
        echo "Relays left running. Stop with:"
        echo "  $DOCKER_COMPOSE -f $COMPOSE_FILE down"
    fi
fi

# Exit with failure if either agent failed
if [ $PY_EXIT -ne 0 ] || [ $TS_EXIT -ne 0 ]; then
    exit 1
fi

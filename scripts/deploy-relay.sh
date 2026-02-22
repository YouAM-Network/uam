#!/usr/bin/env bash
# UAM Relay Deployment Script
# Checks prerequisites, configures environment, and starts the relay.
#
# Usage: bash scripts/deploy-relay.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DOCKER_DIR="$PROJECT_ROOT/docker"
ENV_FILE="$DOCKER_DIR/.env"
ENV_EXAMPLE="$DOCKER_DIR/.env.example"
COMPOSE_FILE="$DOCKER_DIR/docker-compose.yml"

# ---- Colors ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ---- Step 1: Check prerequisites ----
info "Checking prerequisites..."

if ! command -v docker &>/dev/null; then
    error "Docker is not installed. Install it from https://docs.docker.com/get-docker/"
    exit 1
fi
info "Docker found: $(docker --version)"

# Check for docker compose (v2 plugin) or docker-compose (v1 standalone)
COMPOSE_CMD=""
if docker compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
else
    error "docker-compose is not installed. Install it from https://docs.docker.com/compose/install/"
    exit 1
fi
info "Docker Compose found: $($COMPOSE_CMD version 2>/dev/null || echo 'available')"

# ---- Step 2: Set up environment file ----
if [ ! -f "$ENV_FILE" ]; then
    info "Creating .env file from template..."
    cp "$ENV_EXAMPLE" "$ENV_FILE"

    # Prompt for required values
    echo ""
    echo "=== UAM Relay Configuration ==="
    echo ""

    read -rp "Relay domain (e.g., relay.example.com): " RELAY_DOMAIN
    if [ -n "$RELAY_DOMAIN" ]; then
        sed -i.bak "s|UAM_RELAY_DOMAIN=.*|UAM_RELAY_DOMAIN=$RELAY_DOMAIN|" "$ENV_FILE"
        sed -i.bak "s|UAM_RELAY_HTTP_URL=.*|UAM_RELAY_HTTP_URL=https://$RELAY_DOMAIN|" "$ENV_FILE"
        sed -i.bak "s|UAM_RELAY_WS_URL=.*|UAM_RELAY_WS_URL=wss://$RELAY_DOMAIN/ws|" "$ENV_FILE"
    fi

    read -rp "Admin API key (leave blank to disable admin API): " ADMIN_KEY
    if [ -n "$ADMIN_KEY" ]; then
        sed -i.bak "s|UAM_ADMIN_API_KEY=.*|UAM_ADMIN_API_KEY=$ADMIN_KEY|" "$ENV_FILE"
    fi

    # Clean up sed backup files
    rm -f "$ENV_FILE.bak"

    echo ""
    info "Configuration saved to $ENV_FILE"
    info "Edit $ENV_FILE to customize further settings."
    echo ""
else
    info ".env file already exists at $ENV_FILE"
fi

# ---- Step 3: Build and start ----
info "Building and starting UAM relay..."
$COMPOSE_CMD -f "$COMPOSE_FILE" up -d --build

# ---- Step 4: Wait for health check ----
info "Waiting for relay to become healthy..."

MAX_WAIT=60
ELAPSED=0
HEALTHY=false

while [ $ELAPSED -lt $MAX_WAIT ]; do
    if curl -sf http://localhost:${UAM_PORT:-8000}/health >/dev/null 2>&1; then
        HEALTHY=true
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    echo -n "."
done
echo ""

if [ "$HEALTHY" = true ]; then
    info "Relay is healthy!"
else
    warn "Relay did not become healthy within ${MAX_WAIT}s."
    warn "Check logs: $COMPOSE_CMD -f $COMPOSE_FILE logs"
    exit 1
fi

# ---- Step 5: Print relay info ----
echo ""
echo "==========================================="
echo "  UAM Relay Deployed Successfully"
echo "==========================================="
echo ""

# Read domain from .env
DOMAIN=$(grep -E '^UAM_RELAY_DOMAIN=' "$ENV_FILE" | cut -d= -f2)
HTTP_URL=$(grep -E '^UAM_RELAY_HTTP_URL=' "$ENV_FILE" | cut -d= -f2)
WS_URL=$(grep -E '^UAM_RELAY_WS_URL=' "$ENV_FILE" | cut -d= -f2)

echo "  Domain:              $DOMAIN"
echo "  HTTP URL:            $HTTP_URL"
echo "  WebSocket URL:       $WS_URL"
echo "  Health check:        http://localhost:${UAM_PORT:-8000}/health"
echo "  .well-known:         $HTTP_URL/.well-known/uam-relay.json"
echo "  Federation endpoint: $HTTP_URL/api/v1/federation/deliver"
echo ""
echo "  Logs:    $COMPOSE_CMD -f $COMPOSE_FILE logs -f"
echo "  Stop:    $COMPOSE_CMD -f $COMPOSE_FILE down"
echo "  Restart: $COMPOSE_CMD -f $COMPOSE_FILE restart"
echo ""
echo "==========================================="

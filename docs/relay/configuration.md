# Configuration Reference

All UAM relay configuration is done through environment variables. Every variable is prefixed with `UAM_` and has a sensible default for development use.

## Core Settings

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `UAM_RELAY_DOMAIN` | `youam.network` | string | The public domain name of this relay. Used in federation identity, `.well-known` responses, and destination domain validation for inbound federation. |
| `UAM_RELAY_WS_URL` | `wss://relay.youam.network/ws` | string | The full public WebSocket URL agents use to connect. Advertised during registration. |
| `UAM_RELAY_HTTP_URL` | `https://relay.youam.network` | string | The full public HTTP URL of the relay. Used to construct the federation endpoint URL in `.well-known/uam-relay.json`. |
| `UAM_DB_PATH` | `relay.db` | string | Path to the SQLite database file. Created automatically on first startup. Can be absolute or relative to the working directory. |
| `UAM_HOST` | `0.0.0.0` | string | The network interface to bind to. Use `0.0.0.0` for all interfaces, `127.0.0.1` for localhost only. |
| `UAM_PORT` | `8000` | integer | The port the relay listens on. Override with platform-provided `$PORT` in production. |
| `UAM_CORS_ORIGINS` | `*` | string | Allowed CORS origins. Use `*` for development, restrict to specific origins in production. |

## Security Settings

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `UAM_ADMIN_API_KEY` | *(none)* | string or null | When set, enables admin endpoints (`/api/v1/admin/*`). All admin requests must include `X-Admin-Key: <value>` header. Leave unset to disable admin API entirely. |
| `UAM_DOMAIN_VERIFICATION_TTL_HOURS` | `24` | integer | How long a domain verification remains valid before re-verification is required. After expiry, the reverification background task re-checks DNS/HTTPS and downgrades the agent to Tier 1 on failure. |

## Spam Defense Settings

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `UAM_DOMAIN_RATE_LIMIT` | `200` | integer | Maximum messages per minute from any single domain (not per-sender). Prevents mass-registration spam attacks where many agents on one domain flood the relay. |
| `UAM_REPUTATION_DEFAULT_SCORE` | `30` | integer | Starting reputation score for newly registered Tier 1 agents (range 0-100). Agents with DNS-verified domains start at the DNS-verified score instead. |
| `UAM_REPUTATION_DNS_VERIFIED_SCORE` | `60` | integer | Reputation score assigned to agents after successful DNS domain verification. Provides higher rate limits and better deliverability. |

## Webhook Settings

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `UAM_WEBHOOK_CIRCUIT_COOLDOWN_SECONDS` | `3600` | integer | After 5 consecutive webhook delivery failures, the circuit breaker disables the endpoint for this many seconds. During cooldown, messages fall back to store-and-forward. |
| `UAM_WEBHOOK_DELIVERY_TIMEOUT` | `30.0` | float | HTTP timeout in seconds for webhook delivery POST requests. Webhooks that don't respond within this time are counted as failures. |

## Federation Settings

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `UAM_RELAY_KEY_PATH` | `relay_key.pem` | string | Path to the relay's Ed25519 signing key file. Auto-generated on first startup if the file doesn't exist. The file stores a 32-byte base64-encoded seed with mode 0600. **Keep this file secure** -- it is the relay's cryptographic identity. |
| `UAM_FEDERATION_ENABLED` | `true` | boolean | Enable or disable federation. When `false`, the relay operates as a standalone node: it does not forward messages to other relays, does not accept inbound federated envelopes, and does not load federation services at startup. |
| `UAM_FEDERATION_MAX_HOPS` | `3` | integer | Maximum number of relay hops allowed in a federated message chain. Prevents infinite forwarding loops. A message that has traversed this many relays is rejected. |
| `UAM_FEDERATION_RELAY_RATE_LIMIT` | `1000` | integer | Default maximum federated messages per minute accepted from any single source relay. This limit is adjusted based on the source relay's reputation score (higher reputation = higher limit). |
| `UAM_FEDERATION_TIMESTAMP_MAX_AGE` | `300` | integer | Maximum age in seconds for a federated request timestamp. Requests older than this are rejected to prevent replay attacks. Default is 5 minutes. Ensure NTP is running on your server to avoid clock drift issues. |
| `UAM_FEDERATION_DISCOVERY_TTL_HOURS` | `1` | integer | How long to cache discovered relay endpoints before re-verifying via DNS SRV or `.well-known`. Lower values detect relay moves faster but increase DNS/HTTP lookups. |

## Debug Settings

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `UAM_LOG_LEVEL` | `INFO` | string | Logging verbosity. One of: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. Controls the root logger level for the relay process. |
| `UAM_DEBUG` | *(false)* | boolean | When `true` (or `1` or `yes`), sets all `uam.*` loggers to DEBUG level regardless of `UAM_LOG_LEVEL`. Useful for diagnosing federation or protocol issues. **Do not use in production** -- generates high log volume. |

## Configuration by Deployment Scenario

### Local Development

```bash
# Minimal -- all defaults are fine
uvicorn uam.relay.app:create_app --factory
```

### Single Production Relay

```bash
UAM_RELAY_DOMAIN=relay.example.com
UAM_RELAY_HTTP_URL=https://relay.example.com
UAM_RELAY_WS_URL=wss://relay.example.com/ws
UAM_DB_PATH=/var/lib/uam/relay.db
UAM_RELAY_KEY_PATH=/var/lib/uam/relay_key.pem
UAM_ADMIN_API_KEY=change-this-to-a-strong-random-string
UAM_LOG_LEVEL=INFO
UAM_CORS_ORIGINS=https://example.com,https://app.example.com
```

### Federated Relay (Receiving from Peers)

```bash
# Same as production, plus tuning federation limits
UAM_FEDERATION_ENABLED=true
UAM_FEDERATION_RELAY_RATE_LIMIT=500
UAM_FEDERATION_TIMESTAMP_MAX_AGE=300
UAM_FEDERATION_MAX_HOPS=3
```

### High-Security Relay

```bash
# Restrictive settings
UAM_FEDERATION_ENABLED=false          # No federation
UAM_CORS_ORIGINS=https://myapp.com    # Single origin
UAM_DOMAIN_RATE_LIMIT=50              # Tight rate limit
UAM_REPUTATION_DEFAULT_SCORE=10       # Low trust for new agents
UAM_ADMIN_API_KEY=strong-random-key   # Enable admin for manual control
```

## Environment File Example

See `docker/.env.example` for a copy-paste-ready template with all variables and comments.

---

*All variables are read from the `Settings` class in `src/uam/relay/config.py`. Restart the relay after changing environment variables.*

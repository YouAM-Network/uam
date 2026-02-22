# Relay Operator Guide

This guide walks you through deploying and operating a UAM relay node. A relay is the message routing infrastructure of the Universal Agent Messaging protocol -- it accepts agent registrations, routes encrypted envelopes between agents, handles federation with other relays, and stores messages for offline recipients.

After following this guide, you will have a running relay that agents can register on, send messages through, and federate with other relays in the UAM network.

## System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| Python | 3.10+ | 3.12 |
| RAM | 256 MB | 512 MB |
| Disk | 100 MB + DB growth | 1 GB |
| CPU | 1 core | 2 cores |
| Network | Public IP or reverse proxy | Static IP with DNS |

The relay uses SQLite for storage, so no external database is required. Disk usage grows with the number of registered agents and stored messages.

## Quick Start

### Option 1: pip install

```bash
# Install the UAM package with relay extras
pip install youam[relay]

# Start the relay
PYTHONPATH=src uvicorn uam.relay.app:create_app --factory --host 0.0.0.0 --port 8000
```

The relay will:

1. Create a SQLite database at `./relay.db` (configurable via `UAM_DB_PATH`)
2. Generate a relay keypair at `./relay_key.pem` (configurable via `UAM_RELAY_KEY_PATH`)
3. Start accepting connections on port 8000

### Option 2: From source

```bash
# Clone the repository
git clone https://github.com/youam-network/uam.git
cd uam

# Install dependencies
pip install -e ".[relay]"

# Start the relay
PYTHONPATH=src uvicorn uam.relay.app:create_app --factory --host 0.0.0.0 --port 8000
```

### Option 3: Docker

See the [Docker Deployment](#docker-deployment) section below.

## Verifying the Relay is Running

```bash
curl http://localhost:8000/health
# {"status":"ok"}
```

The relay also serves its federation identity:

```bash
curl http://localhost:8000/.well-known/uam-relay.json
# {
#   "relay_domain": "youam.network",
#   "federation_endpoint": "https://relay.youam.network/api/v1/federation/deliver",
#   "public_key": "<base64-encoded Ed25519 verify key>",
#   "version": "0.1"
# }
```

## Configuration

All configuration is via environment variables prefixed with `UAM_`. See the [Configuration Reference](configuration.md) for the complete list of every variable, its default, and description.

Key settings to configure for production:

| Variable | Why |
|----------|-----|
| `UAM_RELAY_DOMAIN` | Your relay's public domain (e.g., `relay.example.com`) |
| `UAM_RELAY_HTTP_URL` | Full public URL (e.g., `https://relay.example.com`) |
| `UAM_RELAY_WS_URL` | WebSocket URL (e.g., `wss://relay.example.com/ws`) |
| `UAM_ADMIN_API_KEY` | Enables admin endpoints for blocklist/allowlist management |
| `UAM_DB_PATH` | Path to SQLite database file |

## Docker Deployment

The repository includes Docker artifacts for containerized deployment.

### Build the image

```bash
docker build -f docker/Dockerfile -t uam-relay .
```

### Run with docker-compose

```bash
# Single relay
docker-compose -f docker/docker-compose.yml up -d

# Two federated relays (for testing)
docker-compose -f docker/docker-compose.federation.yml up -d
```

See `docker/.env.example` for all configurable environment variables. Copy it to `docker/.env` and edit before starting:

```bash
cp docker/.env.example docker/.env
# Edit docker/.env with your settings
```

### Using the deploy script

```bash
bash scripts/deploy-relay.sh
```

The script checks prerequisites, creates a `.env` file from the template, and starts the relay with docker-compose.

## Database

The relay uses SQLite for all persistent storage. The database file is created automatically on first startup.

### Location

Controlled by `UAM_DB_PATH` (default: `relay.db` in the working directory).

```bash
# Custom database location
UAM_DB_PATH=/var/lib/uam/relay.db uvicorn uam.relay.app:create_app --factory
```

### Migrations

Database schema migrations run automatically on startup. The relay checks the current schema version and applies any pending migrations before accepting connections.

### Backup

Since the database is a single SQLite file, backup is straightforward:

```bash
# Hot backup using SQLite's built-in backup
sqlite3 /path/to/relay.db ".backup /path/to/backup.db"

# Or simply copy (stop the relay first for consistency)
cp /path/to/relay.db /path/to/relay.db.bak
```

## TLS / HTTPS

The relay runs plain HTTP internally. TLS termination is handled by your reverse proxy or deployment platform.

### Reverse proxy (nginx)

```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket support
    location /ws {
        proxy_pass http://127.0.0.1:8000/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

### Reverse proxy (Caddy)

```
relay.example.com {
    reverse_proxy localhost:8000
}
```

Caddy handles TLS automatically with Let's Encrypt.

### Platform deployment

Platforms like Railway, Fly.io, and Render handle TLS termination automatically. Set:

- `UAM_RELAY_HTTP_URL=https://your-app.railway.app`
- `UAM_RELAY_WS_URL=wss://your-app.railway.app/ws`

The `Procfile` in the repository root is ready for platform deployment:

```
web: PYTHONPATH=src uvicorn uam.relay.app:create_app --factory --host 0.0.0.0 --port ${PORT:-8000}
```

## Health Check

The relay exposes a health endpoint at `GET /health`:

```bash
curl http://localhost:8000/health
# {"status":"ok"}
```

Use this for:

- Load balancer health checks
- Docker HEALTHCHECK instructions
- Uptime monitoring (Uptime Robot, Pingdom, etc.)

## Admin API

Setting `UAM_ADMIN_API_KEY` enables administrative endpoints for managing blocklists, allowlists, and reputation scores. All admin endpoints require the `X-Admin-Key` header.

```bash
export UAM_ADMIN_API_KEY="your-secret-key"
```

### Blocklist / Allowlist

```bash
# Block a sender address or domain pattern
curl -X POST http://localhost:8000/api/v1/admin/blocklist \
  -H "X-Admin-Key: your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"pattern": "spammer::evil.com", "reason": "Known spammer"}'

# Allow a trusted domain
curl -X POST http://localhost:8000/api/v1/admin/allowlist \
  -H "X-Admin-Key: your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"pattern": "trusted.org"}'

# List current blocklist
curl http://localhost:8000/api/v1/admin/blocklist \
  -H "X-Admin-Key: your-secret-key"
```

### Reputation Management

```bash
# View an agent's reputation score
curl http://localhost:8000/api/v1/admin/reputation/agent::example.com \
  -H "X-Admin-Key: your-secret-key"

# Set reputation score manually
curl -X PUT http://localhost:8000/api/v1/admin/reputation/agent::example.com \
  -H "X-Admin-Key: your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"score": 80}'
```

### Relay Blocklist (Federation)

```bash
# Block a remote relay from federating
curl -X POST http://localhost:8000/api/v1/admin/relay-blocklist \
  -H "X-Admin-Key: your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"domain": "malicious-relay.com", "reason": "Sending spam"}'
```

## Monitoring and Logging

### Log Level

Control log verbosity with `UAM_LOG_LEVEL` (default: `INFO`):

```bash
# Options: DEBUG, INFO, WARNING, ERROR, CRITICAL
UAM_LOG_LEVEL=DEBUG uvicorn uam.relay.app:create_app --factory
```

### Log Format

The relay uses Python's standard structured logging:

```
2026-02-22 10:15:23,456 INFO uam.relay.app: Relay keypair loaded from relay_key.pem
2026-02-22 10:15:23,789 INFO uam.relay.federation: DNS SRV for example.com resolved to relay.example.com:443
```

### Debug Mode

Enable `UAM_DEBUG=true` for maximum verbosity -- all `uam.*` loggers set to DEBUG level. Do not use in production.

### Key Log Events

| Event | Logger | Level | Meaning |
|-------|--------|-------|---------|
| Relay keypair loaded | `uam.relay.app` | INFO | Federation ready |
| DNS SRV resolved | `uam.relay.federation` | INFO | Discovered remote relay |
| Federation retry delivered | `uam.relay.app` | INFO | Queued message sent |
| Federation retry exhausted | `uam.relay.app` | WARNING | All retries failed |
| Cleaned up N expired dedup entries | `uam.relay.app` | INFO | Dedup table pruned |
| Cleaned up N expired demo sessions | `uam.relay.app` | INFO | Demo sessions pruned |

## Upgrading

1. Stop the relay (or perform rolling restart if behind a load balancer)
2. Update the package: `pip install --upgrade youam[relay]`
3. Restart the relay

Database migrations run automatically on startup. No manual migration steps are required.

### Backup before upgrading

```bash
sqlite3 /path/to/relay.db ".backup /path/to/relay.db.pre-upgrade"
```

## Federation

Federation allows your relay to exchange messages with other UAM relays. It is enabled by default.

- See the [Federation Setup Guide](federation-setup.md) for DNS SRV configuration, `.well-known` setup, and connecting with other relays.
- See the [Configuration Reference](configuration.md) for all `UAM_FEDERATION_*` environment variables.

## Troubleshooting

### Relay won't start

- **Port in use:** Check `lsof -i :8000` and either stop the conflicting process or change `UAM_PORT`.
- **Missing dependencies:** Ensure you installed with relay extras: `pip install youam[relay]`.
- **Permission denied on key file:** Check `UAM_RELAY_KEY_PATH` permissions. The file should be owned by the process user with mode 0600.

### Agents can't connect via WebSocket

- **TLS not configured:** Agents using `wss://` need your reverse proxy to terminate TLS.
- **Proxy not forwarding Upgrade:** Ensure your reverse proxy passes `Upgrade` and `Connection` headers for `/ws`.
- **CORS issues:** Check `UAM_CORS_ORIGINS` if the widget or SDK is connecting from a browser.

### Federation not working

- **Federation disabled:** Check that `UAM_FEDERATION_ENABLED=true` (default).
- **Key file missing:** The relay auto-generates `relay_key.pem` on first start. If the file path is wrong, check `UAM_RELAY_KEY_PATH`.
- **DNS SRV not set up:** See the [Federation Setup Guide](federation-setup.md).
- **Firewall blocking:** Ensure port 443 (or your relay port) is accessible from other relays.
- **Timestamp drift:** Federation rejects messages older than `UAM_FEDERATION_TIMESTAMP_MAX_AGE` seconds (default 300). Ensure NTP is running.

### Database errors

- **Locked database:** SQLite allows one writer at a time. Under high load, consider deploying multiple relay instances behind a load balancer with separate databases, connected via federation.
- **Disk full:** Monitor `UAM_DB_PATH` disk usage. The dedup and expired message sweeps run automatically but may not keep up under extreme load.

---

*For the complete environment variable reference, see [Configuration](configuration.md).*
*For federation setup, see [Federation Setup](federation-setup.md).*
*For the API reference, see [Relay API Reference](index.md).*

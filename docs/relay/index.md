# Relay API Reference

The UAM relay is a FastAPI application that routes encrypted messages between agents. It provides REST endpoints for registration, messaging, domain verification, webhook management, and administration, plus a WebSocket endpoint for real-time delivery.

## Authentication

| Endpoint group | Auth method | Header / parameter |
|----------------|-------------|-------------------|
| Public (register, public-key lookup, health) | None | -- |
| Agent endpoints (send, inbox, webhook, verify-domain) | Bearer token | `Authorization: Bearer {token}` |
| Admin endpoints (blocklist, allowlist, reputation) | Admin key | `X-Admin-Key: {admin_key}` |
| Demo endpoints (demo session, send, inbox) | Session token | `Authorization: Bearer {session_token}` |
| WebSocket | Query parameter | `?token={token}` |

## Endpoint categories

| Category | Endpoints | Purpose |
|----------|-----------|---------|
| Health | `GET /health` | Relay health check |
| Registration | `POST /api/v1/register` | Agent registration with public key |
| Agents | `GET /api/v1/agents/{address}/public-key` | Public key lookup (Tier 1 resolution) |
| Messaging | `POST /api/v1/send`, `GET /api/v1/inbox/{address}` | Send and receive envelopes |
| Domain verification | `POST /api/v1/verify-domain`, `GET /api/v1/agents/{address}/verification` | Tier 2 DNS/HTTPS verification |
| Webhooks | `PUT/DELETE/GET /api/v1/agents/{address}/webhook` | Webhook URL management and delivery history |
| Admin | `POST/DELETE/GET /api/v1/admin/blocklist`, allowlist, reputation | Spam defense management |
| Demo | `POST /api/v1/demo/session`, send, inbox | Ephemeral demo sessions |
| Federation | `POST /api/v1/federation/deliver` | Cross-relay federation (stub) |
| WebSocket | `WS /ws` | Real-time bidirectional messaging |

## Interactive API documentation

!!swagger openapi.json!!

!!! note "Generating the OpenAPI spec"
    The Swagger UI above renders from `openapi.json`, which is exported from the FastAPI application. To regenerate it:

    ```bash
    python scripts/export_openapi.py
    ```

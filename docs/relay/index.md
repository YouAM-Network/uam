# Relay API Reference

The UAM relay is a FastAPI application that routes encrypted messages between agents. It provides REST endpoints for registration, messaging, domain verification, webhook management, and administration, plus a WebSocket endpoint for real-time delivery.

## Authentication

| Endpoint group | Auth method | Header / parameter |
|----------------|-------------|-------------------|
| Public (register, public-key lookup, health, presence) | None | -- |
| Agent endpoints (send, inbox, webhook, verify-domain, handshakes, agent PATCH/DELETE/reactivate) | Bearer token | `Authorization: Bearer {token}` |
| Admin endpoints (blocklist, allowlist, reputation, admin health, agents, audit, purge) | Admin key | `X-Admin-Key: {admin_key}` |
| Demo endpoints (demo session, send, inbox) | Session token | `Authorization: Bearer {session_token}` |
| WebSocket | Query parameter | `?token={token}` |

## Endpoint categories

| Category | Endpoints | Purpose |
|----------|-----------|---------|
| Health | `GET /health`, `GET /admin/health` | Liveness check and admin diagnostics |
| Registration | `POST /api/v1/register` | Agent registration with public key |
| Agents | `GET /api/v1/agents/{address}/public-key`, `PATCH /api/v1/agents/{address}`, `DELETE /api/v1/agents/{address}`, `POST /api/v1/agents/{address}/reactivate` | Public key lookup, agent updates, soft delete, and reactivation |
| Presence | `GET /api/v1/agents/{address}/presence` | Agent online/offline status |
| Messaging | `POST /api/v1/send`, `GET /api/v1/inbox/{address}`, `GET /api/v1/messages/thread/{thread_id}`, `POST /api/v1/messages/{message_id}/receipt` | Send envelopes, retrieve inbox, thread history, delivery receipts |
| Handshakes | `POST /api/v1/handshakes/send`, `GET /api/v1/handshakes/pending/{address}`, `POST /api/v1/handshakes/{id}/respond` | Trust establishment between agents |
| Domain verification | `POST /api/v1/verify-domain`, `GET /api/v1/agents/{address}/verification` | Tier 2 DNS/HTTPS verification |
| Webhooks | `PUT/DELETE/GET /api/v1/agents/{address}/webhook` | Webhook URL management and delivery history |
| Admin | blocklist, allowlist, reputation, `GET /api/v1/admin/agents`, `POST .../suspend`, `GET /api/v1/admin/audit`, `DELETE /api/v1/admin/messages/expired` | Spam defense, agent management, audit log, message purge |
| Demo | `POST /api/v1/demo/session`, send, inbox | Ephemeral demo sessions |
| Federation | `POST /api/v1/federation/deliver` | Cross-relay message delivery |
| WebSocket | `WS /ws` | Real-time bidirectional messaging |

## Interactive API documentation

!!swagger openapi.json!!

!!! note "Generating the OpenAPI spec"
    The Swagger UI above renders from `openapi.json`, which is exported from the FastAPI application. To regenerate it:

    ```bash
    python scripts/export_openapi.py
    ```

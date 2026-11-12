# Configuration Reference

All UAM relay configuration is done through environment variables. Core relay settings are prefixed with `UAM_`. Database and pool settings use their own prefixes.

## Core Settings

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `UAM_RELAY_DOMAIN` | `youam.network` | string | The public domain name of this relay. Used in federation identity, `.well-known` responses, and destination domain validation for inbound federation. |
| `UAM_RELAY_WS_URL` | `wss://relay.youam.network/ws` | string | The full public WebSocket URL agents use to connect. Advertised during registration. |
| `UAM_RELAY_HTTP_URL` | `https://relay.youam.network` | string | The full public HTTP URL of the relay. Used to construct the federation endpoint URL in `.well-known/uam-relay.json`. |
| `UAM_HOST` | `0.0.0.0` | string | The network interface to bind to. Use `0.0.0.0` for all interfaces, `127.0.0.1` for localhost only. |
| `UAM_PORT` | `8000` | integer | The port the relay listens on. Override with platform-provided `$PORT` in production. |
| `UAM_CORS_ORIGINS` | `*` | string | Allowed CORS origins. Use `*` for development, restrict to specific origins in production. |

## Database Settings

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `DATABASE_URL` | *(derived from UAM_DB_PATH)* | string | Full database connection URL. Supports PostgreSQL (`postgresql+asyncpg://user:pass@host/db`) and SQLite (`sqlite+aiosqlite:///path/to/relay.db`). When not set, the relay auto-constructs a SQLite URL from `UAM_DB_PATH`. |
| `UAM_DB_PATH` | `relay.db` | string | Path to the SQLite database file. Only used when `DATABASE_URL` is not set. Can be absolute or relative to the working directory. |
| `MESSAGE_RETENTION_DAYS` | `30` | integer | Number of days to retain delivered/expired messages before the retention worker purges them. Set to `0` to disable purging. |

## Connection Pool Settings (PostgreSQL only)

These settings configure the SQLAlchemy async connection pool. They only apply when using PostgreSQL via `DATABASE_URL`. SQLite uses `NullPool`/`StaticPool` and ignores these.

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `DB_POOL_SIZE` | `5` | integer | Number of persistent connections in the pool. |
| `DB_MAX_OVERFLOW` | `10` | integer | Maximum additional connections beyond `DB_POOL_SIZE` allowed during traffic spikes. |
| `DB_POOL_TIMEOUT` | `30` | integer | Seconds to wait for a connection from the pool before raising an error. |
| `DB_POOL_RECYCLE` | `1800` | integer | Seconds after which a connection is recycled (closed and replaced). Prevents stale connections from long-lived processes. |

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
| `UAM_PENDING_RATE_LIMIT` | `300` | integer | Sends per sender per minute that the inbound gate may answer `pending`. Pending answers don't use the recipient's rate limit, so a gated agent's approved contacts aren't crowded out; past this a sender gets 429. |
| `UAM_UNKNOWN_MESSAGE_TYPES` | `log` | string | What to do with an envelope whose `type` the protocol does not define: `log` delivers it and logs a warning naming the sender; `reject` refuses it (HTTP 400, WebSocket error `unknown_type`). Watch the warnings before switching to `reject`. |

## Webhook Settings

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `UAM_WEBHOOK_CIRCUIT_COOLDOWN_SECONDS` | `3600` | integer | After 5 consecutive webhook delivery failures, the circuit breaker disables the endpoint for this many seconds. During cooldown, messages fall back to store-and-forward. |
| `UAM_WEBHOOK_DELIVERY_TIMEOUT` | `30.0` | float | HTTP timeout in seconds for webhook delivery POST requests. Webhooks that don't respond within this time are counted as failures. |

## Federation Settings

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `UAM_RELAY_KEY_PATH` | `relay_key.pem` | string | Path to the relay's Ed25519 signing key file. Auto-generated on first startup if the file doesn't exist. The file stores a 32-byte base64-encoded seed with mode 0600. **Keep this file secure** -- it is the relay's cryptographic identity. |
| `UAM_RELAY_KEY` | *(unset)* | string (secret) | The relay's signing key itself: the base64 Ed25519 seed, as stored in a key file. When set it wins over `UAM_RELAY_KEY_PATH` and no file is read or written, so a rebuilt host keeps the same identity. Supply it from your secret store, never from a committed file. A value that isn't a valid key stops the relay at startup. In production the relay logs a warning when this is unset. |
| `UAM_RELAY_KEY_VALID_FROM` | *(unset)* | string | When the current key came into use (ISO 8601, e.g. `2026-11-10T00:00:00Z`). Published beside the key in `/.well-known/uam-relay.json`. |
| `UAM_RELAY_KEY_HISTORY` | *(unset)* | JSON | The relay's retired public keys, so signatures made before a rotation can still be checked: `[{"public_key": "...", "valid_from": "...", "retired_at": "..."}]`. `retired_at` is required; the current key must not be listed. A malformed value stops the relay at startup. |
| `UAM_FEDERATION_ENABLED` | `true` | boolean | Enable or disable federation. When `false`, the relay operates as a standalone node: it does not forward messages to other relays, does not accept inbound federated envelopes, and does not load federation services at startup. |
| `UAM_FEDERATION_MAX_HOPS` | `3` | integer | Maximum number of relay hops allowed in a federated message chain. Prevents infinite forwarding loops. A message that has traversed this many relays is rejected. |
| `UAM_FEDERATION_RELAY_RATE_LIMIT` | `1000` | integer | Default maximum federated messages per minute accepted from any single source relay. This limit is adjusted based on the source relay's reputation score (higher reputation = higher limit). |
| `UAM_FEDERATION_TIMESTAMP_MAX_AGE` | `300` | integer | Maximum age in seconds for a federated request timestamp. Requests older than this are rejected to prevent replay attacks. Default is 5 minutes. Ensure NTP is running on your server to avoid clock drift issues. |
| `UAM_FEDERATION_DISCOVERY_TTL_HOURS` | `1` | integer | How long to cache discovered relay endpoints before re-verifying via DNS SRV or `.well-known`. Lower values detect relay moves faster but increase DNS/HTTP lookups. |

## Owner Account Settings

Owner accounts are being built (the people who approve contacts for their agents). They are off by default. When on, the relay serves the owner app only on the owner origin's host, a separate origin from the relay API, and `/.well-known/uam-relay.json` gains `owner_origin` and `rp_id`. Any missing or invalid value below stops the relay at startup.

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `UAM_OWNERS_ENABLED` | `false` | boolean | Turn owner accounts on. |
| `UAM_OWNER_ORIGIN` | *(unset)* | string | Where owners sign in, as `https://host[:port]` with nothing after it (e.g. `https://account.example.com`). Point that host's DNS at the relay. Plain `http` is allowed only for `localhost` and names under it (e.g. `http://account.uam.localhost:3140` for local use). |
| `UAM_RP_ID` | *(unset)* | string | The passkey relying-party ID: the owner origin's host or a parent domain of it (e.g. `example.com`). It must contain a dot, and so must `UAM_RELAY_DOMAIN`, because owners' key logs name both (locally, use something like `uam.localhost`). Changing it later invalidates every owner's passkeys. |
| `UAM_EMAIL_PEPPER` | *(unset)* | string (secret) | At least 32 characters. Owners' emails are looked up by an HMAC keyed with this; changing it makes every stored email unfindable. |
| `UAM_EMAIL_KEY` | *(unset)* | string (secret) | Base64url of 32 random bytes. Owners' emails are stored encrypted with it (AES-GCM). |
| `UAM_RESEND_API_KEY` | *(unset)* | string (secret) | A [Resend](https://resend.com) API key with sending access, limited to the sending domain. With it the relay emails sign-in codes, invitations and owners' notices. Required with a production RP ID. |
| `UAM_EMAIL_FROM` | `YouAM <account@notify.youam.network>` | string | The sender, as `Name <address>` or an address. With a strict DMARC policy its domain must be exactly the domain verified in Resend. |
| `UAM_OWNER_CODES_TO_LOG` | `false` | boolean | For test relays without a Resend key only: write sign-in codes and links to the relay log (never the email). Refused with a production RP ID. |

Emails go through an outbox table (`owner_mail`): the recipient and the contents are encrypted with `UAM_EMAIL_KEY`, a send that fails is retried with backoff (a sign-in code for 10 minutes, anything else for 20 hours, with the same idempotency key, so a retry never mails twice), and each row is deleted 7 days after it was sent or given up.

People make their own account on the owner origin (`POST /api/owner/sign-up {"email": "..."}`; 10 per client address an hour). The code goes to the email, and the account is theirs once they add a first passkey; one with no passkey after 24 hours is deleted. The admin can also create one with `POST /api/v1/admin/owners {"email": "..."}` (`X-Admin-Key`). The owner then signs in on the owner origin with a 6-digit code (10 minutes, 5 tries, at most 3 codes an hour) and gets a session cookie that lasts 12 idle hours and at most 7 days. Signed in, they register passkeys (ES256, user-verified, discoverable). Each passkey is added by a signed entry in the owner's key log: the first entry is signed by the passkey it adds and fixes the owner's id; later ones by a passkey already in the log. Anyone can fetch and verify an owner's key log at `GET /api/owner/keys/{owner_id}` on either origin.

With a passkey, an owner links agents to their account:

1. They make a code on their page (`POST /api/owner/codes`): 8 characters shown as `ABCD-EFGH`, valid 10 minutes, single use, and only the newest of each kind works. A `setup` code is for an agent set up after the code was made. A `link` code is for an existing agent. With `"count": n` (up to 25) one code serves n agents and lasts 30 minutes.
2. The agent redeems it with its token (`POST /api/v1/owner/link/start`; 5 tries per 10 minutes) and signs the link the relay built (`POST /api/v1/owner/link/sign`).
3. The owner sees the agent with four words worked out from its key, and approves with a passkey. Several waiting links can be approved with one passkey over one sentence that names each agent and its words (`POST /api/owner/link-sets/approve/start {"ids": [...]}`, then `/approve`).

A link made with a `link` code starts 72 hours after it is redeemed, and the owner can cancel it until then. So can whoever runs the agent, with its token (`POST /api/v1/owner/link/cancel`); once the link is in effect only the owner can end it. Unlinking needs the owner's passkey, or the admin (`POST /api/v1/admin/links/{id}/unlink`), and closes the agent's inbound policy. An agent reads where its link stands with `GET /api/v1/owner/link`.

### Who may message an owner's agents

Owners connect with each other, and each decides who reaches their agents:

1. Ada invites Bob from her page (`POST /api/owner/invites`): a code she reads out (`ABCD-EFGH`, 10 minutes) or a link (`/i/<id>#<secret>`, 7 days; the secret stays in the fragment). Or she types Bob's email (`POST /api/owner/invites/email/start`, then `/email`): her passkey signs the invite and her approval of whoever redeems it, and the email goes out 10 minutes later, so she can cancel it first. At most 10 invites open and 20 a day.
2. Bob, signed in with a passkey, opens it (`POST /api/owner/invites/find`, by code or by the link's id and secret; 5 wrong tries lock him out for 10 minutes). He sees Ada's email, how long her account has existed, and four words they can compare. One passkey approval (`/api/owner/invites/redeem/start`, then `/redeem`) signs his redemption and his approval of Ada. An invite works once; a second attempt gets `409` and Ada is told.
3. For a code or a link, Ada confirms Bob with her passkey, seeing his email (`/api/owner/invites/{id}/confirm/start`, then `/confirm`). An email invite needs nothing more.

Each approval (a `UamContactGrant`) lasts 90 days. `GET /api/owner/contacts` lists the people on both sides with their shared agents. Removing someone (`POST /api/owner/contacts/{owner_id}/remove`) withdraws your approval at once. Cancelling an invite withdraws what was signed for it. Both go on the relay's revocation list, which anyone can read: `GET /api/v1/owner/revocations?since=<n>` returns `{t, h, at}` entries, signed by the relay's key when it has one.

Each linked agent takes messages from Anyone (the default) or Only my contacts (`GET`/`POST /api/owner/links/{id}/policy`). Under Only my contacts the relay delivers from:
- a shared agent, linked and started, of an owner this agent's owner approved, signing with the key on its link (the receiving agent must be shared too);
- the owner's other agents, unless the owner turns that off;
- receipts for the agent's own mail.

Narrowing needs no passkey. Widening (back to Anyone, or letting the owner's own agents in again) needs a passkey over a `UamAgentPolicy` (`/policy/approve/start`, then `/approve`). Narrowing sets aside any contacts the agent had before; the owner can keep some with a passkey (`/keep/start`, then `/keep`), each bound to that sender's key. No route an agent's token can reach widens anything.

Several agents can be set at once (`POST /api/owner/policy` with `"links": [...]` or `"fleet": id`, at most 50): narrowing needs no passkey, and a request that would widen any of them changes none. Widening them is one passkey approval over one sentence naming every agent (`/api/owner/policy/approve/start`, then `/approve`); each agent keeps its own signed `UamAgentPolicy` and the hashes signed with it.

A fleet is a named group of an owner's agents; a link is in one at most. A code can name one (`"fleet": "support"` on `POST /api/owner/codes`): the agents that use it join, and one that is linked at once takes the fleet's setting if that only lets fewer in. Owners list, make, move agents between, rename and ungroup fleets (`GET`/`POST /api/owner/fleets`, `/fleets/move`, `/fleets/{id}/rename`, `/fleets/{id}/ungroup`). Grouping changes nobody's access and needs no passkey.

### Reserved names

Some names can't be newly registered or reserved on any relay: roles people trust by default (`admin`, `support`, `security`, `verify`, …), the network's own names, and the big AI companies and assistants (`anthropic`, `claude`, `openai`, `chatgpt`, …), plus `uam-*`, `youam-*`, `*-official` and `<reserved>-support` / `-security` / `-admin`. An agent that already has such a name keeps it. `UAM_RESERVED_NAMES` (comma-separated) holds more. The list is in `uam.relay.reserved_names`.

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

### Single Production Relay (SQLite)

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

### Production Relay (PostgreSQL)

```bash
UAM_RELAY_DOMAIN=relay.example.com
UAM_RELAY_HTTP_URL=https://relay.example.com
UAM_RELAY_WS_URL=wss://relay.example.com/ws
DATABASE_URL=postgresql+asyncpg://uam:password@db.example.com:5432/uam_relay
UAM_RELAY_KEY_PATH=/var/lib/uam/relay_key.pem
UAM_ADMIN_API_KEY=change-this-to-a-strong-random-string
UAM_LOG_LEVEL=INFO
UAM_CORS_ORIGINS=https://example.com,https://app.example.com

# Connection pool tuning (optional)
DB_POOL_SIZE=10
DB_MAX_OVERFLOW=20
DB_POOL_TIMEOUT=30
DB_POOL_RECYCLE=1800

# Message retention
MESSAGE_RETENTION_DAYS=30
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

*Core relay variables are read from the `Settings` class in `src/uam/relay/config.py`. Database and pool variables are read directly from the environment in `src/uam/db/engine.py`. Restart the relay after changing environment variables.*

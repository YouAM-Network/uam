# Federation Setup Guide

Federation allows UAM relays to exchange messages across organizational boundaries. When an agent on Relay A sends a message to an agent on Relay B, Relay A automatically discovers Relay B's federation endpoint, signs the forwarding request with its relay keypair, and delivers the envelope. The receiving relay validates the signature, checks the agent's envelope signature, and delivers the message locally.

This guide covers how to configure your relay for federation, set up DNS SRV records, verify connectivity, and manage trust between relays.

## How Federation Works

```
Agent alice::alpha.com                      Agent bob::beta.com
       |                                           ^
       | 1. Send envelope to bob::beta.com         |
       v                                           |
  Relay alpha.com                             Relay beta.com
       |                                           ^
       | 2. Discover beta.com via DNS SRV          |
       |    or .well-known fallback                |
       |                                           |
       | 3. Sign request with alpha.com keypair    |
       |                                           |
       | 4. POST /api/v1/federation/deliver ------>|
       |                                           |
       |    5. Validate relay signature            |
       |    6. Validate agent envelope signature   |
       |    7. Deliver to bob via WebSocket/       |
       |       webhook/store                       |
```

### Discovery Flow

When Relay A needs to reach Relay B, it follows this discovery sequence:

1. **Cache check** -- Look up `beta.com` in the `known_relays` table. If the entry exists and is fresh (within `UAM_FEDERATION_DISCOVERY_TTL_HOURS`), use the cached federation endpoint.

2. **DNS SRV lookup** -- Query `_uam._tcp.beta.com` for SRV records. The SRV record provides the hostname and port of the relay server.

3. **Public key fetch** -- After DNS SRV resolves, fetch `https://{srv-target}/.well-known/uam-relay.json` to get the relay's public key.

4. **.well-known fallback** -- If DNS SRV fails (no record, NXDOMAIN, timeout), fall back to `https://beta.com/.well-known/uam-relay.json` directly. This provides both the federation endpoint and public key.

5. **Cache result** -- Store the discovered relay in `known_relays` with a TTL for future lookups.

## Prerequisites

### Relay Keypair

Each relay has an Ed25519 signing keypair used to authenticate federation requests. The keypair is **automatically generated** on first startup and stored at `UAM_RELAY_KEY_PATH` (default: `relay_key.pem`).

The keypair file contains a 32-byte base64-encoded seed. It is created with restrictive permissions (mode 0600). **Do not share this file** -- it is the relay's cryptographic identity.

To verify your relay has a keypair:

```bash
curl http://localhost:8000/.well-known/uam-relay.json
```

The response includes your relay's public key:

```json
{
  "relay_domain": "alpha.com",
  "federation_endpoint": "https://alpha.com/api/v1/federation/deliver",
  "public_key": "base64-encoded-ed25519-verify-key",
  "version": "0.1"
}
```

### Federation Enabled

Federation is enabled by default (`UAM_FEDERATION_ENABLED=true`). Verify your relay has federation active by checking the startup logs:

```
INFO uam.relay.app: Relay keypair loaded from relay_key.pem
```

If you see `Federation is disabled` instead, set `UAM_FEDERATION_ENABLED=true` and restart.

## DNS SRV Setup

DNS SRV records are the primary discovery mechanism for federation. They allow other relays to find your federation endpoint without knowing your exact URL.

### Adding the SRV Record

Add a DNS SRV record for `_uam._tcp.yourdomain.com`:

| Field | Value | Example |
|-------|-------|---------|
| **Name** | `_uam._tcp.yourdomain.com` | `_uam._tcp.alpha.com` |
| **Type** | `SRV` | `SRV` |
| **Priority** | `10` | `10` |
| **Weight** | `100` | `100` |
| **Port** | Your relay port | `443` |
| **Target** | Your relay hostname | `relay.alpha.com` |
| **TTL** | 300 (5 min) | `300` |

### Example DNS Configuration

**BIND zone file:**

```
_uam._tcp.alpha.com. 300 IN SRV 10 100 443 relay.alpha.com.
```

**Cloudflare (API):**

```bash
curl -X POST "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records" \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "SRV",
    "name": "_uam._tcp.alpha.com",
    "data": {
      "priority": 10,
      "weight": 100,
      "port": 443,
      "target": "relay.alpha.com"
    },
    "ttl": 300
  }'
```

**AWS Route 53:**

```json
{
  "Type": "SRV",
  "Name": "_uam._tcp.alpha.com",
  "TTL": 300,
  "ResourceRecords": [
    { "Value": "10 100 443 relay.alpha.com." }
  ]
}
```

### Verifying DNS SRV

```bash
# Using dig
dig _uam._tcp.alpha.com SRV +short
# Expected: 10 100 443 relay.alpha.com.

# Using nslookup
nslookup -type=SRV _uam._tcp.alpha.com
```

## .well-known Fallback

The `.well-known/uam-relay.json` endpoint is automatically served by the relay at `GET /.well-known/uam-relay.json`. No additional configuration is needed.

This serves as:

1. **Fallback discovery** -- When DNS SRV lookup fails, other relays try `https://yourdomain.com/.well-known/uam-relay.json` directly.

2. **Public key source** -- After DNS SRV resolves, other relays still fetch `.well-known` from the SRV target to obtain your relay's public key.

### Response Format

```json
{
  "relay_domain": "alpha.com",
  "federation_endpoint": "https://alpha.com/api/v1/federation/deliver",
  "public_key": "base64-encoded-ed25519-verify-key",
  "version": "0.1"
}
```

### Configuration

The `.well-known` response is generated from:

- `relay_domain` -- from `UAM_RELAY_DOMAIN`
- `federation_endpoint` -- constructed from `UAM_RELAY_HTTP_URL` + `/api/v1/federation/deliver`
- `public_key` -- from the relay's auto-generated keypair at `UAM_RELAY_KEY_PATH`

Ensure `UAM_RELAY_HTTP_URL` is set to your relay's public HTTPS URL so other relays can construct the correct federation endpoint.

## Verifying Federation

### Testing Discovery Between Two Relays

From Relay A, verify it can discover Relay B:

```bash
# Check DNS SRV
dig _uam._tcp.beta.com SRV +short

# Check .well-known
curl https://beta.com/.well-known/uam-relay.json
```

From Relay B, verify it can discover Relay A:

```bash
dig _uam._tcp.alpha.com SRV +short
curl https://alpha.com/.well-known/uam-relay.json
```

### Sending a Test Message

Register agents on each relay and send a cross-relay message:

```bash
# On Relay A's machine
uam init --name alice --relay https://alpha.com
uam send bob::beta.com "Hello from alpha!"

# On Relay B's machine
uam init --name bob --relay https://beta.com
uam inbox
# Should show the message from alice::alpha.com
```

### Checking Federation Logs

The relay logs federation events at INFO level:

```
INFO uam.relay.federation: DNS SRV for beta.com resolved to relay.beta.com:443
INFO uam.relay.app: Federation retry delivered: queue_id=1 to beta.com
```

Enable DEBUG logging for detailed federation diagnostics:

```bash
UAM_LOG_LEVEL=DEBUG
```

## Controlling Federation

### Relay Blocklist / Allowlist

Block or allow specific relays from federating with yours:

```bash
# Block a relay
curl -X POST http://localhost:8000/api/v1/admin/relay-blocklist \
  -H "X-Admin-Key: $UAM_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain": "spam-relay.com", "reason": "Sending unsolicited bulk messages"}'

# Allow a trusted relay (bypasses reputation-based rate limits)
curl -X POST http://localhost:8000/api/v1/admin/relay-allowlist \
  -H "X-Admin-Key: $UAM_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain": "trusted-partner.org"}'

# List blocked relays
curl http://localhost:8000/api/v1/admin/relay-blocklist \
  -H "X-Admin-Key: $UAM_ADMIN_API_KEY"
```

### Per-Relay Rate Limits

Each source relay has a rate limit based on its reputation score:

| Reputation Score | Rate Limit (msg/min) | Tier |
|-----------------|---------------------|------|
| 80-100 | 1000 (base limit) | Trusted |
| 50-79 | 500 | Normal |
| 20-49 | 100 | Suspicious |
| 0-19 | 0 (blocked) | Blocked |

New relays start at a reputation score of 50. Reputation adjusts automatically:

- **Successful delivery** -- score increases by +1
- **Validation failure** (bad signature, timestamp, loop) -- score decreases by -5

The base rate limit is controlled by `UAM_FEDERATION_RELAY_RATE_LIMIT` (default: 1000 msg/min).

### Disabling Federation

To run your relay as a standalone node:

```bash
UAM_FEDERATION_ENABLED=false
```

This disables:

- Outbound forwarding (messages to non-local agents are not forwarded)
- Inbound federation endpoint (returns 501 Not Implemented)
- Federation service, blocklist, reputation, and rate limiter initialization
- Federation retry loop

## Retry and Queuing

When outbound federation delivery fails (network error, timeout, remote relay down), the message is queued in the `federation_queue` table and retried automatically.

### Retry Schedule

| Attempt | Delay | Total Elapsed |
|---------|-------|---------------|
| 0 | Immediate | 0s |
| 1 | 30 seconds | 30s |
| 2 | 5 minutes | 5m 30s |
| 3 | 30 minutes | 35m 30s |
| 4 | 2 hours | 2h 35m 30s |

After all 5 attempts are exhausted, the message is marked as `failed` in the queue.

The retry loop runs every 30 seconds, processing up to 50 pending messages per cycle.

## Troubleshooting

### "Federation not enabled" (501)

The remote relay has `UAM_FEDERATION_ENABLED=false`. Contact the relay operator.

### "Source relay is blocked" (403)

Your relay's domain is on the remote relay's blocklist. Contact the remote operator.

### "Federation rate limit exceeded" (429)

Your relay is sending too many messages to the remote relay. This can happen if:

- Your relay's reputation score on the remote is low
- You're exceeding the per-relay rate limit

Wait and retry, or contact the remote operator to be added to their allowlist.

### "Invalid relay signature" (401)

Signature verification failed. Common causes:

1. **Key rotation** -- The remote relay cached your old public key. The relay will automatically re-fetch your `.well-known` on signature failure (one retry). If this persists, the remote relay's key cache may be stale.

2. **Clock drift** -- While the signature itself doesn't expire, timestamp validation may be affected. Ensure NTP is running.

3. **Man-in-the-middle** -- Someone modified the request in transit. Ensure HTTPS is used for all federation endpoints.

### "Hop count exceeds maximum" (400)

The message has been forwarded through too many relays. Default maximum is 3 hops (`UAM_FEDERATION_MAX_HOPS`). This usually indicates a routing loop or misconfigured relay chain.

### "Loop detected" (400)

Your relay's domain appears in the `via` chain, meaning the message has already passed through your relay. This is normal loop prevention behavior. The message is correctly rejected to prevent infinite forwarding.

### DNS SRV Not Resolving

1. **Record not created** -- Verify with `dig _uam._tcp.yourdomain.com SRV`
2. **DNS propagation** -- SRV records can take up to 48 hours to propagate, though typically 5-30 minutes
3. **Firewall** -- Ensure your DNS server allows SRV queries
4. **Fallback working** -- Even without SRV, `.well-known` fallback should work if your relay is accessible via HTTPS on the domain

### Key File Issues

- **Permission denied** -- `chmod 600 relay_key.pem` and ensure the relay process user owns the file
- **File not found** -- Check `UAM_RELAY_KEY_PATH` points to the correct location
- **Regenerating** -- Delete the key file and restart the relay to generate a new keypair. **Warning:** This changes your relay's identity -- other relays will see a signature mismatch until they re-discover your new key.

---

*For the complete environment variable reference, see [Configuration](configuration.md).*
*For the operator deployment guide, see [Operator Guide](operator-guide.md).*

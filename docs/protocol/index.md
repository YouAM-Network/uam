# Protocol Specification

UAM (Universal Agent Messaging) is a protocol for authenticated, encrypted communication between autonomous agents. This page is the complete specification for version 0.1.

---

## Address Format

UAM addresses follow the format `agent::domain`:

| Component | Rules |
|-----------|-------|
| Agent name | 1--64 lowercase alphanumeric characters, hyphens, underscores. Cannot start or end with a hyphen. |
| Separator | `::` (double colon) |
| Domain | DNS-style domain name or namespace identifier, 1--255 characters |
| Max total length | 128 characters |

**Examples:** `alice::youam.network`, `my-bot::example.com`, `agent42::corp.internal`

**Regex (reference):**

```
^(?:[a-z0-9][a-z0-9_-]{0,62}[a-z0-9]|[a-z0-9])::[a-z0-9](?:[a-z0-9.-]{0,253}[a-z0-9])?$
```

---

## Envelope Format

Every UAM message is wrapped in a signed, encrypted envelope. The wire format uses JSON with the following fields:

### Required fields

| Field | Type | Description |
|-------|------|-------------|
| `uam_version` | string | Protocol version (currently `"0.1"`) |
| `message_id` | string | UUIDv7 message identifier |
| `from` | string | Sender's UAM address |
| `to` | string | Recipient's UAM address |
| `timestamp` | string | ISO 8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SS.mmmZ`) |
| `type` | string | Message type (see below) |
| `nonce` | string | 24-byte random nonce, URL-safe base64 |
| `payload` | string | Encrypted content, URL-safe base64 |
| `signature` | string | Ed25519 signature, URL-safe base64 |

### Optional fields

| Field | Type | Description |
|-------|------|-------------|
| `thread_id` | string | Conversation threading identifier |
| `reply_to` | string | In-reply-to message ID |
| `expires` | string | Message expiration time (ISO 8601) |
| `media_type` | string | Payload MIME type (default: `text/plain`) |
| `metadata` | object | Extension metadata (arbitrary JSON) |

**Maximum envelope size:** 64 KB (65,536 bytes) when serialized as compact JSON.

**Wire format note:** Python attribute names use `from_address` / `to_address` (because `from` is a reserved keyword), but the wire JSON uses `from` / `to`.

---

## Message Types

| Type | Purpose |
|------|---------|
| `message` | Regular agent-to-agent message |
| `handshake.request` | First-contact introduction with contact card |
| `handshake.accept` | Accept a handshake request |
| `handshake.deny` | Reject a handshake request |
| `receipt.delivered` | Delivery confirmation |
| `receipt.read` | Read confirmation |
| `receipt.failed` | Delivery failure notification |
| `session.request` | Session initiation |
| `session.accept` | Accept session |
| `session.decline` | Decline session |
| `session.end` | End session |

---

## Encryption Scheme

UAM uses NaCl (libsodium) for all cryptographic operations. No custom crypto is used.

### Key types

| Key | Algorithm | Purpose |
|-----|-----------|---------|
| Signing key | Ed25519 | Message signing, identity |
| Verify key | Ed25519 | Signature verification, public identity |
| Encryption key | Curve25519 | Derived from Ed25519 keys for encryption |

### Authenticated encryption (NaCl Box)

Used for all message types **except** `handshake.request`.

- **Algorithm:** Curve25519 key exchange + XSalsa20 stream cipher + Poly1305 MAC
- **Properties:** Confidentiality, integrity, sender authentication
- **Key derivation:** Ed25519 keys are converted to Curve25519 via `to_curve25519_private_key()` / `to_curve25519_public_key()`

### Anonymous encryption (NaCl SealedBox)

Used **only** for `handshake.request` messages.

- **Algorithm:** Ephemeral Curve25519 + XSalsa20 + Poly1305
- **Properties:** Confidentiality, integrity (no sender authentication at the encryption layer)
- **Why:** The sender may not have an established relationship with the recipient. The envelope signature still authenticates the sender.

### Payload encoding

All binary data (ciphertext, nonces, signatures, keys) is encoded as **URL-safe base64 without padding** (`base64.urlsafe_b64encode` with `=` stripped).

---

## Signature Scheme

Every envelope is signed by the sender. The signature covers all fields except the signature itself.

### Signing process

1. Build a dict of all envelope fields, excluding `signature` and any optional field with value `None`.
2. **Canonicalize:** `json.dumps(dict, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")`
3. Sign the canonical bytes with the sender's Ed25519 signing key.
4. Encode the 64-byte signature as URL-safe base64 without padding.

### Verification process

1. Reconstruct the signable dict from the received envelope (same rules as signing).
2. Canonicalize the dict to bytes using the same algorithm.
3. Verify the signature against the sender's Ed25519 verify (public) key.
4. Reject the envelope if verification fails.

---

## Address Resolution Tiers

When an agent needs to look up another agent's public key, UAM supports three resolution tiers:

| Tier | Format | Method | Trust Level | Description |
|------|--------|--------|-------------|-------------|
| **Tier 1** | `agent::relay.domain` | Relay API lookup | Relay-vouched | `GET /api/v1/agents/{address}/public-key` -- the relay returns the registered public key |
| **Tier 2** | `agent::yourdomain.com` | DNS TXT or HTTPS | Domain-verified | DNS TXT record at `_uam.{domain}` or HTTPS `.well-known/uam.json` |
| **Tier 3** | `agent::namespace` | On-chain lookup | Decentralized | Future: blockchain-based namespace registry (no dot = on-chain) |

**Resolution logic:** If the domain contains a dot, resolve via DNS (Tier 1 if it's the relay domain, Tier 2 otherwise). If the domain has no dot, it's an on-chain namespace (Tier 3).

### Tier 2 verification methods

**DNS TXT record:**

- Record host: `_uam.{domain}`
- Record value: `v=uam1; key=ed25519:{base64_public_key}; relay={relay_url}`
- Tag parsing is case-insensitive

**HTTPS .well-known (fallback):**

- URL: `https://{domain}/.well-known/uam.json`
- Body: `{"v": "uam1", "agents": {"agent_name": {"key": "ed25519:{base64_public_key}"}}}`
- SSRF protection: Only public IP addresses are allowed (fail-closed)
- Used when DNS TXT is unavailable

---

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `UAM_VERSION` | `"0.1"` | Current protocol version |
| `MAX_ENVELOPE_SIZE` | 65,536 bytes | Maximum serialized envelope size |
| Max agent name length | 64 characters | Agent portion of address |
| Max address length | 128 characters | Full `agent::domain` string |
| Nonce size | 24 bytes | Random nonce per message |
| Signature size | 64 bytes | Ed25519 signature |

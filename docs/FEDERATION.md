# UAM Federation Protocol

Relay-to-relay forwarding for cross-domain agent messaging.

## Overview

UAM federation lets an agent on `alice::relay-a.com` send messages to an
agent on `bob::relay-b.com` without either user installing software for
both relays. The originating relay forwards the envelope to the destination
relay over an authenticated, replay-protected channel.

The reference implementation lives in:

- `src/uam/relay/federation.py` — outbound `FederationService` (forward + retry)
- `src/uam/relay/routes/federation.py` — inbound `POST /api/v1/federation/deliver`
- `src/uam/relay/peer_key_cache.py` — peer signing-key resolution + caching
- `src/uam/relay/relay_auth.py` — `verify_federation_signature`

## Discovery

A relay advertises its federation endpoint via the `.well-known` document:

```
GET /.well-known/uam-relay
-> { "federation_endpoint": "https://relay-b.com/api/v1/federation/deliver",
     "supported_major_versions": ["0"], ... }
```

Originating relays cache this descriptor for routing decisions and warm the
PeerKeyCache from the document's signing-key field on first contact.

## Forwarding Protocol

### Request shape

`POST /api/v1/federation/deliver`

Body (`FederationDeliverRequest` in `src/uam/relay/routes/federation.py`):

```
{
  "from_relay":   "<source relay domain>",
  "timestamp":    "<RFC 3339 UTC>",
  "nonce":        "<base64, 16 random bytes>",
  "hop_count":    <int, monotonically increasing per hop>,
  "via":          ["relay-a.com", "relay-mid.com"],   // loop-prevention chain
  "envelope":     { ... signed UAM envelope, verbatim ... },
  "signature":    "<base64 Ed25519 sig over canonical body>"
}
```

The `signature` field signs the canonical JSON of the body MINUS the signature
field itself, using the **source relay's** Ed25519 signing key. See
`verify_federation_signature` in `src/uam/relay/relay_auth.py`.

### Validation order (recipient side)

`federation_deliver` in `src/uam/relay/routes/federation.py` runs the
following pipeline in cheap-checks-first order to keep DoS surface small:

1. **Federation enabled.** If the local relay has federation disabled, return
   HTTP 501.
2. **Parse request fields** (Pydantic model validation).
3. **Timestamp freshness.** Reject if outside the configured tolerance window.
4. **Loop prevention.** Reject if `hop_count` exceeds the per-relay cap OR if
   this relay's domain already appears in `via`.
5. **Destination domain verification.** Reject if the envelope's recipient
   domain isn't served by this relay.
6. **Relay signature verification.** Ed25519 verify against the cached
   signing key for `from_relay`; on key-rotation failures, re-fetch the key
   from the source's `.well-known` and retry once.
7. **Federation nonce dedup (Phase 45 T3.2).** Cheap INSERT into
   `federation_nonces (from_relay, nonce, seen_at)`. Conflict means replay
   and the request is rejected. Placed AFTER cheap checks so stale-timestamp
   DoS can't fill the table; placed BEFORE the expensive crypto verify so
   attackers can't burn recipient CPU replaying a signed body.
8. **Agent envelope signature verification.** Re-resolve the sender's
   verify_key via PeerKeyCache (see below) — the envelope-supplied
   `sender_key` is **never** trusted for verification.
9. **Envelope-level dedup** by `message_id`.
10. **Deliver.** WebSocket if connected, then webhook fallback, then
    store-and-forward.
11. **Audit.** Append to `federation_log`.

## Replay Protection (Phase 45)

The `federation_nonces` table records every accepted
`(from_relay, nonce, seen_at)` tuple. The `(from_relay, nonce)` pair is the
primary key, so a duplicate INSERT raises and the replay is rejected at
step 7 above.

Phase 48 Q5 (`src/uam/relay/retention.py`) adds an env-tunable retention
sweep that prunes nonces older than `UAM_RETENTION_FED_NONCE_HOURS`
(default 1 hour). The pre-existing `_federation_nonce_sweep_loop` (default
600s interval, 600s max-age) remains as a stricter inner loop and is
unchanged.

## Peer-Key Resolution (Phase 43-03)

`PeerKeyCache` (`src/uam/relay/peer_key_cache.py`) holds
`(sender_address -> verify_key)` entries with a TTL. On cache miss, the
recipient relay fetches the key from the **sender's home relay**
`.well-known` document.

The envelope's `sender_key` field is **IGNORED for trust purposes**
(`_resolve_remote_sender_key` in `routes/federation.py`, lines 220-275).
This closes the T1.4 impersonation bypass: an attacker who controls a
malicious peer relay cannot forge a sender key by stuffing it into the
envelope, because the recipient always re-resolves from the sender's home.

A `sender_key` field IS still inspected as a cross-check: if present and it
disagrees with the home-relay-resolved key, the request is rejected with
HTTP 400 and a `T1.4: envelope sender_key mismatch` log entry.

## SSRF Protection (Phase 45)

Outbound federation HTTP enforces:

- `is_public_ip` guard on every URL (refuse RFC 1918 / link-local / loopback)
- Redirects re-checked against the same guard (no redirect-to-private bypass)
- Strict timeout per request
- Pinned-URL builder (`build_pinned_url`, `resolve_pinned`,
  `validate_outbound_target` in `src/uam/relay/ssrf.py`)

## Loop Prevention

`via` is an ordered list of every relay that handled the envelope. Every
forwarder appends its own domain. `hop_count` is incremented on each forward.
A recipient rejects if its own domain already appears in `via` (immediate
loop) or if `hop_count` exceeds the cap (large transitive loop).

## Version Negotiation (Phase 48 Q4)

`from_wire_dict` calls `check_version()` (from
`src/uam/protocol/versioning.py`) BEFORE the required-fields shape check, so
unknown-MAJOR rejection fires even for malformed bodies. Unknown MAJOR raises
`IncompatibleVersionError` -> HTTP 400 `{"error": "incompatible_version"}`.

Peer relays SHOULD probe `GET /api/v1/versions` before initiating federation.
The response shape is documented in `docs/FORWARD_COMPAT.md`.

## Operational Notes

- **Drain (Phase 48 Q7).** During graceful shutdown the relay broadcasts a
  drain notice; in-flight federation requests still complete, but new
  inbound requests get 503 + `Retry-After: UAM_DRAIN_SECONDS`. The
  originating relay's `FederationService` then queues the envelope for retry.
- **Webhook fallback.** If WS delivery to the destination agent fails, the
  recipient relay attempts webhook delivery. Webhook bodies are signed with
  `token_hash` (Phase 47-08) so replay against a leaked webhook URL is
  cryptographically detectable.
- **Federation log retention.** `federation_log` rows currently fall under
  the existing 90-day catch-all (`purge_expired`). A per-category sweep can
  be layered on later via the same pattern as Q5's retention module.

## See Also

- `docs/spec-v7.md` — full wire-protocol specification
- `docs/FORWARD_COMPAT.md` — version-negotiation policy + Phase 48 env vars
- `.planning/phases/43-*` — peer-key resolution hardening (T1.4 fix)
- `.planning/phases/45-*` — replay + SSRF protection
- `.planning/phases/48-*` — version negotiation + retention sweep

# UAM Forward-Compatibility Policy

Phase 48 (v1.5 milestone closer) formalizes the protocol's forward-compat
contract for wire format, contact-card lifecycle, and operator-tunable
runtime windows.

## Version Negotiation

Wire format: every envelope carries a `uam_version` field.
Format: `MAJOR.MINOR`. Current value: `0.1`.

Reference implementation: `src/uam/protocol/versioning.py`.

### Major version policy

- Implementations REJECT envelopes with unknown MAJOR.
- Rejection raises `IncompatibleVersionError`, which the central FastAPI
  handler from Phase 48 Q1 maps to HTTP 400 with body
  `{"error": "incompatible_version"}`.
- Today, only major `0` is supported
  (`SUPPORTED_MAJOR_VERSIONS = ("0",)` in `versioning.py`).

### Minor version policy

- Implementations ACCEPT envelopes with unknown MINOR.
- Unknown FIELDS within an envelope MUST be treated as opaque pass-through:
  preserved on relay/forward, ignored on parse.
- This is the additive forward-compat lane: peers running `0.99` interoperate
  with peers running `0.1` without code changes, as long as new fields are
  additive and signed.

### Discovery

`GET /api/v1/versions` (no auth) returns:

```json
{
  "uam_version": "0.1",
  "supported_major_versions": ["0"]
}
```

Peer relays SHOULD probe this endpoint before initiating federation. The
endpoint lives on the existing health router
(`src/uam/relay/routes/health.py`) — no separate router is added so the
router count stays manageable.

### Cutover strategy (v0.x → v1.0)

When the codebase is ready to ship `1.0`:

1. **Bridging window.** Append `"1"` to `SUPPORTED_MAJOR_VERSIONS` so the
   tuple becomes `("0", "1")`. Both majors are accepted on the wire while
   peers upgrade.
2. **Cutover signal.** Monitor incoming envelope versions via the existing
   logging path (peer-relay version is in the envelope and visible in
   request logs once Phase 48 Q6's `RequestIDMiddleware` ships).
3. **Drop window.** When the v0.x peer-traffic share crosses below an agreed
   threshold (recommended: `<5%` over a rolling 30-day window), drop `"0"`
   from the tuple in a single PR. The hard-cutover failure mode is
   `IncompatibleVersionError` with `supported = ("1",)` — peer relays see
   this in `GET /api/v1/versions` and surface a clear upgrade message.
4. **Bump `UAM_VERSION` constant** in `src/uam/protocol/types.py`. The
   `/api/v1/versions` endpoint reflects this automatically because it reads
   from the same constant.
5. **Test contract.** `tests/test_versioning.py` will need updating to test
   `"1"` instead of (or alongside) `"0"`.
6. **Bridging window minimum.** Recommended: ≥3 months. Document the cutover
   in `CHANGELOG.md` before flipping any production relay.

## Contact Card Expiry (Phase 48 Q2)

`ContactCard.not_after` (ISO-8601 UTC) is OPTIONAL on the wire today.

### Transitional behavior

- Cards WITHOUT `not_after`: treated as `imported_at + 365d`. A WARNING log
  is emitted on first encounter as an "upgrade pressure" signal so operators
  can re-issue with explicit expiries before the v2.0 strict-cutover.
- Cards WITH `not_after`: enforced strictly. `not_after` is in signing scope
  (`_build_signable_dict`), so attackers cannot extend a captured card's
  expiry without re-signing — and they don't have the original signing key.

### Migration path for existing cards

1. **v1.5** (current): Cards may omit `not_after` (transitional, WARN log).
2. **v1.6**: WARNING log promoted to ERROR (still accepted).
3. **v2.0**: Cards REQUIRE `not_after`; cards without it are rejected at
   import time.

Operators should re-issue cards with explicit `not_after` before v2.0.

## Phase 48 Environment Variables

All new env vars are additive with safe defaults. None of them break
existing deploys.

| Env Var                            | Default | Effect                                                    | Plan  |
|------------------------------------|---------|-----------------------------------------------------------|-------|
| `UAM_LOG_FORMAT`                   | (unset) | Plain logs; set to `json` for structured access logs      | 48-05 |
| `UAM_DRAIN_SECONDS`                | 15      | Graceful drain window in seconds                          | 48-06 |
| `UAM_RETENTION_DELIVERED_DAYS`     | 1       | Delivered-message retention window (days)                 | 48-04 |
| `UAM_RETENTION_UNDELIVERED_DAYS`   | 7       | Undelivered-message retention window (days)               | 48-04 |
| `UAM_RETENTION_FED_NONCE_HOURS`    | 1       | Federation-nonce retention window (hours)                 | 48-04 |
| `UAM_RETENTION_DEMO_HOURS`         | 1       | Demo-session retention window (hours, forward-compat)     | 48-04 |
| `UAM_RETENTION_CHALLENGE_MINUTES`  | 5       | Auth-challenge retention window (minutes, forward-compat) | 48-04 |
| `UAM_LANDING_ENV`                  | (unset) | Set to `demo` to enable `/api/demo/*` routes in landing   | 48-09 |

### Retention tuning hazards

| Env var                            | Stricter (smaller) value risk                                                                              | Looser (larger) value risk                                |
|------------------------------------|------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------|
| `UAM_RETENTION_DELIVERED_DAYS`     | Aggressive prune of recently delivered messages — operators relying on delivered-message inspection lose visibility | Disk growth: delivered envelopes accumulate              |
| `UAM_RETENTION_UNDELIVERED_DAYS`   | Inboxes for offline agents lose messages they never received                                              | Quotas could fill with stale undelivered messages         |
| `UAM_RETENTION_FED_NONCE_HOURS`    | Federation replay window narrows; a slow relay-to-relay path could replay nonces beyond the window         | Larger `federation_nonces` table; storage cost only       |
| `UAM_RETENTION_DEMO_HOURS`         | (no-op today; forward-compat placeholder)                                                                  | (no-op today; forward-compat placeholder)                 |
| `UAM_RETENTION_CHALLENGE_MINUTES`  | (no-op today; forward-compat placeholder)                                                                  | (no-op today; forward-compat placeholder)                 |

Setting any retention var to `0` prunes everything older than `now`.
Documented as an "operator hazard" — the safe default behavior is preserved
by `_int_env` parsing (which falls back to the default + WARN log on
non-integer input) but does not clamp `0` upward.

## Operational Requirements

### Uvicorn graceful timeout

Phase 48 Q7 (drain) assumes `uvicorn --graceful-timeout >= UAM_DRAIN_SECONDS`.
Recommended: set `--graceful-timeout` to `UAM_DRAIN_SECONDS + 5` (default
20s) so the drain notice broadcast plus the sleep window completes BEFORE
uvicorn forces socket close. Without this, in-flight federation forwards
risk being severed mid-request and surfacing as transient delivery failures
on the originating relay.

### Logging in production

`UAM_LOG_FORMAT=json` is recommended for production deploys (Datadog, Loki,
ELK ingestion). Plain logs remain the default for backward compat with
existing deploy scripts that grep human-readable logs.

### Landing demo gating

The landing app ships with `UAM_LANDING_ENV` unset by default. Set it to
`demo` ONLY on the public demo deploy. Production `youam.network` deploys
**MUST NOT** set `UAM_LANDING_ENV=demo` — `landing/middleware.ts` returns
HTTP 404 for `/api/demo/*` routes when the var is unset, hiding the
existence of the demo endpoints from production traffic.

If `UAM_LANDING_ENV=demo` leaks into a production environment, demo APIs
become publicly callable. Treat the env var with the same care as a
secret-flag toggle.

### Federation drain coordination

When draining a relay (Q7), the originating relay's `FederationService`
treats 503 + Retry-After responses as transient and queues for retry. No
operator action is required for graceful shutdown; just ensure the
graceful-timeout above is set correctly.

## Deferred to v1.6+

- **Federation v2** — multi-major-version negotiation in a single envelope,
  full peer-key revocation lifecycle, signed `.well-known` rotation manifests
- **TOFU UI** — landing-page contact verification flow (visual key
  fingerprint, optional notarization)
- **GDPR controls** — data deletion API, right-to-be-forgotten, audit-log
  redaction
- **Unify `RegistrarError`** with the `UAMError` hierarchy (Q1 currently
  scopes the unification to relay + protocol + SDK)
- **KMS / cloud secret manager integration** for the custodial Eth key
- **Tighter CSP** for the landing page — replace `script-src 'unsafe-inline'`
  with per-render nonces (current v1.5 ceiling documented in `48-09`'s
  threat model)

## See Also

- `docs/FEDERATION.md` — federation protocol
- `docs/spec-v7.md` — full wire spec
- `src/uam/protocol/versioning.py` — version negotiation source of truth
- `src/uam/relay/retention.py` — retention sweep + env-var bindings
- `.planning/phases/48-*` — Phase 48 plans for each Q-fix

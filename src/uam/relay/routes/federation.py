"""Federation routes -- inbound delivery and relay identity.

POST /api/v1/federation/deliver  -- accept inbound federated envelopes
GET  /.well-known/uam-relay.json -- advertise this relay's identity
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud.agents import get_agent_by_address
from uam.db.crud.dedup import record_message_id
from uam.db.crud.federation import get_known_relay, log_federation, upsert_known_relay
from uam.db.crud.messages import store_message
from uam.db.session import get_session
from uam.protocol import (
    InvalidEnvelopeError,
    SignatureVerificationError,
    deserialize_verify_key,
    from_wire_dict,
    serialize_verify_key,
    verify_envelope,
)
from uam.relay.models import (
    FederationDeliverRequest,
    FederationDeliverResponse,
    WellKnownRelayResponse,
)
from uam.relay.peer_key_cache import peer_key_cache
from uam.relay.relay_auth import verify_federation_signature

logger = logging.getLogger(__name__)

router = APIRouter()

# Separate router for /.well-known (mounted WITHOUT /api/v1 prefix)
well_known_router = APIRouter()


@router.post("/federation/deliver", response_model=FederationDeliverResponse)
async def federation_deliver(
    body: FederationDeliverRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> FederationDeliverResponse:
    """Accept an inbound federated envelope from a remote relay.

    Validation order (DoS-resistant, cheapest checks first):
    1.  Federation enabled check
    2.  Parse request fields
    3.  Timestamp freshness
    4.  Loop prevention (hop_count + via chain)
    5.  Destination domain verification
    6.  Relay signature verification (with key rotation retry)
    7.  Agent envelope signature verification
    8.  Dedup check
    9.  Deliver (WebSocket > webhook > store)
    10. Log to federation_log
    """
    manager = request.app.state.manager
    settings = request.app.state.settings

    # ---- Step 1: Federation enabled check ----
    if not settings.federation_enabled:
        raise HTTPException(status_code=501, detail="Federation not enabled")

    # ---- Step 2: Parse request fields ----
    from_relay = body.from_relay
    timestamp = body.timestamp
    hop_count = body.hop_count
    via = body.via
    envelope_dict = body.envelope

    # Relay blocklist check (FED-07) -- O(1), before everything else
    relay_blocklist = getattr(request.app.state, "relay_blocklist", None)
    if relay_blocklist and relay_blocklist.is_blocked(from_relay):
        envelope_msg_id = envelope_dict.get("message_id", "")
        await log_federation(session, envelope_msg_id, from_relay, settings.relay_domain, "inbound", hop_count, "rejected", "blocklisted")
        raise HTTPException(status_code=403, detail="Source relay is blocked")

    # Relay allowlist check (FED-07) -- sets skip flag for reputation-based limits
    relay_allowlisted = False
    if relay_blocklist and relay_blocklist.is_allowed(from_relay):
        relay_allowlisted = True

    # Per-source-relay rate limit (FED-06) -- before expensive validation
    if not relay_allowlisted:
        relay_reputation = getattr(request.app.state, "relay_reputation", None)
        federation_limiter = getattr(request.app.state, "federation_limiter", None)
        if relay_reputation and federation_limiter:
            relay_limit = relay_reputation.get_rate_limit(from_relay)
            if relay_limit == 0:
                raise HTTPException(status_code=403, detail="Source relay reputation too low")
            if not await federation_limiter.check(from_relay, limit=relay_limit):
                raise HTTPException(status_code=429, detail="Federation rate limit exceeded")

    # Resolve relay_reputation once for use in validation and success/failure recording
    relay_reputation = getattr(request.app.state, "relay_reputation", None)

    # Wrap core validation in try/except for reputation tracking (FED-08)
    try:
        # ---- Step 3: Timestamp freshness (FED-05) ----
        try:
            request_ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            age_seconds = abs((now - request_ts).total_seconds())
            if age_seconds > settings.federation_timestamp_max_age:
                raise HTTPException(
                    status_code=400,
                    detail=f"Federation request too old ({int(age_seconds)}s > {settings.federation_timestamp_max_age}s)",
                )
        except ValueError as exc:
            raise HTTPException(
                status_code=400, detail=f"Invalid timestamp format: {exc}"
            ) from exc

        # ---- Step 4: Loop prevention (FED-04) ----
        if hop_count >= settings.federation_max_hops:
            raise HTTPException(
                status_code=400,
                detail=f"Hop count {hop_count} exceeds maximum {settings.federation_max_hops}",
            )
        if settings.relay_domain in via:
            raise HTTPException(
                status_code=400,
                detail=f"Loop detected: {settings.relay_domain} already in via chain {via}",
            )

        # ---- Step 5: Destination domain verification (FED-05) ----
        to_address = envelope_dict.get("to", "")
        if "::" not in to_address:
            raise HTTPException(
                status_code=400, detail="Invalid to_address in envelope"
            )
        recipient_domain = to_address.split("::")[1]
        if recipient_domain != settings.relay_domain:
            raise HTTPException(
                status_code=400,
                detail=f"Destination domain mismatch: envelope to '{recipient_domain}' but this relay is '{settings.relay_domain}'",
            )

        # ---- Step 6: Relay signature verification (FED-03) ----
        signature_header = request.headers.get("X-UAM-Relay-Signature")
        if not signature_header:
            raise HTTPException(
                status_code=401, detail="Missing X-UAM-Relay-Signature header"
            )

        # Build the dict that was signed (must match what the sender signed)
        verify_dict = {
            "envelope": body.envelope,
            "via": body.via,
            "hop_count": body.hop_count,
            "timestamp": body.timestamp,
            "from_relay": body.from_relay,
        }

        relay_public_key = await _get_relay_public_key(session, from_relay)

        sig_valid = False
        if relay_public_key:
            sig_valid = verify_federation_signature(
                verify_dict, signature_header, relay_public_key
            )

        # Key rotation retry: re-discover and try once more
        if not sig_valid:
            fresh_key = await _rediscover_relay_key(session, from_relay)
            if fresh_key and fresh_key != relay_public_key:
                sig_valid = verify_federation_signature(
                    verify_dict, signature_header, fresh_key
                )

        if not sig_valid:
            raise HTTPException(
                status_code=401, detail="Invalid relay signature"
            )

        # ---- Step 7: Agent envelope signature verification (T1.4) ----
        #
        # We MUST resolve the sender's verify key authoritatively, NOT trust
        # the envelope-supplied ``sender_key`` field. For local senders the
        # DB is authoritative; for remote senders we look up the key on the
        # sender's home relay (cached for ``UAM_FEDERATION_PEER_KEY_TTL`` s).
        # If the envelope embeds a ``sender_key`` and it disagrees with the
        # authoritative record, reject with 403 — that is the federation
        # impersonation attack T1.4 closes.
        try:
            envelope = from_wire_dict(envelope_dict)
        except InvalidEnvelopeError as exc:
            raise HTTPException(
                status_code=400, detail=f"Invalid envelope: {exc}"
            ) from exc

        sender_key_envelope = envelope_dict.get("sender_key")  # cross-check only
        sender_agent = await get_agent_by_address(session, envelope.from_address)
        if sender_agent is not None:
            # Local sender — DB is authoritative
            authoritative_key = sender_agent.public_key
        else:
            # Remote sender — resolve via the sender's home relay
            federation_service = getattr(
                request.app.state, "federation_service", None
            )
            if federation_service is None:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"Cannot resolve sender key for {envelope.from_address!r}: "
                        "federation service unavailable"
                    ),
                )
            authoritative_key = await _resolve_remote_sender_key(
                session, envelope.from_address, federation_service, settings
            )
            if authoritative_key is None:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"Cannot resolve sender key for {envelope.from_address!r}: "
                        "home relay unreachable or sender unknown"
                    ),
                )

        # Cross-check: if envelope embedded a sender_key, it MUST match the
        # authoritative one. This is the federation-impersonation guard.
        if sender_key_envelope and sender_key_envelope != authoritative_key:
            logger.warning(
                "T1.4: envelope sender_key mismatch for %s "
                "(envelope=%s..., authoritative=%s...)",
                envelope.from_address,
                sender_key_envelope[:16],
                authoritative_key[:16],
            )
            raise HTTPException(
                status_code=403,
                detail="Envelope sender_key does not match home-relay record",
            )

        # Verify the envelope signature against the AUTHORITATIVE key
        try:
            sender_vk = deserialize_verify_key(authoritative_key)
            verify_envelope(envelope, sender_vk)
        except SignatureVerificationError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid agent envelope signature: {exc}",
            ) from exc

        # ---- Step 8: Dedup check ----
        is_new = await record_message_id(session, envelope.message_id, envelope.from_address, commit=False)
        if not is_new:
            return FederationDeliverResponse(status="duplicate", detail="Message already delivered")

    except HTTPException:
        # Record reputation failure for the source relay (FED-08)
        if relay_reputation:
            await relay_reputation.record_failure(from_relay, "validation_error")
        raise

    # --- Transaction-wrapped DB section (RES-01) ---
    # dedup (flushed above) + store + federation log in a single commit.
    try:
        # ---- Step 9: Deliver (WebSocket > webhook > store) ----
        delivered = await manager.send_to(envelope.to_address, envelope_dict)
        delivery_method = "websocket" if delivered else None

        if not delivered:
            # Try webhook
            webhook_service = request.app.state.webhook_service
            webhook_initiated = await webhook_service.try_deliver(
                envelope.to_address, envelope_dict
            )
            if webhook_initiated:
                delivery_method = "webhook"
                delivered = True

        if delivery_method is None:
            # Store for later pickup
            await store_message(
                session,
                envelope.message_id,
                envelope.from_address,
                envelope.to_address,
                json.dumps(envelope_dict),
                commit=False,
            )
            delivery_method = "stored"

        # ---- Step 10: Log to federation_log ----
        await log_federation(
            session,
            envelope.message_id,
            from_relay,
            settings.relay_domain,
            "inbound",
            hop_count,
            "delivered",
            commit=False,
        )

        # Single commit for dedup + store + federation log
        await session.commit()

    except Exception:
        await session.rollback()
        raise

    # Update relay reputation on success (FED-08)
    if relay_reputation:
        await relay_reputation.record_success(from_relay)

    return FederationDeliverResponse(status="delivered")


@well_known_router.get(
    "/.well-known/uam-relay.json",
    response_model=WellKnownRelayResponse,
)
async def well_known_relay(request: Request) -> WellKnownRelayResponse:
    """Serve this relay's identity for federation discovery."""
    settings = request.app.state.settings
    relay_verify_key = request.app.state.relay_verify_key
    return WellKnownRelayResponse(
        relay_domain=settings.relay_domain,
        federation_endpoint=f"{settings.relay_http_url}/api/v1/federation/deliver",
        public_key=serialize_verify_key(relay_verify_key),
        version="0.1",
    )


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


async def _get_relay_public_key(session: AsyncSession, from_relay: str) -> str | None:
    """Look up a relay's public key from the known_relays cache."""
    cached = await get_known_relay(session, from_relay)
    if cached:
        return cached.public_key
    return None


async def _rediscover_relay_key(session: AsyncSession, from_relay: str) -> str | None:
    """Fetch the relay's .well-known to get a fresh public key (key rotation)."""
    url = f"https://{from_relay}/.well-known/uam-relay.json"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
            public_key = data.get("public_key")
            federation_endpoint = data.get("federation_endpoint")
            if public_key and federation_endpoint:
                await upsert_known_relay(
                    session, from_relay, federation_endpoint, public_key, "well-known"
                )
                return public_key
    except Exception:
        logger.debug(
            "Failed to re-discover relay key for %s", from_relay, exc_info=True
        )
    return None


async def _resolve_remote_sender_key(
    session: AsyncSession,
    sender_address: str,
    federation_service,  # noqa: ANN001 — FederationService, avoid import cycle
    settings,  # noqa: ANN001 — Settings, avoid import cycle
) -> str | None:
    """T1.4: resolve a non-local sender's verify key via its HOME relay.

    Calls ``GET {home_relay}/api/v1/agents/{sender_address}/public-key`` (which
    is the same unauthenticated endpoint a fresh-handshake client would use)
    and caches successful resolutions in :data:`peer_key_cache` for
    ``settings.federation_peer_key_ttl`` seconds.

    Returns the public_key (b64) on success; ``None`` on any failure
    (home relay unreachable, agent unknown, network error, malformed response).

    Caller MUST treat ``None`` as a hard failure (HTTP 403). Falling back
    to the envelope-supplied ``sender_key`` is the impersonation bypass T1.4
    closes.

    Notes
    -----
    * Failed lookups are NOT cached — a transient outage at the home relay
      should not pin "no key" for ``ttl`` seconds.
    * The ``federation_service._client`` httpx pool is reused (per
      RESEARCH.md § Don't Build Your Own — do NOT instantiate a fresh client
      per call).
    * For senders whose ``domain == settings.relay_domain`` we return ``None``;
      the caller is expected to resolve via :func:`get_agent_by_address`
      before falling through to this helper.
    """
    cache_key = f"peer_agent_key:{sender_address}"
    cached = await peer_key_cache.get(cache_key)
    if cached:
        return cached

    if "::" not in sender_address:
        logger.warning("T1.4: malformed sender_address %r", sender_address)
        return None
    domain = sender_address.split("::", 1)[1]
    if domain == settings.relay_domain:
        # Local agent — caller should have used get_agent_by_address.
        return None

    relay = await federation_service.discover_relay(domain)
    if relay is None:
        logger.warning(
            "T1.4: cannot discover home relay for %s (domain=%s)",
            sender_address, domain,
        )
        return None

    federation_url = relay.get("federation_url")
    if not federation_url:
        logger.warning(
            "T1.4: home relay record for %s lacks federation_url: %r",
            domain, relay,
        )
        return None

    parsed = urlparse(federation_url)
    if not parsed.scheme or not parsed.netloc:
        logger.warning(
            "T1.4: home relay federation_url is malformed: %r", federation_url
        )
        return None
    base = f"{parsed.scheme}://{parsed.netloc}"
    url = f"{base}/api/v1/agents/{sender_address}/public-key"

    try:
        resp = await federation_service._client.get(url, timeout=10.0)
        resp.raise_for_status()
        data = resp.json()
        public_key = data.get("public_key")
        if public_key:
            await peer_key_cache.set(
                cache_key, public_key, ttl=settings.federation_peer_key_ttl
            )
            return public_key
        logger.warning(
            "T1.4: home relay %s returned no public_key for %s",
            base, sender_address,
        )
    except Exception:
        logger.warning(
            "T1.4: failed to resolve remote sender key for %s via %s",
            sender_address, url, exc_info=True,
        )
    return None

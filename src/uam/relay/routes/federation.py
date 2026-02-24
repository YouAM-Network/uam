"""Federation routes -- inbound delivery and relay identity.

POST /api/v1/federation/deliver  -- accept inbound federated envelopes
GET  /.well-known/uam-relay.json -- advertise this relay's identity
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

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
            if not federation_limiter.check(from_relay, limit=relay_limit):
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

        # ---- Step 7: Agent envelope signature verification ----
        try:
            envelope = from_wire_dict(envelope_dict)
        except InvalidEnvelopeError as exc:
            raise HTTPException(
                status_code=400, detail=f"Invalid envelope: {exc}"
            ) from exc

        # Get sender's verify key from the envelope wire dict
        sender_key_b64 = envelope_dict.get("sender_key")
        if sender_key_b64:
            try:
                sender_vk = deserialize_verify_key(sender_key_b64)
                verify_envelope(envelope, sender_vk)
            except SignatureVerificationError as exc:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid agent envelope signature: {exc}",
                ) from exc
        else:
            # Try looking up the sender locally (if registered on this relay)
            sender_agent = await get_agent_by_address(session, envelope.from_address)
            if sender_agent:
                try:
                    sender_vk = deserialize_verify_key(sender_agent.public_key)
                    verify_envelope(envelope, sender_vk)
                except SignatureVerificationError as exc:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid agent envelope signature: {exc}",
                    ) from exc
            # else: sender not local and no sender_key in envelope
            # The sending relay already verified the agent signature.
            # Log a warning but don't reject -- the relay signature is valid.
            else:
                logger.warning(
                    "Cannot re-verify agent signature for %s (no sender_key, sender not local)",
                    envelope.from_address,
                )

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

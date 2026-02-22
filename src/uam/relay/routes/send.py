"""POST /send -- message send endpoint (RELAY-02)."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request

from uam.protocol import (
    InvalidEnvelopeError,
    SignatureVerificationError,
    deserialize_verify_key,
    from_wire_dict,
    verify_envelope,
)
from uam.relay.auth import verify_token_http
from uam.relay.database import record_message_id, store_message
from uam.relay.models import SendRequest, SendResponse

logger = logging.getLogger(__name__)

# Grace period for clock skew when checking expiry (seconds)
_EXPIRY_GRACE_SECONDS = 30

router = APIRouter()


async def _queue_federation(db, target_domain: str, envelope_dict: dict, from_relay: str) -> None:  # noqa: ANN001
    """Queue a federation message for retry (FED-10)."""
    await db.execute(
        "INSERT INTO federation_queue (target_domain, envelope, via, hop_count) VALUES (?, ?, ?, ?)",
        (target_domain, json.dumps(envelope_dict), json.dumps([from_relay]), 1),
    )
    await db.commit()


@router.post("/send", response_model=SendResponse)
async def send_message(
    body: SendRequest,
    request: Request,
    agent: dict = Depends(verify_token_http),
) -> SendResponse:
    """Send a signed message envelope via REST.

    Order of operations (DoS-resistant):
    1.  Auth (via dependency injection -- already done)
    2.  Blocklist check (SPAM-01 -- O(1) set lookup)
    3.  Allowlist check (SPAM-01 -- O(1), sets skip_reputation flag)
    4.  Adaptive sender rate limit (SPAM-04 -- reputation-based limit)
    5.  Parse envelope
    6.  Sender identity match
    7.  Domain rate limit (SPAM-03 -- relay domain exempt)
    8.  Recipient rate limit (RELAY-05)
    9.  Reputation score check (SPAM-06 -- drop if score <20)
    10. Signature verification (expensive -- LAST)
    11. Route or store
    """
    db = request.app.state.db
    manager = request.app.state.manager
    sender_limiter = request.app.state.sender_limiter
    recipient_limiter = request.app.state.recipient_limiter
    spam_filter = request.app.state.spam_filter
    reputation_manager = request.app.state.reputation_manager
    domain_limiter = request.app.state.domain_limiter
    settings = request.app.state.settings

    # Receipt type detection -- check raw dict before full parsing (MSG-05)
    is_receipt = str(body.envelope.get("type", "")).startswith("receipt.")

    # Blocklist check (SPAM-01) -- O(1), before everything
    if spam_filter.is_blocked(agent["address"]):
        raise HTTPException(status_code=403, detail="Sender is blocked")

    # Allowlist check (SPAM-01) -- O(1), skip reputation-based limits
    is_allowlisted = spam_filter.is_allowed(agent["address"])

    # Adaptive sender rate limit (SPAM-04) -- receipt types exempt
    if is_receipt:
        pass  # receipts skip all rate limits and reputation checks
    elif not is_allowlisted:
        send_limit = reputation_manager.get_send_limit(agent["address"])
        if send_limit == 0:
            raise HTTPException(status_code=403, detail="Sender reputation too low")
        if not sender_limiter.check(agent["address"], limit=send_limit):
            raise HTTPException(status_code=429, detail="Sender rate limit exceeded")
    else:
        # Allowlisted senders use default (full) rate limit
        if not sender_limiter.check(agent["address"]):
            raise HTTPException(status_code=429, detail="Sender rate limit exceeded")

    # Parse envelope
    try:
        envelope = from_wire_dict(body.envelope)
    except InvalidEnvelopeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid envelope: {exc}") from exc

    # Verify sender identity matches
    if envelope.from_address != agent["address"]:
        raise HTTPException(
            status_code=403,
            detail=f"Sender mismatch: envelope from '{envelope.from_address}' but authenticated as '{agent['address']}'",
        )

    # Dedup check (MSG-03) -- before expensive delivery chain
    is_new = await record_message_id(db, envelope.message_id, agent["address"])
    if not is_new:
        # Silently accept duplicate -- idempotent for the sender
        return SendResponse(message_id=envelope.message_id, delivered=True)

    # Expiry check (MSG-04) -- reject if expires timestamp is in the past
    expires_str: str | None = envelope.expires
    if expires_str is not None:
        try:
            # Parse ISO 8601 timestamp (handle both "Z" and "+00:00" suffixes)
            exp_ts = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            if exp_ts + timedelta(seconds=_EXPIRY_GRACE_SECONDS) < now:
                raise HTTPException(status_code=400, detail="Message has expired")
        except (ValueError, TypeError):
            # Malformed expires = no expiry (don't reject)
            expires_str = None

    # Domain rate limit (SPAM-03) -- by sender domain, relay domain exempt; receipt types exempt
    if not is_receipt:
        sender_domain = agent["address"].split("::")[1] if "::" in agent["address"] else ""
        if sender_domain and sender_domain != settings.relay_domain and not is_allowlisted:
            if not domain_limiter.check(sender_domain):
                raise HTTPException(status_code=429, detail="Domain rate limit exceeded")

    # Rate limit: recipient (RELAY-05) -- receipt types exempt
    if not is_receipt and not recipient_limiter.check(envelope.to_address):
        raise HTTPException(status_code=429, detail="Recipient rate limit exceeded (100/min)")

    # Reputation check (SPAM-06) -- receipt types exempt
    if not is_receipt and not is_allowlisted:
        score = reputation_manager.get_score(agent["address"])
        if score < 20:
            raise HTTPException(status_code=403, detail="Sender reputation too low")

    # Verify signature (expensive -- only after cheap checks pass)
    try:
        sender_vk = deserialize_verify_key(agent["public_key"])
        verify_envelope(envelope, sender_vk)
    except SignatureVerificationError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid signature: {exc}") from exc

    # Three-tier delivery chain: WebSocket > webhook > store-and-forward (HOOK-02)
    # Tier 1: WebSocket (real-time)
    delivered = await manager.send_to(envelope.to_address, body.envelope)
    delivery_method = "websocket" if delivered else None

    if not delivered:
        # Tier 2: Webhook (near-real-time)
        webhook_service = request.app.state.webhook_service
        webhook_initiated = await webhook_service.try_deliver(
            envelope.to_address, body.envelope
        )
        if webhook_initiated:
            delivery_method = "webhook"
            delivered = True  # webhook delivery initiated (async)

    if delivery_method is None:
        # Step 12: Federation forwarding for non-local recipients (FED-01)
        recipient_domain = ""
        if "::" in envelope.to_address:
            recipient_domain = envelope.to_address.split("::")[1]

        if recipient_domain and recipient_domain != settings.relay_domain:
            # Non-local recipient -- forward via federation
            federation_service = getattr(request.app.state, "federation_service", None)
            if federation_service and settings.federation_enabled:
                fed_result = await federation_service.forward(
                    envelope_dict=body.envelope,
                    from_relay=settings.relay_domain,
                )
                if fed_result.delivered:
                    delivery_method = "federated"
                elif fed_result.queued:
                    delivery_method = "federation_queued"
                else:
                    # Federation failed -- queue for retry
                    await _queue_federation(
                        request.app.state.db,
                        recipient_domain,
                        body.envelope,
                        settings.relay_domain,
                    )
                    delivery_method = "federation_queued"
            else:
                # Federation not available -- store locally as fallback
                await store_message(
                    db, envelope.from_address, envelope.to_address,
                    json.dumps(body.envelope), expires=expires_str,
                )
                delivery_method = "stored"
        else:
            # Local recipient not online -- store for pickup
            await store_message(
                db, envelope.from_address, envelope.to_address,
                json.dumps(body.envelope), expires=expires_str,
            )
            delivery_method = "stored"

    delivered_flag = delivery_method not in ("stored", "federation_queued")

    # Generate receipt.delivered for the sender (MSG-05 anti-loop guard)
    if delivered_flag and not is_receipt:
        receipt = {
            "type": "receipt.delivered",
            "message_id": envelope.message_id,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "to": envelope.to_address,
        }
        await manager.send_to(envelope.from_address, receipt)

    return SendResponse(message_id=envelope.message_id, delivered=delivered_flag)

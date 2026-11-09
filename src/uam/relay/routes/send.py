"""POST /send -- message send endpoint (RELAY-02)."""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud.dedup import record_message_id
from uam.db.crud.messages import store_message
from uam.db.session import get_session
from uam.protocol import (
    InvalidEnvelopeError,
    SignatureVerificationError,
    deserialize_verify_key,
    from_wire_dict,
    verify_envelope,
)
from uam.relay.auth import verify_token_http
from uam.relay.federation import forward_to_peer
from uam.relay.receipts import delivery_receipt, wants_delivery_receipt
from uam.relay.models import SendRequest, SendResponse
from uam.relay.policy import (
    DeliveryDenied,
    authorize_delivery,
    charge_duplicate,
    goes_to_peer,
    held_back,
    is_receipt,
    refuse_early,
)
from uam.relay.relay_meta import stamp

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/send", response_model=SendResponse)
async def send_message(
    body: SendRequest,
    request: Request,
    agent: dict = Depends(verify_token_http),
    session: AsyncSession = Depends(get_session),
) -> SendResponse:
    """Send a signed message envelope via REST.

    Order of operations:
    1. Auth (via dependency injection -- already done)
    2. Early refusal (relay/policy.py): blocklist, reputation, sender limit
    3. Parse envelope
    4. Sender identity match
    5. Signature verification
    6. Delivery gate (relay/gate.py): a recipient that hasn't approved the
       sender gets "pending", and nothing is written
    7. Dedup (MSG-03) -- a duplicate is accepted again, idempotently
    8. Delivery checks (relay/policy.py): blocklist, expiry, reputation,
       sender / domain / recipient rate limits
    9. Route or store

    Steps 7-9 share one transaction: a refusal rolls back the dedup row,
    so the sender can send the same message again later.
    """
    manager = request.app.state.manager
    settings = request.app.state.settings

    # Receipt type detection -- check raw dict before full parsing (MSG-05)
    receipt = is_receipt(body.envelope.get("type"))

    try:
        await refuse_early(request.app.state, agent["address"], receipt=receipt)
    except DeliveryDenied as denied:
        raise HTTPException(status_code=denied.status, detail=denied.detail) from denied

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

    # Verify the signature before the gate, so a bad one is refused the
    # same way whether or not the recipient is gated.
    try:
        verify_envelope(envelope, deserialize_verify_key(agent["public_key"]))
    except SignatureVerificationError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid signature: {exc}") from exc

    # The delivery gate (gate.py): reads only, before any write.
    try:
        if await held_back(
            request.app.state, envelope, session, sender_key=agent["public_key"]
        ):
            await session.rollback()
            return SendResponse(
                message_id=envelope.message_id, status="pending", delivered=False
            )
    except DeliveryDenied as denied:
        raise HTTPException(status_code=denied.status, detail=denied.detail) from denied

    # What the relay delivers, stores and forwards: the envelope with this
    # relay's relay_meta in place of any relay_* keys the sender sent.
    wire = stamp(body.envelope, settings.relay_domain)

    # --- Transaction-wrapped DB section (RES-01) ---
    # All DB mutations (dedup + store/enqueue) use commit=False so they
    # live in a single implicit transaction.  A failure at any step
    # rolls back all changes atomically.
    try:
        # Dedup check (MSG-03) -- before expensive delivery chain
        is_new = await record_message_id(session, envelope.message_id, agent["address"], commit=False)
        if not is_new:
            # Silently accept duplicate -- idempotent for the sender
            try:
                await charge_duplicate(request.app.state, agent["address"], receipt=receipt)
            except DeliveryDenied as denied:
                raise HTTPException(status_code=denied.status, detail=denied.detail) from denied
            return SendResponse(
                message_id=envelope.message_id, status="duplicate", delivered=False
            )

        try:
            clearance = await authorize_delivery(request.app.state, envelope, session)
        except DeliveryDenied as denied:
            raise HTTPException(status_code=denied.status, detail=denied.detail) from denied

        if not clearance.deliver:
            # A receipt past its bucket: accepted, not delivered (relay/policy.py)
            await session.rollback()
            return SendResponse(
                message_id=envelope.message_id, status="dropped", delivered=False
            )

        # Three-tier delivery chain: WebSocket > webhook > store-and-forward (HOOK-02)
        # Tier 1: WebSocket (real-time)
        delivered = await manager.send_to(envelope.to_address, wire)
        status = "delivered" if delivered else None
        start_webhook = None

        if not delivered:
            # Tier 2: Webhook (near-real-time)
            webhook_service = request.app.state.webhook_service
            start_webhook = await webhook_service.prepare(
                session, envelope.to_address, wire
            )
            if start_webhook is not None:
                # Started, not confirmed: the webhook service sends the
                # receipt.delivered once the recipient's endpoint accepts it.
                status = "relayed"

        if status is None:
            if goes_to_peer(request.app.state, envelope.to_address):
                # Step 12: Federation forwarding for non-local recipients (FED-01)
                status = await forward_to_peer(
                    request.app.state, session, envelope.to_address, wire
                )
            else:
                # Local recipient not online -- store for pickup
                await store_message(
                    session, envelope.message_id, envelope.from_address,
                    envelope.to_address, json.dumps(wire),
                    expires_at=clearance.expires_at,
                    commit=False,
                )
                status = "stored"

        # Single commit for all DB mutations in this request
        await session.commit()
        if start_webhook is not None:
            start_webhook()

    except HTTPException:
        await session.rollback()
        raise
    except Exception:
        await session.rollback()
        raise

    # receipt.delivered only for mail that reached the recipient (receipts.py).
    # A webhook's receipt comes from the webhook service, once it succeeds.
    if status == "delivered" and wants_delivery_receipt(envelope.type):
        await manager.send_to(
            envelope.from_address,
            delivery_receipt(envelope.message_id, envelope.to_address),
        )

    return SendResponse(
        message_id=envelope.message_id, status=status, delivered=status == "delivered"
    )

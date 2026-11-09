"""WebSocket endpoint for real-time message routing (RELAY-01)."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from uam.protocol import (
    InvalidEnvelopeError,
    SignatureVerificationError,
    deserialize_verify_key,
    from_wire_dict,
    verify_envelope,
)
from uam.protocol.errors import IncompatibleVersionError
from uam.relay.auth import verify_token_ws
from uam.relay.connections import ConnectionManager, LockedWebSocket
from uam.relay.federation import forward_to_peer
from uam.relay.receipts import delivery_receipt, wants_delivery_receipt
from uam.relay.models import check_envelope_size
from uam.relay.policy import (
    DeliveryDenied,
    authorize_delivery,
    charge_duplicate,
    goes_to_peer,
    is_receipt,
    refuse_early,
)
from uam.relay.relay_meta import mark_stored, stamp

from uam.db.crud.agents import get_agent_by_address, update_agent
from uam.db.crud.messages import get_inbox, mark_delivered, store_message
from uam.db.crud.dedup import record_message_id
from uam.db.session import init_session_factory
from uam.db.engine import get_engine

logger = logging.getLogger(__name__)

router = APIRouter()


async def _deliver_stored_messages(
    address: str,
    factory: object,
    manager: ConnectionManager,
) -> None:
    """Send all stored offline messages to a freshly connected agent.

    Routes every drain frame through ``manager.send_to(address, ...)``
    so the per-connection :class:`LockedWebSocket` lock serializes the
    drain against the recv loop's error responses, the heartbeat ping,
    peer forwarding, and webhook receipt forwarding (T4.1 / closes M8
    from REVIEW-relay-core).

    If the connection dies mid-drain, ``manager.send_to`` returns False
    and we abort the rest of the drain — the unsent messages remain in
    storage and will be redelivered on the next reconnect (RELAY-03).
    """
    while True:
        async with factory() as session:
            stored = await get_inbox(session, address)
        if not stored:
            return

        ids: list[int] = []
        for msg in stored:
            envelope_data = mark_stored(json.loads(msg.envelope))
            delivered = await manager.send_to(address, envelope_data)
            if not delivered:
                # Connection died mid-drain; abort. Unsent messages stay in
                # storage and will be redelivered on the next reconnect.
                logger.warning("Drain aborted for %s: connection lost", address)
                break
            ids.append(msg.id)

            # Send receipt.delivered to the original sender (receipts.py)
            original_from = envelope_data.get("from", "")
            if original_from and wants_delivery_receipt(envelope_data.get("type")):
                await manager.send_to(
                    original_from,
                    delivery_receipt(envelope_data.get("message_id", ""), address),
                )

        if ids:
            async with factory() as session:
                await mark_delivered(session, ids)
            logger.info("Delivered %d stored messages to %s", len(ids), address)
        if len(ids) < len(stored):
            return


async def _record_last_seen(address: str, factory) -> None:
    """Note when *address* was last connected.  Best effort."""
    try:
        async with factory() as session:
            await update_agent(session, address, last_seen=datetime.now(timezone.utc))
    except Exception:
        logger.debug("Failed to update last_seen for %s on disconnect", address)


def _sent_id(raw: dict) -> str | None:
    """The message_id a client's frame names, if it is a plausible one."""
    mid = raw.get("message_id")
    return mid if isinstance(mid, str) and 0 < len(mid) <= 64 else None


async def _ack(ws, message_id: str, status: str) -> None:
    """Answer a send: its status (receipts.SEND_STATUSES).  ``delivered`` is
    kept for clients before 1.1."""
    await ws.send_json({
        "type": "ack",
        "message_id": message_id,
        "status": status,
        "delivered": status == "delivered",
    })


async def _error(ws, raw: dict, code: str, detail: str) -> None:
    """Refuse a send, naming its message_id so the client can match it."""
    frame = {"error": code, "detail": detail}
    mid = _sent_id(raw)
    if mid is not None:
        frame["message_id"] = mid
    await ws.send_json(frame)


async def handle_inbound_message(
    wrapped_ws: LockedWebSocket,
    raw: dict,
    sender_address: str,
    factory: object,
    manager: ConnectionManager,
) -> None:
    """Parse, verify, and route an inbound envelope from a WebSocket client.

    All response sends (errors, acks, rate-limit replies) go through the
    :class:`LockedWebSocket` wrapper so they share the per-connection
    lock with peer forwarding, heartbeat, the stored-message drain, and
    webhook receipt forwarding — preventing frame interleave under
    concurrent send pressure (T4.1).

    Order of operations:
    1. Early refusal (relay/policy.py): blocklist, reputation, sender limit
    2. Parse envelope
    3. Sender identity match
    4. Dedup (MSG-03) -- a duplicate is acked again, idempotently
    5. Delivery checks (relay/policy.py): blocklist, expiry, reputation,
       sender / domain / recipient rate limits
    6. Signature verification (expensive -- after the cheap checks)
    7. Route or store

    Steps 4-7 share one transaction: a refusal rolls back the dedup row,
    so the sender can send the same message again later.
    """
    # Receipt type detection -- check raw dict before full parsing (MSG-05)
    receipt = is_receipt(raw.get("type"))

    try:
        await refuse_early(wrapped_ws.app.state, sender_address, receipt=receipt)
    except DeliveryDenied as denied:
        await _error(wrapped_ws, raw, denied.code, denied.detail)
        return

    # Parse envelope
    try:
        envelope = from_wire_dict(raw)
    except (InvalidEnvelopeError, IncompatibleVersionError) as exc:
        await _error(wrapped_ws, raw, "invalid_envelope", str(exc))
        return

    # Verify sender matches authenticated connection
    if envelope.from_address != sender_address:
        await _error(
            wrapped_ws,
            raw,
            "sender_mismatch",
            f"Envelope from '{envelope.from_address}' but connected as '{sender_address}'",
        )
        return

    # What the relay delivers and stores: the envelope with this relay's
    # relay_meta in place of any relay_* keys the sender sent.
    wire = stamp(raw, wrapped_ws.app.state.settings.relay_domain)

    async with factory() as session:
        try:
            # Dedup check (MSG-03) -- before expensive delivery chain
            is_new = await record_message_id(
                session, envelope.message_id, sender_address, commit=False
            )
            if not is_new:
                # Silently ACK duplicate -- idempotent for the sender
                try:
                    await charge_duplicate(
                        wrapped_ws.app.state, sender_address, receipt=receipt
                    )
                except DeliveryDenied as denied:
                    await _error(wrapped_ws, raw, denied.code, denied.detail)
                    return
                await _ack(wrapped_ws, envelope.message_id, "duplicate")
                return

            try:
                clearance = await authorize_delivery(wrapped_ws.app.state, envelope, session)
            except DeliveryDenied as denied:
                await session.rollback()
                await _error(wrapped_ws, raw, denied.code, denied.detail)
                return

            # Look up sender's public key and verify signature (expensive)
            sender_agent = await get_agent_by_address(session, sender_address)
            if sender_agent is None:
                await session.rollback()
                await _error(wrapped_ws, raw, "sender_not_found", f"Sender agent not found: {sender_address}")
                return
            if sender_agent.status != "active":
                await session.rollback()
                await _error(wrapped_ws, raw, "sender_not_active", f"Sender agent is not active: {sender_address}")
                return

            try:
                sender_vk = deserialize_verify_key(sender_agent.public_key)
                verify_envelope(envelope, sender_vk)
            except SignatureVerificationError as exc:
                await session.rollback()
                await _error(wrapped_ws, raw, "invalid_signature", str(exc))
                return

            if not clearance.deliver:
                # A receipt past its bucket: accepted, not delivered (relay/policy.py)
                await session.rollback()
                await _ack(wrapped_ws, envelope.message_id, "dropped")
                return

            # Three-tier delivery chain: WebSocket > webhook > store-and-forward (HOOK-02)
            # Tier 1: WebSocket (real-time)
            delivered = await manager.send_to(envelope.to_address, wire)
            status = "delivered" if delivered else None
            start_webhook = None

            if status is None:
                # Tier 2: Webhook (near-real-time)
                webhook_service = wrapped_ws.app.state.webhook_service
                start_webhook = await webhook_service.prepare(
                    session, envelope.to_address, wire
                )
                if start_webhook is not None:
                    # Started, not confirmed: the webhook service sends the
                    # receipt.delivered once the endpoint accepts it.
                    status = "relayed"

            if status is None and goes_to_peer(wrapped_ws.app.state, envelope.to_address):
                # Non-local recipient -- forward via federation
                status = await forward_to_peer(
                    wrapped_ws.app.state, session, envelope.to_address, wire
                )
            elif status is None:
                # Tier 3: Store-and-forward (eventual)
                await store_message(
                    session,
                    message_id=envelope.message_id,
                    from_addr=envelope.from_address,
                    to_addr=envelope.to_address,
                    envelope=json.dumps(wire),
                    expires_at=clearance.expires_at,
                    commit=False,
                )
                status = "stored"

            # Single commit for dedup + store
            await session.commit()
            if start_webhook is not None:
                start_webhook()
        except Exception:
            await session.rollback()
            raise

    # Send ACK first (always before receipt)
    await _ack(wrapped_ws, envelope.message_id, status)

    # receipt.delivered only for mail that reached the recipient (receipts.py).
    # A webhook's receipt comes from the webhook service, once it succeeds.
    if status == "delivered" and wants_delivery_receipt(envelope.type):
        await manager.send_to(
            envelope.from_address,
            delivery_receipt(envelope.message_id, envelope.to_address),
        )


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """WebSocket endpoint for real-time agent messaging.

    Auth flow (T2.2 -- Phase 43 Plan 04, priority order):
      1. ``Authorization: Bearer {token}``      -- programmatic clients (Python SDK)
      2. ``Sec-WebSocket-Protocol: bearer.{token}`` -- browsers (cannot set
         custom headers on WS upgrade; subprotocol is the canonical workaround)
      3. ``?token={token}`` query string         -- DEPRECATED; logs warning.
         Removed in a follow-up release; documented as a one-release transition.

    Look up agent by token BEFORE accepting.  Never accept unauthenticated
    connections.  When auth is via subprotocol, the chosen subprotocol MUST
    be echoed back in ``websocket.accept(subprotocol=...)`` -- without this,
    browsers drop the connection silently with no error frame (Pitfall 3).
    """
    factory = await init_session_factory(get_engine())
    manager: ConnectionManager = websocket.app.state.manager
    heartbeat = websocket.app.state.heartbeat

    # T2.2: extract token from header / subprotocol / query (in priority order).
    auth_header = websocket.headers.get("authorization")
    token: str | None = None
    chosen_subproto: str | None = None

    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    else:
        # Sec-WebSocket-Protocol may list multiple protocols; find the bearer one.
        # Starlette parses the header into a list under scope['subprotocols'].
        for proto in websocket.scope.get("subprotocols", []):
            if proto.startswith("bearer."):
                token = proto.removeprefix("bearer.")
                chosen_subproto = proto
                break

    if not token:
        token = websocket.query_params.get("token")
        if token:
            client_host = websocket.client.host if websocket.client else "unknown"
            logger.warning(
                "WS auth via querystring is DEPRECATED; use Authorization "
                "header or Sec-WebSocket-Protocol: bearer.<token>. "
                "(client_ip=%s)",
                client_host,
            )

    if not token:
        await websocket.close(code=1008, reason="missing token")
        return

    # Auth: look up agent by token before accepting
    agent = await verify_token_ws(token)
    if agent is None:
        await websocket.close(code=1008, reason="invalid token")
        return

    address = agent["address"]

    # Check blocklist at connection time (SPAM-01 -- per-connection check)
    spam_filter = websocket.app.state.spam_filter
    if spam_filter.is_blocked(address):
        await websocket.close(code=1008, reason="sender is blocked")
        return

    # Accept and register.  Echo the chosen subprotocol so browser clients
    # don't drop the connection (Pitfall 3 -- without echo the WS handshake
    # is technically valid but browsers per-spec close it).
    if chosen_subproto:
        await websocket.accept(subprotocol=chosen_subproto)
    else:
        await websocket.accept()
    # T4.1: manager.connect() returns the LockedWebSocket wrapper. Every
    # subsequent send/close on this connection MUST go through wrapped_ws
    # so the per-connection lock serializes the recv loop, drain,
    # heartbeat, peer forwarding, and webhook receipts.
    wrapped_ws = await manager.connect(address, websocket)
    heartbeat.record_connect(address)
    logger.info("WebSocket connected: %s", address)

    try:
        # Deliver stored offline messages on reconnect (RELAY-03).
        # Drain routes through manager.send_to (closes M8) so it shares
        # the per-connection lock with every other send path.
        await _deliver_stored_messages(address, factory, manager)

        # Message loop. Receive uses the wrapper's pass-through (no lock
        # — single-reader contract). Sends use wrapped_ws (locked).
        while True:
            try:
                raw = await wrapped_ws.receive_json()
            except (ValueError, KeyError):
                # Not JSON, or a binary frame.  KeyError is how Starlette
                # reports a frame without text.
                await wrapped_ws.send_json({
                    "error": "invalid_json",
                    "detail": "Frames must be JSON text",
                })
                continue

            # Handle pong messages (heartbeat RELAY-06)
            if isinstance(raw, dict) and raw.get("type") == "pong":
                heartbeat.record_pong(address)
                continue

            # Distinguish message types: envelopes have "uam_version" field
            if isinstance(raw, dict) and "uam_version" in raw:
                try:
                    check_envelope_size(raw)
                except ValueError as exc:
                    await _error(wrapped_ws, raw, "envelope_too_large", str(exc))
                    continue
                await handle_inbound_message(wrapped_ws, raw, address, factory, manager)
            else:
                msg_type = raw.get("type", "<missing>") if isinstance(raw, dict) else "<invalid>"
                logger.warning("Unknown message type from %s: %s", address, msg_type)
                await wrapped_ws.send_json({
                    "error": "unknown_message_type",
                    "detail": f"Unrecognized message type: {msg_type}",
                })

    except WebSocketDisconnect:
        logger.info("WebSocket disconnected: %s", address)
    except Exception:
        if websocket.application_state == WebSocketState.DISCONNECTED:
            # The relay closed it: replaced by a newer connection, or dead.
            logger.info("WebSocket closed: %s", address)
        else:
            logger.exception("WebSocket error for %s", address)
    finally:
        # A client that reconnected already owns the address: leave that alone.
        await manager.disconnect(address, wrapped_ws)
        if not manager.is_online(address):
            heartbeat.record_disconnect(address)
        # Shielded: this handler can be cancelled, and a database call cancelled
        # half way can hang shutdown (see tests/relay/test_ws_disconnect.py).
        await asyncio.shield(_record_last_seen(address, factory))

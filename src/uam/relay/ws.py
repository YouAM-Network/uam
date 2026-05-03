"""WebSocket endpoint for real-time message routing (RELAY-01)."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

# Grace period for clock skew when checking expiry (seconds)
_EXPIRY_GRACE_SECONDS = 30

from uam.protocol import (
    InvalidEnvelopeError,
    SignatureVerificationError,
    deserialize_verify_key,
    from_wire_dict,
    verify_envelope,
)
from uam.relay.auth import verify_token_ws
from uam.relay.connections import ConnectionManager, LockedWebSocket

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
    async with factory() as session:
        stored = await get_inbox(session, address)
    if not stored:
        return

    ids: list[int] = []
    for msg in stored:
        envelope_data = json.loads(msg.envelope)
        delivered = await manager.send_to(address, envelope_data)
        if not delivered:
            # Connection died mid-drain; abort. Unsent messages stay in
            # storage and will be redelivered on the next reconnect.
            logger.warning("Drain aborted for %s: connection lost", address)
            break
        ids.append(msg.id)

        # Send receipt.delivered to the original sender (MSG-05 anti-loop guard)
        original_from = envelope_data.get("from", "")
        msg_type = str(envelope_data.get("type", ""))
        if original_from and not msg_type.startswith("receipt."):
            receipt = {
                "type": "receipt.delivered",
                "message_id": envelope_data.get("message_id", ""),
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "to": address,
            }
            await manager.send_to(original_from, receipt)

    if ids:
        async with factory() as session:
            await mark_delivered(session, ids)
        logger.info("Delivered %d stored messages to %s", len(ids), address)


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

    Order of operations (DoS-resistant):
    1.  Blocklist check (SPAM-01 -- O(1) set lookup)
    2.  Allowlist check (SPAM-01 -- O(1), sets skip_reputation flag)
    3.  Adaptive sender rate limit (SPAM-04 -- reputation-based)
    4.  Parse envelope
    5.  Sender identity match
    6.  Domain rate limit (SPAM-03 -- relay domain exempt)
    7.  Recipient rate limit (RELAY-05)
    8.  Reputation score check (SPAM-06 -- before crypto)
    9.  Signature verification (expensive -- LAST)
    10. Route or store
    """
    sender_limiter = wrapped_ws.app.state.sender_limiter
    recipient_limiter = wrapped_ws.app.state.recipient_limiter
    spam_filter = wrapped_ws.app.state.spam_filter
    reputation_manager = wrapped_ws.app.state.reputation_manager
    domain_limiter = wrapped_ws.app.state.domain_limiter
    settings = wrapped_ws.app.state.settings

    # Receipt type detection -- check raw dict before full parsing (MSG-05)
    is_receipt = str(raw.get("type", "")).startswith("receipt.")

    # Blocklist check (SPAM-01)
    if spam_filter.is_blocked(sender_address):
        await wrapped_ws.send_json({"error": "blocked", "detail": "Sender is blocked"})
        return

    # Allowlist check (SPAM-01)
    is_allowlisted = spam_filter.is_allowed(sender_address)

    # Adaptive sender rate limit (SPAM-04) -- receipt types exempt
    if is_receipt:
        pass  # receipts skip all rate limits and reputation checks
    elif not is_allowlisted:
        send_limit = reputation_manager.get_send_limit(sender_address)
        if send_limit == 0:
            await wrapped_ws.send_json({"error": "reputation_blocked", "detail": "Sender reputation too low"})
            return
        if not await sender_limiter.check(sender_address, limit=send_limit):
            await wrapped_ws.send_json({"error": "rate_limited", "detail": "Sender rate limit exceeded"})
            return
    else:
        if not await sender_limiter.check(sender_address):
            await wrapped_ws.send_json({"error": "rate_limited", "detail": "Sender rate limit exceeded"})
            return

    # Parse envelope
    try:
        envelope = from_wire_dict(raw)
    except InvalidEnvelopeError as exc:
        await wrapped_ws.send_json({
            "error": "invalid_envelope",
            "detail": str(exc),
        })
        return

    # Verify sender matches authenticated connection
    if envelope.from_address != sender_address:
        await wrapped_ws.send_json({
            "error": "sender_mismatch",
            "detail": f"Envelope from '{envelope.from_address}' but connected as '{sender_address}'",
        })
        return

    # Dedup check (MSG-03) -- before expensive delivery chain
    async with factory() as session:
        is_new = await record_message_id(session, envelope.message_id, sender_address)
    if not is_new:
        # Silently ACK duplicate -- idempotent for the sender
        await wrapped_ws.send_json({
            "type": "ack",
            "message_id": envelope.message_id,
            "delivered": True,
        })
        return

    # Expiry check (MSG-04) -- reject if expires timestamp is in the past
    expires_str: str | None = envelope.expires
    if expires_str is not None:
        try:
            exp_ts = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            if exp_ts + timedelta(seconds=_EXPIRY_GRACE_SECONDS) < now:
                await wrapped_ws.send_json({
                    "error": "expired",
                    "detail": "Message has expired",
                })
                return
        except (ValueError, TypeError):
            # Malformed expires = no expiry (don't reject)
            expires_str = None

    # Domain rate limit (SPAM-03) -- receipt types exempt
    if not is_receipt:
        sender_domain = sender_address.split("::")[1] if "::" in sender_address else ""
        if sender_domain and sender_domain != settings.relay_domain and not is_allowlisted:
            if not await domain_limiter.check(sender_domain):
                await wrapped_ws.send_json({"error": "rate_limited", "detail": "Domain rate limit exceeded"})
                return

    # Rate limit: recipient (RELAY-05) -- receipt types exempt
    if not is_receipt and not await recipient_limiter.check(envelope.to_address):
        await wrapped_ws.send_json({
            "error": "rate_limited",
            "detail": "Recipient rate limit exceeded (100/min)",
        })
        return

    # Reputation check (SPAM-06) -- receipt types exempt
    if not is_receipt and not is_allowlisted:
        score = reputation_manager.get_score(sender_address)
        if score < 20:
            await wrapped_ws.send_json({"error": "reputation_blocked", "detail": "Sender reputation too low"})
            return

    # Look up sender's public key and verify signature (expensive)
    async with factory() as session:
        sender_agent = await get_agent_by_address(session, sender_address)
    if sender_agent is None:
        await wrapped_ws.send_json({
            "error": "sender_not_found",
            "detail": f"Sender agent not found: {sender_address}",
        })
        return

    try:
        sender_vk = deserialize_verify_key(sender_agent.public_key)
        verify_envelope(envelope, sender_vk)
    except SignatureVerificationError as exc:
        await wrapped_ws.send_json({
            "error": "invalid_signature",
            "detail": str(exc),
        })
        return

    # Three-tier delivery chain: WebSocket > webhook > store-and-forward (HOOK-02)
    # Tier 1: WebSocket (real-time)
    delivered = await manager.send_to(envelope.to_address, raw)

    if not delivered:
        # Tier 2: Webhook (near-real-time)
        webhook_service = wrapped_ws.app.state.webhook_service
        webhook_initiated = await webhook_service.try_deliver(
            envelope.to_address, raw
        )
        if webhook_initiated:
            delivered = True  # webhook delivery initiated (async)

    if not delivered:
        # Tier 3: Store-and-forward (eventual)
        # Convert expires string to datetime for CRUD layer
        expires_dt = None
        if expires_str is not None:
            try:
                expires_dt = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
        async with factory() as session:
            await store_message(
                session,
                message_id=envelope.message_id,
                from_addr=envelope.from_address,
                to_addr=envelope.to_address,
                envelope=json.dumps(raw),
                expires_at=expires_dt,
            )

    # Send ACK first (always before receipt)
    await wrapped_ws.send_json({
        "type": "ack",
        "message_id": envelope.message_id,
        "delivered": delivered,
    })

    # Generate receipt.delivered for the sender (MSG-05 anti-loop guard)
    if delivered and not is_receipt:
        receipt = {
            "type": "receipt.delivered",
            "message_id": envelope.message_id,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "to": envelope.to_address,
        }
        await manager.send_to(envelope.from_address, receipt)


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
            raw = await wrapped_ws.receive_json()

            # Handle pong messages (heartbeat RELAY-06)
            if isinstance(raw, dict) and raw.get("type") == "pong":
                heartbeat.record_pong(address)
                continue

            # Distinguish message types: envelopes have "uam_version" field
            if "uam_version" in raw:
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
        logger.exception("WebSocket error for %s", address)
    finally:
        heartbeat.record_disconnect(address)
        try:
            async with factory() as session:
                await update_agent(session, address, last_seen=datetime.now(timezone.utc))
        except Exception:
            logger.debug("Failed to update last_seen for %s on disconnect", address)
        await manager.disconnect(address)

"""Demo widget endpoints -- ephemeral session, send, and inbox.

These endpoints let the landing-page chat widget create real UAM agents,
send signed+encrypted envelopes, and read decrypted replies without ever
exposing private keys to the browser.

All crypto operations (key generation, signing, encryption, decryption)
happen server-side.
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, HTTPException, Query, Request

from uam.protocol import (
    MessageType,
    create_envelope,
    decrypt_payload,
    from_wire_dict,
    to_wire_dict,
)
from uam.protocol.crypto import (
    deserialize_signing_key,
    deserialize_verify_key,
)
from uam.relay.database import (
    get_agent_by_address,
    get_stored_messages,
    mark_messages_delivered,
    register_agent,
    store_message,
)
from uam.relay.models import (
    CreateSessionResponse,
    DemoInboxResponse,
    DemoSendRequest,
    DemoSendResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/demo/session", response_model=CreateSessionResponse)
async def create_demo_session(request: Request) -> CreateSessionResponse:
    """Create an ephemeral demo agent with a real Ed25519 keypair.

    The keypair is held server-side; the browser only receives a session
    token and the agent address.
    """
    session_mgr = request.app.state.demo_sessions
    db = request.app.state.db
    settings = request.app.state.settings

    # Rate limit session creation (reuse register limiter -- 5/min per IP)
    client_ip = request.client.host if request.client else "unknown"
    if not request.app.state.register_limiter.check(client_ip):
        raise HTTPException(status_code=429, detail="Session creation rate limit exceeded")

    session = await session_mgr.create(settings.relay_domain)

    # Register the ephemeral agent in the relay database so other agents
    # can look up its public key and route messages to it.
    await register_agent(db, session.address, session.verify_key_b64, session.token)

    return CreateSessionResponse(session_id=session.session_id, address=session.address)


@router.post("/demo/send", response_model=DemoSendResponse)
async def demo_send(body: DemoSendRequest, request: Request) -> DemoSendResponse:
    """Send a message from the demo session to any registered agent.

    The relay signs and encrypts the envelope on behalf of the ephemeral
    agent using the server-held private key.
    """
    session_mgr = request.app.state.demo_sessions
    db = request.app.state.db
    manager = request.app.state.manager

    # Validate session
    session = await session_mgr.get(body.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    # Rate limit sends per session address
    if not request.app.state.sender_limiter.check(session.address):
        raise HTTPException(status_code=429, detail="Send rate limit exceeded")

    # Resolve recipient public key
    recipient = await get_agent_by_address(db, body.to_address)
    if recipient is None:
        raise HTTPException(status_code=404, detail="Recipient not found")

    # Deserialize keys
    signing_key = deserialize_signing_key(session.signing_key_b64)
    recipient_vk = deserialize_verify_key(recipient["public_key"])

    # Create signed, encrypted envelope
    envelope = create_envelope(
        from_address=session.address,
        to_address=body.to_address,
        message_type=MessageType.MESSAGE,
        payload_plaintext=body.message.encode("utf-8"),
        signing_key=signing_key,
        recipient_verify_key=recipient_vk,
        media_type="text/plain",
    )
    wire = to_wire_dict(envelope)

    # Route: try live delivery first, fall back to offline storage
    delivered = await manager.send_to(body.to_address, wire)
    if not delivered:
        await store_message(db, session.address, body.to_address, json.dumps(wire))

    return DemoSendResponse(message_id=envelope.message_id)


@router.get("/demo/inbox", response_model=DemoInboxResponse)
async def demo_inbox(
    request: Request,
    session_id: str = Query(..., description="Demo session ID"),
) -> DemoInboxResponse:
    """Return decrypted plaintext messages for the demo session.

    The relay decrypts each stored envelope using the server-held private
    key, so the browser receives plaintext content.
    """
    session_mgr = request.app.state.demo_sessions
    db = request.app.state.db

    # Validate session
    session = await session_mgr.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    # Fetch undelivered messages addressed to this ephemeral agent
    stored = await get_stored_messages(db, session.address, limit=50)

    signing_key = deserialize_signing_key(session.signing_key_b64)

    messages: list[dict] = []
    ids_to_mark: list[int] = []

    for msg in stored:
        try:
            envelope = from_wire_dict(msg["envelope"])
        except Exception:
            logger.debug("Skipping unparseable envelope id=%s", msg["id"])
            ids_to_mark.append(msg["id"])
            continue

        # Filter out non-message types (handshakes, receipts, etc.)
        if envelope.type != MessageType.MESSAGE:
            ids_to_mark.append(msg["id"])
            continue

        # Resolve sender public key for decryption
        sender = await get_agent_by_address(db, envelope.from_address)
        if sender is None:
            logger.debug("Skipping message from unknown sender %s", envelope.from_address)
            ids_to_mark.append(msg["id"])
            continue

        # Decrypt the payload using the ephemeral agent's private key
        try:
            sender_vk = deserialize_verify_key(sender["public_key"])
            plaintext = decrypt_payload(envelope.payload, signing_key, sender_vk)
            content = plaintext.decode("utf-8")
        except Exception:
            logger.debug("Failed to decrypt message id=%s", msg["id"])
            ids_to_mark.append(msg["id"])
            continue

        messages.append({
            "from_address": envelope.from_address,
            "content": content,
            "timestamp": envelope.timestamp,
            "message_id": envelope.message_id,
        })
        ids_to_mark.append(msg["id"])

    # Mark all processed messages as delivered
    if ids_to_mark:
        await mark_messages_delivered(db, ids_to_mark)

    return DemoInboxResponse(messages=messages)

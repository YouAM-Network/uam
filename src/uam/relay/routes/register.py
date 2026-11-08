"""POST /register -- agent registration endpoint (RELAY-04)."""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud.agents import (
    create_agent,
    get_agent_by_address,
    set_webhook,
    update_agent,
)
from uam.db.crud.federation_nonces import record_nonce
from uam.db.session import get_session
from uam.protocol import (
    InvalidAddressError,
    deserialize_verify_key,
    parse_address,
)
from uam.protocol.register_proof import register_proof_is_valid, register_proof_nonce
from uam.relay.models import RegisterRequest, RegisterResponse
from uam.relay.token_hashing import hash_token
from uam.relay.webhook_validator import async_validate_webhook_url

router = APIRouter()


@router.post("/register", response_model=RegisterResponse)
async def register(body: RegisterRequest, request: Request, session: AsyncSession = Depends(get_session)) -> RegisterResponse:
    """Register a new agent with the relay.

    This is the only public (unauthenticated) endpoint besides /health.
    Rate limited to 5 registrations per minute per IP.
    """
    settings = request.app.state.settings

    # Rate limit by client IP (5/min)
    client_ip = request.client.host if request.client else "unknown"
    if not await request.app.state.register_limiter.check(client_ip):
        raise HTTPException(status_code=429, detail="Registration rate limit exceeded (5/min)")

    # Validate public key is a real Ed25519 key
    try:
        deserialize_verify_key(body.public_key)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid public key: {exc}") from exc

    # Normalize agent name and build address
    agent_name = body.agent_name.strip().lower()
    address = f"{agent_name}::{settings.relay_domain}"

    # Validate address format
    try:
        parse_address(address)
    except InvalidAddressError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid agent name: {exc}") from exc

    # Check blocklist before registration (SPAM-01 -- "before handshake processing")
    spam_filter = request.app.state.spam_filter
    if spam_filter.is_blocked(address):
        raise HTTPException(
            status_code=403,
            detail="Registration blocked: address or domain is blocklisted",
        )

    # An address that is taken stays with its agent.  Whoever holds the key
    # can get a new token (the old one stops working); the public key alone
    # proves nothing.
    existing = await get_agent_by_address(session, address)
    if existing is not None:
        if body.proof is None or existing.public_key != body.public_key:
            raise HTTPException(
                status_code=409, detail=f"Agent address already registered: {address}"
            )
        if not register_proof_is_valid(
            address,
            body.proof.timestamp,
            body.proof.signature,
            deserialize_verify_key(existing.public_key),
        ):
            raise HTTPException(status_code=403, detail="Invalid registration proof")
        # A proof works once.  The nonce sweep outlasts the proof's window.
        nonce = register_proof_nonce(body.proof.timestamp)
        if not await record_nonce(session, address, nonce, commit=False):
            raise HTTPException(status_code=403, detail="Invalid registration proof")
        new_token = secrets.token_urlsafe(32)
        await update_agent(
            session,
            address,
            commit=False,
            token_hash=hash_token(new_token, settings.token_pepper),
        )
        await session.commit()
        return RegisterResponse(
            address=address,
            token=new_token,
            relay=settings.relay_ws_url,
        )

    # --- Transaction-wrapped DB section (RES-01) ---
    # create_agent + optional update_agent (webhook URL) in a single commit.
    # Phase 47 T7.5: only the hashed token is persisted. The plaintext
    # ``token`` is returned to the caller in the HTTP response and never
    # written to the database.
    token = secrets.token_urlsafe(32)
    token_hash_value = hash_token(token, settings.token_pepper)
    webhook_secret = None
    try:
        await create_agent(
            session,
            address,
            body.public_key,
            token_hash=token_hash_value,
            commit=False,
        )

        # Optionally set webhook URL (HOOK-01)
        if body.webhook_url is not None:
            valid, reason = await async_validate_webhook_url(body.webhook_url)
            if not valid:
                raise HTTPException(status_code=400, detail=f"Invalid webhook URL: {reason}")
            webhook_secret = await set_webhook(
                session, address, body.webhook_url, commit=False
            )

        # Single commit for agent creation + optional webhook update
        await session.commit()

    except HTTPException:
        await session.rollback()
        raise
    except IntegrityError as exc:
        # A deleted agent keeps its address, and two callers can race for one.
        await session.rollback()
        raise HTTPException(
            status_code=409, detail=f"Agent address already registered: {address}"
        ) from exc
    except Exception:
        await session.rollback()
        raise

    # Initialize reputation score (SPAM-02) -- outside transaction
    # (reputation is managed by an in-memory service, not critical DB state)
    reputation_manager = request.app.state.reputation_manager
    await reputation_manager.init_score(address, dns_verified=False)

    return RegisterResponse(
        address=address,
        token=token,
        relay=settings.relay_ws_url,
        webhook_secret=webhook_secret,
    )

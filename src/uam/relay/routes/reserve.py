"""Reservation endpoints: check availability, reserve address, claim reservation,
and vCard download (RES-01, RES-02, RES-04, RES-05, RES-06, VCF-04)."""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import Response

from uam.db.crud.agents import create_agent, get_agent_by_address
from uam.db.crud.reservations import (
    AddressAlreadyReserved,
    check_address_available,
    claim_reservation,
    count_active_reservations_by_ip,
    create_reservation,
    get_reservation_by_token,
)
from uam.db.session import get_session
from uam.protocol import InvalidAddressError, parse_address
from uam.protocol.crypto import deserialize_verify_key
from uam.relay.models import (
    ReserveCheckResponse,
    ReserveClaimRequest,
    ReserveClaimResponse,
    ReserveRequest,
    ReserveResponse,
)
from uam.cards.image import render_card
from uam.cards.vcard import generate_reservation_vcard
from uam.relay.webhook_validator import validate_webhook_url

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/reserve/check/{name}", response_model=ReserveCheckResponse)
async def reserve_check(
    name: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> ReserveCheckResponse:
    """Check whether an agent name is available for reservation (RES-01).

    Queries both the agents table (registered agents) and the reservations
    table (active reservations) to determine availability.
    """
    settings = request.app.state.settings

    # Normalize name
    name = name.strip().lower()

    # Build full address
    address = f"{name}::{settings.relay_domain}"

    # Validate address format
    try:
        parse_address(address)
    except InvalidAddressError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid agent name: {exc}") from exc

    # Check availability against both agents and reservations
    is_available = await check_address_available(session, address)

    return ReserveCheckResponse(address=address, available=is_available)


@router.post("/reserve", response_model=ReserveResponse, status_code=201)
async def reserve_address(
    body: ReserveRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> ReserveResponse:
    """Reserve an agent address with a time-limited claim token (RES-02, RES-06).

    Creates a reservation with a 256-bit claim token and configurable TTL
    (default 48 hours). Rate limited to 5 active reservations per IP per hour.
    """
    settings = request.app.state.settings

    # Extract client IP
    client_ip = request.client.host if request.client else "unknown"

    # Rate limit: max 5 active reservations per IP per hour (RES-06)
    count = await count_active_reservations_by_ip(session, client_ip, window_hours=1)
    if count >= 5:
        raise HTTPException(
            status_code=429,
            detail="Reservation rate limit exceeded (5 per IP per hour)",
        )

    # Normalize name
    name = body.name.strip().lower()

    # Build full address
    address = f"{name}::{settings.relay_domain}"

    # Validate address format
    try:
        parse_address(address)
    except InvalidAddressError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid agent name: {exc}") from exc

    # Check availability
    is_available = await check_address_available(session, address)
    if not is_available:
        raise HTTPException(status_code=409, detail=f"Address already taken: {address}")

    # Generate 256-bit claim token (32 bytes = 256 bits)
    claim_token = secrets.token_urlsafe(32)

    # Calculate expiry from configurable TTL
    expires_at = datetime.utcnow() + timedelta(hours=settings.reservation_ttl_hours)

    # Create reservation
    try:
        reservation = await create_reservation(
            session, address, claim_token, client_ip, expires_at
        )
    except AddressAlreadyReserved:
        raise HTTPException(status_code=409, detail=f"Address already taken: {address}")

    # Build vcf download URL
    vcf_url = f"{settings.relay_http_url}/api/v1/reserve/{claim_token}/vcf"

    return ReserveResponse(
        address=address,
        claim_token=claim_token,
        expires_at=reservation.expires_at.isoformat(),
        vcf_url=vcf_url,
    )


@router.post("/reserve/claim", response_model=ReserveClaimResponse)
async def reserve_claim(
    body: ReserveClaimRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> ReserveClaimResponse:
    """Claim a reserved address using a claim token (RES-04).

    Validates the claim token, checks the reservation is still valid,
    registers the agent via create_agent(), and marks the reservation
    as claimed -- all in a single transaction.
    """
    settings = request.app.state.settings

    # Validate public key format
    try:
        deserialize_verify_key(body.public_key)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid public key: {exc}") from exc

    # Validate webhook URL if provided
    if body.webhook_url is not None:
        valid, reason = validate_webhook_url(body.webhook_url)
        if not valid:
            raise HTTPException(status_code=400, detail=f"Invalid webhook URL: {reason}")

    # Look up reservation by claim token
    reservation = await get_reservation_by_token(session, body.claim_token)
    if reservation is None:
        raise HTTPException(status_code=404, detail="Invalid claim token")

    # Check reservation status
    if reservation.status != "reserved":
        raise HTTPException(status_code=409, detail="Reservation already claimed or expired")

    # Check expiry
    if reservation.expires_at <= datetime.utcnow():
        raise HTTPException(status_code=410, detail="Reservation expired")

    # --- Transaction-wrapped DB section ---
    try:
        # Claim the reservation (sets status='claimed', claimed_at=now)
        claimed = await claim_reservation(session, body.claim_token, commit=False)
        if claimed is None:
            raise HTTPException(status_code=409, detail="Could not claim reservation")

        # Register the agent with the reserved address
        agent_token = secrets.token_urlsafe(32)
        await create_agent(
            session,
            reservation.address,
            body.public_key,
            agent_token,
            commit=False,
            webhook_url=body.webhook_url,
        )

        # Single commit for both claim + agent creation
        await session.commit()

    except HTTPException:
        await session.rollback()
        raise
    except Exception:
        await session.rollback()
        raise

    # Initialize reputation score (follow register.py pattern) -- outside transaction
    await request.app.state.reputation_manager.init_score(
        reservation.address, dns_verified=False
    )

    return ReserveClaimResponse(
        address=reservation.address,
        token=agent_token,
        relay=settings.relay_ws_url,
    )


@router.get("/reserve/{token}/card.jpg")
async def download_reservation_card(
    token: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Download the reservation card image as JPEG for a given claim token."""
    reservation = await get_reservation_by_token(session, token)
    if reservation is None:
        raise HTTPException(status_code=404, detail="Invalid claim token")

    settings = request.app.state.settings
    agent_name = reservation.address.split("::")[0]

    jpeg_bytes = render_card(
        agent_name=agent_name,
        relay_domain=settings.relay_domain,
        card_type="reservation",
        expires_at=reservation.expires_at.isoformat() if reservation.expires_at else None,
        avatar_style=settings.avatar_style,
    )

    return Response(
        content=jpeg_bytes,
        media_type="image/jpeg",
        headers={
            "Content-Disposition": f'inline; filename="{agent_name}-card.jpg"',
        },
    )


@router.get("/reserve/{token}/vcf")
async def download_reservation_vcf(
    token: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Download the reservation vCard file for a given claim token (VCF-04).

    Returns a vCard 3.0 file with text/vcard MIME type and
    Content-Disposition: attachment header for browser download.
    """
    reservation = await get_reservation_by_token(session, token)
    if reservation is None:
        raise HTTPException(status_code=404, detail="Invalid claim token")

    settings = request.app.state.settings
    # Extract agent name from address (e.g. "scout::youam.network" -> "scout")
    agent_name = reservation.address.split("::")[0]

    vcf_content = generate_reservation_vcard(
        agent_name=agent_name,
        relay_domain=settings.relay_domain,
        claim_token=reservation.claim_token,
        expires_at=reservation.expires_at.isoformat() if reservation.expires_at else None,
    )

    filename = f"reservation.{agent_name}.vcf"
    return Response(
        content=vcf_content,
        media_type="text/vcard",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )

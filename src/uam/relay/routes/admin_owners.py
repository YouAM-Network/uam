"""Admin routes for owner accounts: create one (P2c-1), give one a name
(P2s-2), and freeze one whose owner lost every passkey (DEC-010).

People can also make their own account (``POST /api/owner/sign-up`` on the
owner origin, P2s); these routes are for the relay admin. They are 404
while UAM_OWNERS_ENABLED is off.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud.owners import EmailTaken, create_owner, owner_by_owner_id
from uam.db.crud.reservations import AddressAlreadyReserved
from uam.db.session import get_session
from uam.protocol import InvalidAddressError, parse_address
from uam.relay.models import _AGENT_NAME_PATTERN
from uam.relay.owners import freeze, links, names
from uam.relay.owners.crypto import normalise_email
from uam.relay.owners.passkeys import PasskeyError
from uam.relay.routes.admin import verify_admin_key


async def owners_enabled(request: Request) -> None:
    if not request.app.state.settings.owners_enabled:
        raise HTTPException(status_code=404, detail="Not Found")


router = APIRouter(
    prefix="/admin/owners",
    tags=["admin"],
    dependencies=[Depends(owners_enabled), Depends(verify_admin_key)],
)


class CreateOwnerRequest(BaseModel):
    email: Annotated[str, Field(max_length=320)]


class OwnerView(BaseModel):
    id: int
    status: str
    owner_id: str | None
    created_via: str


@router.post("", status_code=201, response_model=OwnerView)
async def create(
    body: CreateOwnerRequest, request: Request, session: AsyncSession = Depends(get_session)
) -> OwnerView:
    email = normalise_email(body.email)
    if email is None:
        raise HTTPException(status_code=422, detail="not an email address")
    vault = request.app.state.owner_vault
    try:
        owner = await create_owner(
            session, email_hmac=vault.lookup(email), email_enc=vault.encrypt(email),
            created_via="admin",
        )
    except EmailTaken:
        raise HTTPException(status_code=409, detail="an owner already has that email") from None
    await session.commit()
    return OwnerView(
        id=owner.id, status=owner.status, owner_id=owner.owner_id, created_via=owner.created_via
    )


class FreezeRequest(BaseModel):
    email: Annotated[str, Field(max_length=320)]


@router.post("/freeze")
async def freeze_account(
    body: FreezeRequest, request: Request, session: AsyncSession = Depends(get_session)
) -> dict:
    """Freeze the account of someone who lost every passkey (DEC-010).

    Confirm who they are another way first. Their email can keep the account
    for 72 hours; after that it closes and they can make a new one."""
    email = normalise_email(body.email)
    if email is None:
        raise HTTPException(status_code=422, detail="not an email address")
    try:
        return await freeze.freeze(session, request.app, email)
    except PasskeyError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.detail) from None


class GiveNameRequest(BaseModel):
    name: Annotated[str, Field(max_length=64, pattern=_AGENT_NAME_PATTERN)]
    days: Annotated[int, Field(ge=1, le=names.MAX_GIVE_DAYS)] = names.GIVE_DAYS


@router.post("/{owner_id}/names", status_code=201)
async def give_name(
    body: GiveNameRequest,
    request: Request,
    owner_id: Annotated[str, Path(pattern=r"^[A-Za-z0-9_-]{22}$")],
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Hold a name for an account, even one on the reserved list. The
    account makes a setup code for it on its page."""
    owner = await owner_by_owner_id(session, owner_id)
    if owner is None or owner.status != "active":
        raise HTTPException(status_code=404, detail="no such owner")
    address = f"{body.name.strip().lower()}::{request.app.state.settings.relay_domain}"
    try:
        parse_address(address)
    except InvalidAddressError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid agent name: {exc}") from exc
    try:
        row = await names.give(session, owner, address, body.days)
    except AddressAlreadyReserved:
        raise HTTPException(status_code=409, detail=f"Address already taken: {address}") from None
    return {"address": row.address, "expiresAt": links._stamp(row.expires_at)}

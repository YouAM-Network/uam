"""Admin route to create an owner account (P2c-1).

Accounts are invite-only: until invites land (P2e) the relay admin is the
only way in. The route is 404 while UAM_OWNERS_ENABLED is off.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud.owners import EmailTaken, create_owner
from uam.db.session import get_session
from uam.relay.owners.crypto import normalise_email
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

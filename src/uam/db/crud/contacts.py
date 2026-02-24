"""CRUD operations for Contact entities.

Every function takes ``session: AsyncSession`` as its first parameter.
Read queries filter ``deleted_at IS NULL`` by default.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from uam.db.models import Contact


async def create_contact(
    session: AsyncSession,
    owner_address: str,
    contact_address: str,
    trust_state: str = "unknown",
    contact_card: dict | None = None,
) -> Contact:
    """Create a new contact book entry."""
    contact = Contact(
        owner_address=owner_address,
        contact_address=contact_address,
        trust_state=trust_state,
        contact_card=contact_card,
    )
    session.add(contact)
    await session.commit()
    await session.refresh(contact)
    return contact


async def get_contact(
    session: AsyncSession, owner_address: str, contact_address: str
) -> Contact | None:
    """Look up a contact by owner and contact address (soft-delete filtered)."""
    stmt = select(Contact).where(
        Contact.owner_address == owner_address,
        Contact.contact_address == contact_address,
        Contact.deleted_at.is_(None),  # type: ignore[union-attr]
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def update_trust(
    session: AsyncSession,
    owner_address: str,
    contact_address: str,
    trust_state: str,
) -> Contact | None:
    """Update the trust state of a contact. Returns the updated contact or None."""
    contact = await get_contact(session, owner_address, contact_address)
    if contact is None:
        return None
    contact.trust_state = trust_state
    contact.updated_at = datetime.utcnow()
    session.add(contact)
    await session.commit()
    await session.refresh(contact)
    return contact


async def list_by_owner(
    session: AsyncSession, owner_address: str
) -> list[Contact]:
    """List all contacts for an owner (soft-delete filtered)."""
    stmt = select(Contact).where(
        Contact.owner_address == owner_address,
        Contact.deleted_at.is_(None),  # type: ignore[union-attr]
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def delete_contact(
    session: AsyncSession, owner_address: str, contact_address: str
) -> bool:
    """Soft-delete a contact. Returns True if found and deleted."""
    contact = await get_contact(session, owner_address, contact_address)
    if contact is None:
        return False
    contact.deleted_at = datetime.utcnow()
    session.add(contact)
    await session.commit()
    return True


async def list_by_owner_with_deleted(
    session: AsyncSession, owner_address: str
) -> list[Contact]:
    """List all contacts for an owner, including soft-deleted."""
    stmt = select(Contact).where(
        Contact.owner_address == owner_address,
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())

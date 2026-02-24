"""Tests for Contact CRUD operations."""

from __future__ import annotations

from uam.db.crud.contacts import (
    create_contact,
    delete_contact,
    get_contact,
    list_by_owner,
    list_by_owner_with_deleted,
    update_trust,
)


async def test_create_contact(session):
    contact = await create_contact(
        session,
        owner_address="alice::youam.network",
        contact_address="bob::youam.network",
        trust_state="trusted",
        contact_card={"display_name": "Bob"},
    )
    assert contact.owner_address == "alice::youam.network"
    assert contact.contact_address == "bob::youam.network"
    assert contact.trust_state == "trusted"
    assert contact.contact_card == {"display_name": "Bob"}


async def test_get_contact(session):
    await create_contact(
        session,
        owner_address="alice::youam.network",
        contact_address="bob::youam.network",
    )
    found = await get_contact(session, "alice::youam.network", "bob::youam.network")
    assert found is not None
    assert found.contact_address == "bob::youam.network"


async def test_update_trust(session):
    await create_contact(
        session,
        owner_address="alice::youam.network",
        contact_address="bob::youam.network",
        trust_state="unknown",
    )
    updated = await update_trust(
        session, "alice::youam.network", "bob::youam.network", "trusted"
    )
    assert updated is not None
    assert updated.trust_state == "trusted"


async def test_list_by_owner(session):
    for name in ["bob", "carol", "dave"]:
        await create_contact(
            session,
            owner_address="alice::youam.network",
            contact_address=f"{name}::youam.network",
        )
    # Different owner
    await create_contact(
        session,
        owner_address="eve::youam.network",
        contact_address="frank::youam.network",
    )

    contacts = await list_by_owner(session, "alice::youam.network")
    assert len(contacts) == 3
    assert all(c.owner_address == "alice::youam.network" for c in contacts)


async def test_delete_contact_soft(session):
    await create_contact(
        session,
        owner_address="alice::youam.network",
        contact_address="bob::youam.network",
    )

    # Soft delete
    deleted = await delete_contact(session, "alice::youam.network", "bob::youam.network")
    assert deleted is True

    # Default query hides it
    found = await get_contact(session, "alice::youam.network", "bob::youam.network")
    assert found is None

    # _with_deleted shows it
    all_contacts = await list_by_owner_with_deleted(session, "alice::youam.network")
    assert len(all_contacts) == 1
    assert all_contacts[0].deleted_at is not None

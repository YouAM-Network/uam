"""Owners connect (P2e-1, spec P2 §5): invites, redemptions, grants.

Ada invites Bob with a code she reads out (10 minutes), a link (7 days) or
his email (pre-approved). Bob, signed in with a passkey, finds the invite
and approves once: his ``UamRedemption`` and his ``UamContactGrant``
naming Ada. Ada then confirms Bob with her passkey, seeing his checked
email; for a pre-approved invite her grant was signed with the invite and
names it, and redeeming makes it name Bob. The gate (``uam.relay.gate``)
reads the grants live, so removing someone or cancelling works at once;
both also go on the revocation list agents can poll.

Each approval reuses the link ceremony: the relay stores a challenge over
the objects and the sentence, and the owner's passkey signs it once. The
objects name the passkey that will sign (``issuer``), so the page says
which one this browser has (``credentialId``); otherwise the newest is
asked for.
"""

from __future__ import annotations

import hmac
import logging
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud import owner_contacts as crud
from uam.db.crud import owners as owner_crud
from uam.db.models import InviteRedemption, Owner, OwnerEmail, OwnerGrant, OwnerInvite, OwnerPasskey
from uam.protocol.contacts import (
    GRANT,
    INVITE,
    REDEMPTION,
    confirm_screen,
    email_hash,
    invite_id,
    invite_screen,
    invite_words,
    new_secret,
    redeem_screen,
    revocations_message,
    secret_hash,
)
from uam.protocol.crypto import sign_message
from uam.protocol.links import words_for
from uam.protocol.signed import _parse_time, canonical, object_hash, parse_body
from uam.protocol.webauthn import approval_challenge
from uam.relay.owners import service
from uam.relay.owners.crypto import EmailVault, new_link_code, normalise_link_code
from uam.relay.owners.links import _assert, _nonce, _signers, _stamp, show_code
from uam.relay.owners.passkeys import CHALLENGE_TTL, PasskeyError, _b64u

log = logging.getLogger("uam.relay.owners")

CODE_TTL = timedelta(minutes=10)
LINK_TTL = timedelta(days=7)
#: A pre-approved invite's email waits this long, so the inviter can undo it.
EMAIL_UNDO = timedelta(minutes=10)
GRANT_TTL = timedelta(days=90)
MAX_OPEN = 10
MAX_A_DAY = 20
TRIES = 5
TRY_WINDOW = timedelta(minutes=10)
REVOCATIONS_PAGE = 500
#: How each kind of invite records how two owners met. A link is shown as
#: a QR code too, so both are ``intro_qr``.
VIA = {"code": "intro_code", "link": "intro_qr", "email": "intro_email"}
_SHARED = {"actions": ["message"], "locations": ["shared"]}

#: Told about an owner's contacts: (owner_pk, event, details). Events:
#: ``invite_redeemed`` and ``invite_reused`` (to the inviter),
#: ``contact_confirmed`` (to the invitee). P2g sends these as email.
ContactNotice = Callable[[int, str, dict[str, Any]], None]
#: Sends a pre-approved invite: (to, link, inviter's email).
InviteEmail = Callable[[str, str, str], None]


def log_notice(owner_pk: int, event: str, details: dict[str, Any]) -> None:
    log.info("owner %s: %s %s", owner_pk, event, details.get("invite", ""))


def log_invite_email(to: str, link: str, inviter: str) -> None:
    """Local runs only (``UAM_OWNER_CODES_TO_LOG``): the link is a secret."""
    log.warning("invite from %s for %s: %s", inviter, to, link)


def drop_invite_email(to: str, link: str, inviter: str) -> None:
    """No mail transport yet (P2g): the invite is listed, nothing is sent."""


def _refused(status: int, code: str, detail: str) -> PasskeyError:
    return PasskeyError(status, code, detail)


def _no_passkey() -> PasskeyError:
    return _refused(409, "no_passkey", "Add a passkey first.")


def _aware(value: datetime) -> datetime:
    return service._aware(value)


async def _email_of(session: AsyncSession, vault: EmailVault, owner_pk: int) -> str:
    row = await owner_crud.primary_email(session, owner_pk)
    return vault.decrypt(row.email_enc) if row is not None else ""


async def _emails(session: AsyncSession, vault: EmailVault, owner_pk: int) -> list[str]:
    return [vault.decrypt(row.email_enc) for row in await _email_rows(session, owner_pk)]


async def _person(session: AsyncSession, vault: EmailVault, owner_pk: int) -> dict[str, Any]:
    """What one owner is shown about another: checked facts only."""
    other = await session.get(Owner, owner_pk)
    return {
        "ownerId": other.owner_id,
        "email": await _email_of(session, vault, owner_pk),
        "since": _stamp(other.created_at),
    }


def _owner_ref(settings, owner: Owner, keys_hash: str) -> dict[str, str]:
    return {"relay": settings.relay_domain, "ownerId": owner.owner_id, "keysHash": keys_hash}


async def _head(session: AsyncSession, owner: Owner) -> str:
    head = await owner_crud.key_log_head(session, owner.id)
    if owner.owner_id is None or head is None:
        raise _no_passkey()
    return head.hash


async def _signer(
    session: AsyncSession, owner: Owner, keys_hash: str, credential_id: str | None
) -> OwnerPasskey:
    """The passkey that will sign: this browser's, or the newest."""
    signers = await _signers(session, owner, keys_hash)
    if not signers:
        raise _refused(409, "no_passkey", "None of your passkeys can approve this.")
    if credential_id is None:
        return max(signers, key=lambda p: p.id)
    for passkey in signers:
        if passkey.credential_id == credential_id:
            return passkey
    raise _refused(400, "bad_signer", "That passkey can't approve this.")


def _grant_body(
    settings, owner: Owner, issuer: str, subject: dict[str, Any], via: str, now: datetime,
    locations: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "type": GRANT, "v": 1, "issuer": issuer,
        "issuerOwner": {"relay": settings.relay_domain, "ownerId": owner.owner_id},
        "credentialSubject": subject,
        "authorization_details": [{
            "type": "uam_contact", "actions": ["message"],
            "locations": locations or ["shared"],
        }],
        "via": via, "enforcer": settings.relay_domain,
        "validFrom": _stamp(now), "validUntil": _stamp(now + GRANT_TTL), "nonce": _nonce(),
    }


async def _ask(
    session: AsyncSession, settings, owner: Owner, purpose: str, held: dict[str, Any],
    items: list[tuple[str, dict[str, Any]]], screen: str, signer: OwnerPasskey,
) -> dict[str, Any]:
    """Store a challenge over *items* as *screen* shows them, for *signer*.

    *held* is what the finish route needs back; it names the key log entry
    whose passkeys may sign and the one that will.
    """
    held = {**held, "signer": signer.did}
    challenge = _b64u(approval_challenge(
        [(kind, object_hash(body)) for kind, body in items], screen
    ))
    now = service.utcnow()
    await owner_crud.add_challenge(
        session, owner_pk=owner.id, purpose=purpose, challenge=challenge, now=now,
        expires_at=now + CHALLENGE_TTL, body=canonical(held).decode(), screen=screen,
    )
    await session.commit()
    return {
        "items": [
            {"type": kind, "body": canonical(body).decode(), "hash": object_hash(body)}
            for kind, body in items
        ],
        "screen": screen, "challenge": challenge,
        "allowCredentials": [signer.credential_id], "rpId": settings.rp_id,
    }


async def _approved(
    session: AsyncSession, settings, owner: Owner, purpose: str, assertion: dict[str, str]
):
    row, held, signer = await _assert(session, settings, owner, purpose, assertion)
    if signer.did != held["signer"]:
        await session.rollback()
        raise _refused(400, "bad_signer", "That passkey can't approve this.")
    return row, held, signer


def _proof(row, signer: OwnerPasskey, assertion: dict[str, str]) -> dict[str, str]:
    return {
        "signer": signer.did, "authenticator_data": assertion["authenticatorData"],
        "client_data_json": assertion["clientDataJSON"], "signature": assertion["signature"],
        "screen": row.screen,
    }


def _grant_row(owner: Owner, grant: dict[str, Any], proof: dict[str, str], **values) -> OwnerGrant:
    subject = grant["credentialSubject"]
    return OwnerGrant(
        owner_pk=owner.id, body=canonical(grant).decode(), hash=object_hash(grant),
        subject_kind=subject["kind"], via=grant["via"],
        valid_until=_parse(grant["validUntil"]),
        **proof, **values,
    )


def _parse(stamp: str) -> datetime:
    return _parse_time(stamp)


# --- invites (the inviter) --------------------------------------------------------


def _state(invite: OwnerInvite, now: datetime) -> str:
    if invite.state == "open" and _aware(invite.redeem_by) <= now:
        return "expired"
    return invite.state


async def view(session: AsyncSession, vault: EmailVault, invite: OwnerInvite) -> dict[str, Any]:
    now = service.utcnow()
    out: dict[str, Any] = {
        "id": invite.id, "how": invite.how, "mode": invite.mode,
        "state": _state(invite, now), "words": invite_words(invite.hash),
        "redeemBy": _stamp(invite.redeem_by), "createdAt": _stamp(invite.created_at),
    }
    if invite.email_enc:
        out["email"] = vault.decrypt(invite.email_enc)
        out["sendAt"] = _stamp(invite.send_at) if invite.send_at else None
        out["sent"] = invite.sent_at is not None
    redemption = await crud.redemption_of(session, invite.hash)
    if redemption is not None:
        out["invitee"] = await _person(session, vault, redemption.owner_pk)
    return out


async def _room(session: AsyncSession, owner: Owner, now: datetime) -> None:
    if (await crud.open_invites(session, owner.id, now) >= MAX_OPEN
            or await crud.invites_since(session, owner.id, now - timedelta(days=1)) >= MAX_A_DAY):
        raise _refused(429, "too_many", "You have too many invites open. Cancel one first.")


def _invite_body(
    settings, owner: Owner, keys_hash: str, secret: str, mode: str, ttl: timedelta,
    now: datetime, email: str | None = None,
) -> dict[str, Any]:
    nonce = _nonce()
    body = {
        "type": INVITE, "v": 1, "inviter": _owner_ref(settings, owner, keys_hash),
        "offer": dict(_SHARED), "ask": dict(_SHARED), "secretHash": secret_hash(secret),
        "mode": mode, "maxUses": 1, "validFrom": _stamp(now), "redeemBy": _stamp(now + ttl),
        "nonce": nonce,
    }
    if email is not None:
        body["emailHash"] = email_hash(nonce, email)
    return body


def _link(settings, invite: OwnerInvite, secret: str) -> str:
    return f"{settings.owner_origin}/i/{invite.link_id}#{secret}"


async def make_invite(
    session: AsyncSession, settings, vault: EmailVault, owner: Owner, how: str
) -> dict[str, Any]:
    """A code (10 minutes) or a link (7 days). The inviter confirms later."""
    keys_hash = await _head(session, owner)
    now = service.utcnow()
    await _room(session, owner, now)
    secret = new_secret()
    body = _invite_body(settings, owner, keys_hash, secret, "confirm",
                        CODE_TTL if how == "code" else LINK_TTL, now)
    digest = object_hash(body)
    code = new_link_code() if how == "code" else None
    invite = OwnerInvite(
        owner_pk=owner.id, body=canonical(body).decode(), hash=digest, link_id=invite_id(digest),
        mode="confirm", how=how, secret=secret if code else None,
        code_hash=vault.invite_code_hash(code) if code else None,
        redeem_by=now + (CODE_TTL if code else LINK_TTL), created_at=now,
    )
    session.add(invite)
    await session.flush()
    await owner_crud.audit(session, owner.id, "invite_made", {"invite": invite.id, "how": how})
    await session.commit()
    out = await view(session, vault, invite)
    if code:
        out["code"] = show_code(code)
    else:
        out["link"] = _link(settings, invite, secret)
    return out


async def email_start(
    session: AsyncSession, settings, vault: EmailVault, owner: Owner, email: str,
    credential_id: str | None,
) -> dict[str, Any]:
    """A pre-approved invite: the inviter signs it and their grant at once."""
    keys_hash = await _head(session, owner)
    if vault.lookup(email) in {e.email_hmac for e in await _email_rows(session, owner.id)}:
        raise _refused(409, "own_invite", "That's your own email.")
    now = service.utcnow()
    await _room(session, owner, now)
    signer = await _signer(session, owner, keys_hash, credential_id)
    secret = new_secret()
    invite = _invite_body(settings, owner, keys_hash, secret, "preapproved", LINK_TTL, now, email)
    grant = _grant_body(settings, owner, signer.did,
                        {"kind": "invitee", "invite": object_hash(invite)}, VIA["email"], now)
    held = {
        "owner": {"keysHash": keys_hash}, "invite": canonical(invite).decode(),
        "grant": canonical(grant).decode(), "secret": secret, "email": vault.encrypt(email),
    }
    return await _ask(session, settings, owner, "invite", held,
                      [(INVITE, invite), (GRANT, grant)], invite_screen(grant, email), signer)


async def _email_rows(session: AsyncSession, owner_pk: int) -> list[OwnerEmail]:
    return list((await session.execute(
        select(OwnerEmail).where(OwnerEmail.owner_pk == owner_pk)
    )).scalars())


async def email_finish(
    session: AsyncSession, settings, vault: EmailVault, owner: Owner, assertion: dict[str, str]
) -> dict[str, Any]:
    row, held, signer = await _approved(session, settings, owner, "invite", assertion)
    now = service.utcnow()
    try:
        await _room(session, owner, now)
    except PasskeyError:
        await session.rollback()
        raise
    body = parse_body(held["invite"])
    grant = parse_body(held["grant"])
    email = vault.decrypt(held["email"])
    digest = object_hash(body)
    invite = OwnerInvite(
        owner_pk=owner.id, body=held["invite"], hash=digest, link_id=invite_id(digest),
        mode="preapproved", how="email", secret=held["secret"],
        email_hmac=vault.lookup(email), email_enc=held["email"],
        redeem_by=_parse(body["redeemBy"]), send_at=now + EMAIL_UNDO, created_at=now,
    )
    session.add(invite)
    await session.flush()
    session.add(_grant_row(owner, grant, _proof(row, signer, assertion), invite_pk=invite.id))
    await owner_crud.audit(session, owner.id, "invite_made", {"invite": invite.id, "how": "email"})
    await session.commit()
    return await view(session, vault, invite)


async def send_due(session: AsyncSession, app) -> int:
    """Send each pre-approved invite whose undo time has passed. Returns how many."""
    settings = app.state.settings
    vault = app.state.owner_vault
    sink: InviteEmail | None = getattr(app.state, "owner_invite_email_sink", None)
    if sink is None:
        sink = log_invite_email if settings.owner_codes_to_log else drop_invite_email
    now = service.utcnow()
    sent = 0
    for invite in await crud.emails_due(session, now):
        if not await crud.mark_sent(session, invite.id, now):
            continue
        await session.commit()
        try:
            sink(vault.decrypt(invite.email_enc), _link(settings, invite, invite.secret),
                 await _email_of(session, vault, invite.owner_pk))
            sent += 1
        except Exception:
            log.exception("sending invite %s failed", invite.id)
    return sent


async def list_invites(session: AsyncSession, vault: EmailVault, owner: Owner) -> list[dict[str, Any]]:
    return [await view(session, vault, i) for i in await crud.invites_for_owner(session, owner.id)]


async def _owned(session: AsyncSession, owner: Owner, invite_pk: int) -> OwnerInvite:
    invite = await crud.invite_for_owner(session, owner.id, invite_pk)
    if invite is None:
        raise _refused(404, "no_invite", "No such invite.")
    return invite


async def cancel(
    session: AsyncSession, vault: EmailVault, owner: Owner, invite_pk: int
) -> dict[str, Any]:
    """End an invite that hasn't connected anyone. No passkey: it only narrows.
    Declining a redeemed one also withdraws the invitee's grant, which was
    given for this invite."""
    invite = await _owned(session, owner, invite_pk)
    now = service.utcnow()
    if not await crud.move_invite(session, invite.id, crud.OPEN, state="cancelled", ended_at=now):
        raise _refused(409, "not_cancellable", "Only an invite that hasn't connected can be cancelled.")
    for grant in await crud.grants_for_invite(session, invite.id):
        await crud.revoke(session, grant, now)
    await crud.add_revocation(session, INVITE, invite.hash, now)
    await owner_crud.audit(session, owner.id, "invite_cancelled", {"invite": invite.id})
    await session.commit()
    await session.refresh(invite)
    return await view(session, vault, invite)


# --- invites (the invitee) --------------------------------------------------------


async def _alert_reuse(
    session: AsyncSession, notice: ContactNotice, invite_pk: int, inviter_pk: int
) -> None:
    """Someone else tried an invite already used: tell its owner."""
    await owner_crud.audit(session, inviter_pk, "invite_reused", {"invite": invite_pk})
    await session.commit()
    notice(inviter_pk, "invite_reused", {"invite": invite_pk})


def _used() -> PasskeyError:
    return _refused(409, "used", "This invite has already been used.")


def _ended() -> PasskeyError:
    return _refused(410, "invite_ended", "This invite has ended. Ask for a new one.")


async def _locate(
    session: AsyncSession, vault: EmailVault, owner: Owner, key: dict[str, str],
    notice: ContactNotice,
) -> OwnerInvite:
    """The invite *key* opens for *owner*, or a refusal. Wrong codes and
    secrets count: 5 in 10 minutes lock the account out."""
    if owner.owner_id is None:
        raise _no_passkey()
    now = service.utcnow()
    await crud.drop_tries_before(session, owner.id, now - TRY_WINDOW)
    if await crud.tries_since(session, owner.id, now - TRY_WINDOW) >= TRIES:
        await session.commit()
        raise _refused(429, "too_many_tries", "Too many tries. Wait ten minutes.")
    invite = None
    if "code" in key:
        code = normalise_link_code(key["code"])
        if code is not None:
            invite = await crud.invite_by_code_hash(session, vault.invite_code_hash(code))
    else:
        invite = await crud.invite_by_link_id(session, key["link"])
        if invite is not None and not hmac.compare_digest(
            secret_hash(key["secret"]), parse_body(invite.body)["secretHash"]
        ):
            invite = None
    if invite is None:
        await crud.add_try(session, owner.id, now)
        await session.commit()
        raise _refused(404, "no_invite", "That didn't open an invite. Check it and try again.")
    if invite.owner_pk == owner.id:
        raise _refused(409, "own_invite", "That's your own invite.")
    redemption = await crud.redemption_of(session, invite.hash)
    if redemption is not None:
        if redemption.owner_pk != owner.id:
            await _alert_reuse(session, notice, invite.id, invite.owner_pk)
        raise _used()
    if _state(invite, now) != "open":
        raise _ended()
    if invite.mode == "preapproved":
        body = parse_body(invite.body)
        mine = await _emails(session, vault, owner.id)
        if not any(email_hash(body["nonce"], e) == body["emailHash"] for e in mine):
            raise _refused(403, "not_for_you", "This invite is for another email address.")
    return invite


async def find(
    session: AsyncSession, vault: EmailVault, owner: Owner, key: dict[str, str],
    notice: ContactNotice,
) -> dict[str, Any]:
    invite = await _locate(session, vault, owner, key, notice)
    return {
        "inviter": await _person(session, vault, invite.owner_pk),
        "words": invite_words(invite.hash), "mode": invite.mode, "how": invite.how,
        "redeemBy": _stamp(invite.redeem_by),
    }


async def redeem_start(
    session: AsyncSession, settings, vault: EmailVault, owner: Owner, key: dict[str, str],
    credential_id: str | None, notice: ContactNotice,
) -> dict[str, Any]:
    invite = await _locate(session, vault, owner, key, notice)
    keys_hash = await _head(session, owner)
    signer = await _signer(session, owner, keys_hash, credential_id)
    now = service.utcnow()
    inviter = await session.get(Owner, invite.owner_pk)
    inviter_head = await owner_crud.key_log_head(session, inviter.id)
    redemption = {
        "type": REDEMPTION, "v": 1, "invite": invite.hash,
        "secret": invite.secret or key["secret"],
        "invitee": _owner_ref(settings, owner, keys_hash), "issuer": signer.did,
        "createdAt": _stamp(now), "nonce": _nonce(),
    }
    grant = _grant_body(
        settings, owner, signer.did,
        {"kind": "owner", "owner": _owner_ref(settings, inviter, inviter_head.hash)},
        VIA[invite.how], now,
    )
    held = {
        "owner": {"keysHash": keys_hash}, "invite": invite.id, "inviter": inviter.id,
        "redemption": canonical(redemption).decode(), "grant": canonical(grant).decode(),
    }
    screen = redeem_screen(grant, await _email_of(session, vault, inviter.id))
    return await _ask(session, settings, owner, "redeem", held,
                      [(REDEMPTION, redemption), (GRANT, grant)], screen, signer)


async def redeem(
    session: AsyncSession, settings, vault: EmailVault, owner: Owner, assertion: dict[str, str],
    notice: ContactNotice,
) -> dict[str, Any]:
    row, held, signer = await _approved(session, settings, owner, "redeem", assertion)
    invite = await session.get(OwnerInvite, held["invite"])
    now = service.utcnow()
    if invite is None:
        await session.rollback()
        raise _ended()
    # Read before anything commits or rolls back (which expires the row).
    invite_pk, inviter_pk, digest, mode = invite.id, invite.owner_pk, invite.hash, invite.mode
    owner_pk = owner.id

    async def lost() -> PasskeyError:
        await session.rollback()
        if await crud.redemption_of(session, digest) is not None:
            await _alert_reuse(session, notice, invite_pk, inviter_pk)
            return _used()
        return _ended()

    if _state(invite, now) != "open":
        raise await lost()
    redemption = parse_body(held["redemption"])
    grant = parse_body(held["grant"])
    proof = _proof(row, signer, assertion)
    session.add(InviteRedemption(
        invite_hash=digest, invite_pk=invite_pk, owner_pk=owner_pk,
        body=held["redemption"], hash=object_hash(redemption), created_at=now, **proof,
    ))
    try:
        await session.flush()
    except IntegrityError:
        raise await lost() from None
    connected = mode == "preapproved"
    if not await crud.move_invite(session, invite_pk, ("open",),
                                  state="connected" if connected else "redeemed",
                                  ended_at=now if connected else None):
        raise await lost()
    session.add(_grant_row(owner, grant, proof, subject_owner_pk=held["inviter"],
                           invite_pk=invite_pk))
    if connected:
        for theirs in await crud.grants_for_invite(session, invite_pk):
            if theirs.subject_kind == "invitee":
                theirs.subject_owner_pk = owner_pk
    await owner_crud.audit(session, owner_pk, "invite_redeemed", {"invite": invite_pk})
    await owner_crud.audit(session, inviter_pk, "invite_redeemed", {"invite": invite_pk})
    await session.commit()
    notice(inviter_pk, "invite_redeemed", {
        "invite": invite_pk, "email": await _email_of(session, vault, owner_pk),
        "connected": connected,
    })
    return {"state": "connected" if connected else "waiting_for_them",
            "inviter": await _person(session, vault, inviter_pk)}


async def confirm_start(
    session: AsyncSession, settings, vault: EmailVault, owner: Owner, invite_pk: int,
    credential_id: str | None,
) -> dict[str, Any]:
    invite = await _owned(session, owner, invite_pk)
    if invite.state != "redeemed":
        raise _refused(409, "not_waiting", "This invite isn't waiting for you.")
    redemption = await crud.redemption_of(session, invite.hash)
    keys_hash = await _head(session, owner)
    signer = await _signer(session, owner, keys_hash, credential_id)
    invitee = parse_body(redemption.body)["invitee"]
    grant = _grant_body(settings, owner, signer.did, {"kind": "owner", "owner": invitee},
                        VIA[invite.how], service.utcnow())
    held = {"owner": {"keysHash": keys_hash}, "invite": invite.id,
            "invitee": redemption.owner_pk, "grant": canonical(grant).decode()}
    screen = confirm_screen(grant, await _email_of(session, vault, redemption.owner_pk))
    return await _ask(session, settings, owner, "confirm", held, [(GRANT, grant)], screen, signer)


async def confirm(
    session: AsyncSession, settings, vault: EmailVault, owner: Owner, invite_pk: int,
    assertion: dict[str, str], notice: ContactNotice,
) -> dict[str, Any]:
    invite = await _owned(session, owner, invite_pk)
    row, held, signer = await _approved(session, settings, owner, "confirm", assertion)
    now = service.utcnow()
    if held["invite"] != invite.id or not await crud.move_invite(
        session, invite.id, ("redeemed",), state="connected", ended_at=now
    ):
        await session.rollback()
        raise _refused(409, "not_waiting", "This invite isn't waiting for you.")
    grant = parse_body(held["grant"])
    session.add(_grant_row(owner, grant, _proof(row, signer, assertion),
                           subject_owner_pk=held["invitee"], invite_pk=invite.id))
    await owner_crud.audit(session, owner.id, "invite_confirmed", {"invite": invite.id})
    await session.commit()
    notice(held["invitee"], "contact_confirmed", {
        "invite": invite.id, "email": await _email_of(session, vault, owner.id),
    })
    await session.refresh(invite)
    return await view(session, vault, invite)


# --- contacts ---------------------------------------------------------------------


async def list_contacts(session: AsyncSession, vault: EmailVault, owner: Owner) -> list[dict[str, Any]]:
    """Everyone this owner approved or who approved them, with grants in force."""
    now = service.utcnow()
    mine: dict[int, OwnerGrant] = {}
    for grant in await crud.live_grants_from(session, owner.id, now):
        mine.setdefault(grant.subject_owner_pk, grant)
    theirs: dict[int, OwnerGrant] = {}
    for grant in await crud.live_grants_naming(session, owner.id, now):
        theirs.setdefault(grant.owner_pk, grant)
    out = []
    for other in set(mine) | set(theirs):
        first = mine.get(other) or theirs[other]
        person = await _person(session, vault, other)
        out.append({
            **person,
            "youAllow": other in mine, "theyAllow": other in theirs, "via": first.via,
            "until": _stamp(mine[other].valid_until if other in mine else theirs[other].valid_until),
            "connectedAt": _stamp(min(g.created_at for g in (mine.get(other), theirs.get(other)) if g)),
            "agents": [
                {"address": link.agent_address, "words": words_for(link.agent_key)}
                for link in await crud.shared_links(session, other, now)
            ],
        })
    return sorted(out, key=lambda c: c["email"])


async def remove(
    session: AsyncSession, vault: EmailVault, owner: Owner, other_owner_id: str
) -> dict[str, Any]:
    """Stop someone's agents messaging yours. No passkey: it only narrows."""
    other = await owner_crud.owner_by_owner_id(session, other_owner_id)
    now = service.utcnow()
    grants = [] if other is None else [
        g for g in await crud.live_grants_from(session, owner.id, now)
        if g.subject_owner_pk == other.id
    ]
    if not grants:
        raise _refused(404, "no_contact", "You haven't approved this person.")
    for grant in grants:
        await crud.revoke(session, grant, now)
    await owner_crud.audit(session, owner.id, "contact_removed", {"owner": other_owner_id})
    await session.commit()
    return {"contacts": await list_contacts(session, vault, owner)}


# --- the revocation list ----------------------------------------------------------


async def revocations(session: AsyncSession, settings, signing_key, since: int) -> dict[str, Any]:
    """Entries after *since*, in order; signed by the relay when it has a key."""
    rows = await crud.revocations_after(session, since, REVOCATIONS_PAGE)
    listing: dict[str, Any] = {
        "relay": settings.relay_domain, "since": since,
        "through": rows[-1].seq if rows else since,
        "entries": [{"t": r.t, "h": r.h, "at": _stamp(r.at)} for r in rows],
    }
    if signing_key is not None:
        listing["signature"] = sign_message(revocations_message(listing), signing_key)
    return listing


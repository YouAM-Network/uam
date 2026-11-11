"""Owner passkeys and the key log (P2c-2, ships dark).

A signed-in owner registers a passkey (create), then signs the key log
entry that adds it (get). The first entry makes the owner id. Later
passkeys are added by entries signed with a passkey already in the log.
Anyone can fetch an owner's key log and verify it.
"""

from __future__ import annotations

import pytest

from tests._passkey import SoftPasskey, b64u
from tests.relay._owner_fixtures import (  # noqa: F401  (fixtures are used by name)
    OWNER_ORIGIN,
    _exec,
    _on_owner_host,
    _rows,
    _sign_in,
    clock,
    codes,
    owner,
    owner_env,
    relay,
)
from uam.protocol.keylog import entry_challenge, verify_key_log
from uam.protocol.signed import object_hash, parse_body

RP_ID = "test.local"


@pytest.fixture()
def ada(relay, owner, codes):
    """A signed-in owner with no passkeys yet."""
    _sign_in(relay, owner, codes)
    return owner


def _start(client):
    resp = client.post("/api/owner/passkeys/register/start")
    assert resp.status_code == 200, resp.text
    return resp.json()


def _finish(client, made, label="Ada phone"):
    return client.post("/api/owner/passkeys/register/finish", json={
        "attestationObject": made["attestationObject"],
        "clientDataJSON": made["clientDataJSON"],
        "label": label,
    })


def _register(client, passkey, label="Ada phone"):
    resp = _finish(client, passkey.create(_start(client), OWNER_ORIGIN), label)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _sign(client, passkey, approval, *, origin=OWNER_ORIGIN):
    got = passkey.get(approval["challenge"], rp_id=RP_ID, origin=origin)
    return client.post("/api/owner/keys/sign", json=got)


def _first_passkey(ada, label="Ada phone"):
    phone = SoftPasskey()
    approval = _register(ada, phone, label)
    resp = _sign(ada, phone, approval)
    assert resp.status_code == 200, resp.text
    return phone, resp.json()


def _log(client, owner_id, since=None):
    url = f"/api/owner/keys/{owner_id}" + (f"?since={since}" if since is not None else "")
    return client.get(url)


# ---------------------------------------------------------------- registering


def test_registration_options_ask_for_a_verified_discoverable_es256_passkey(ada):
    options = _start(ada)
    assert options["rp"] == {"id": RP_ID, "name": "YouAM"}
    assert options["pubKeyCredParams"] == [{"type": "public-key", "alg": -7}]
    assert options["authenticatorSelection"] == {
        "residentKey": "required", "requireResidentKey": True, "userVerification": "required",
    }
    assert options["attestation"] == "none"
    assert options["user"]["name"] == "ada@example.com"
    assert options["excludeCredentials"] == []
    assert len(options["challenge"]) == 43


def test_the_user_handle_is_stable_and_says_nothing(ada):
    first, second = _start(ada)["user"]["id"], _start(ada)["user"]["id"]
    assert first == second
    assert "ada" not in first.lower() and first != "1"


def test_finishing_a_registration_asks_to_sign_entry_zero(ada):
    phone = SoftPasskey()
    approval = _register(ada, phone)
    body = parse_body(approval["body"])
    assert body["seq"] == 0
    assert body["owner"] == {"relay": "test.local"}
    [key] = body["keys"]
    assert key["label"] == "Ada phone" and key["rpId"] == RP_ID
    assert approval["hash"] == object_hash(body)
    assert approval["screen"] == (
        'Make "Ada phone" the first passkey of your YouAM account on test.local.'
    )
    assert approval["challenge"] == b64u(entry_challenge(approval["hash"], approval["screen"]))
    assert approval["allowCredentials"] == [phone.id]
    assert approval["rpId"] == RP_ID


def test_signing_entry_zero_makes_the_owner_id(ada):
    phone, signed = _first_passkey(ada)
    assert signed["seq"] == 0
    assert len(signed["owner_id"]) == 22
    assert ada.get("/api/owner/me").json()["owner_id"] == signed["owner_id"]
    [listed] = ada.get("/api/owner/passkeys").json()["passkeys"]
    assert listed["id"] == phone.id and listed["label"] == "Ada phone"


def test_the_key_log_is_public_and_verifies(ada, relay):
    _, signed = _first_passkey(ada)
    for client in (ada, relay):
        resp = _log(client, signed["owner_id"])
        assert resp.status_code == 200, resp.text
        entries = resp.json()["entries"]
        log = verify_key_log(entries, rp_id=RP_ID, origin=OWNER_ORIGIN)
        assert log.owner_id == signed["owner_id"]


def test_a_second_passkey_is_signed_for_by_the_first(ada, relay):
    phone, signed = _first_passkey(ada)
    options = _start(ada)
    assert options["excludeCredentials"] == [{"type": "public-key", "id": phone.id}]
    laptop = SoftPasskey(backup_eligible=False, counter=1)
    approval = _finish(ada, laptop.create(options, OWNER_ORIGIN), "Ada laptop").json()
    assert parse_body(approval["body"])["seq"] == 1
    assert approval["allowCredentials"] == [phone.id]
    assert approval["rpId"] == RP_ID
    assert approval["screen"] == 'Add the passkey "Ada laptop" to your YouAM account.'
    assert _sign(ada, phone, approval).status_code == 200
    entries = _log(relay, signed["owner_id"]).json()["entries"]
    log = verify_key_log(entries, rp_id=RP_ID, origin=OWNER_ORIGIN)
    assert log.seq == 1 and len(log.keys) == 2
    assert [p["label"] for p in ada.get("/api/owner/passkeys").json()["passkeys"]] == [
        "Ada phone", "Ada laptop",
    ]
    assert len(_log(relay, signed["owner_id"], since=1).json()["entries"]) == 1


# ---------------------------------------------------------------- refusals


def test_a_registration_from_another_origin_is_refused(ada):
    made = SoftPasskey().create(_start(ada), "https://evil.example")
    assert _finish(ada, made).status_code == 400
    assert _rows(ada, "SELECT id FROM owner_passkeys") == []


def test_a_registration_challenge_works_once(ada):
    options = _start(ada)
    assert _finish(ada, SoftPasskey().create(options, OWNER_ORIGIN)).status_code == 200
    assert _finish(ada, SoftPasskey().create(options, OWNER_ORIGIN)).status_code == 400


def test_a_registration_challenge_lasts_five_minutes(ada, clock):
    options = _start(ada)
    clock(minutes=5, seconds=1)
    assert _finish(ada, SoftPasskey().create(options, OWNER_ORIGIN)).status_code == 400


def test_an_approval_challenge_lasts_five_minutes(ada, clock):
    phone = SoftPasskey()
    approval = _register(ada, phone)
    clock(minutes=5, seconds=1)
    assert _sign(ada, phone, approval).status_code == 400
    assert ada.get("/api/owner/me").json()["owner_id"] is None
    assert ada.get("/api/owner/passkeys").json()["passkeys"] == []


def test_an_approval_works_once(ada):
    phone = SoftPasskey()
    approval = _register(ada, phone)
    assert _sign(ada, phone, approval).status_code == 200
    assert _sign(ada, phone, approval).status_code == 400


def test_an_approval_from_another_origin_is_refused(ada):
    phone = SoftPasskey()
    approval = _register(ada, phone)
    assert _sign(ada, phone, approval, origin="https://evil.example").status_code == 400
    assert ada.get("/api/owner/me").json()["owner_id"] is None


def test_a_new_passkey_cannot_sign_its_own_addition(ada):
    _first_passkey(ada)
    laptop = SoftPasskey()
    approval = _register(ada, laptop, "laptop")
    assert _sign(ada, laptop, approval).json()["error"] == "bad_signer"
    assert len(_rows(ada, "SELECT seq FROM owner_key_log")) == 1


def test_a_refused_approval_is_used_up(ada):
    phone, _ = _first_passkey(ada)
    laptop = SoftPasskey()
    approval = _register(ada, laptop, "laptop")
    assert _sign(ada, laptop, approval).status_code == 400
    assert _sign(ada, phone, approval).json()["error"] == "bad_challenge"


def test_a_held_passkey_cannot_sign_a_later_entry(ada):
    phone, _ = _first_passkey(ada)
    laptop = SoftPasskey()
    _register(ada, laptop, "laptop")  # held: its entry isn't signed
    tablet = SoftPasskey()
    approval = _register(ada, tablet, "tablet")
    assert _sign(ada, laptop, approval).status_code == 400


def test_a_counter_that_goes_down_is_refused(ada):
    phone = SoftPasskey(counter=5)
    assert _sign(ada, phone, _register(ada, phone)).status_code == 200  # counter now 6
    approval = _register(ada, SoftPasskey(), "laptop")
    phone.counter = 5  # its next answer says 6 again: a copy of the passkey
    assert _sign(ada, phone, approval).status_code == 400


def test_two_first_entries_cannot_both_land(ada):
    phone, tablet = SoftPasskey(), SoftPasskey()
    first = _register(ada, phone, "phone")
    second = _register(ada, tablet, "tablet")
    assert _sign(ada, phone, first).status_code == 200
    assert _sign(ada, tablet, second).status_code == 409
    assert len(_rows(ada, "SELECT seq FROM owner_key_log")) == 1


def test_two_pending_entries_cannot_both_land(ada):
    """Two registrations each built entry 1; once one is signed the other
    no longer follows the head, so the log can't fork."""
    phone, _ = _first_passkey(ada)
    first = _register(ada, SoftPasskey(), "laptop")
    second = _register(ada, SoftPasskey(), "tablet")
    assert _sign(ada, phone, first).status_code == 200
    resp = _sign(ada, phone, second)
    assert resp.status_code == 409
    assert len(_rows(ada, "SELECT seq FROM owner_key_log")) == 2


@pytest.mark.parametrize(
    "label", ["", "x" * 65, "Ada’s phone", "tab\there", 'Laptop" to your account. Remove "Phone'],
)
def test_a_passkey_label_is_short_plain_text(ada, label):
    made = SoftPasskey().create(_start(ada), OWNER_ORIGIN)
    assert _finish(ada, made, label).status_code == 422


def test_a_label_may_hold_other_punctuation(ada):
    made = SoftPasskey().create(_start(ada), OWNER_ORIGIN)
    assert _finish(ada, made, "Ada's phone (work) #2").status_code == 200


def test_an_owner_has_at_most_sixteen_passkeys(ada, monkeypatch):
    from uam.relay.owners import passkeys

    monkeypatch.setattr(passkeys, "MAX_PASSKEYS", 2)
    phone, _ = _first_passkey(ada)
    assert _sign(ada, phone, _register(ada, SoftPasskey(), "laptop")).status_code == 200
    assert ada.post("/api/owner/passkeys/register/start").status_code == 409


def test_passkey_routes_need_a_session(relay, owner):
    for path in ("/api/owner/passkeys/register/start", "/api/owner/passkeys/register/finish",
                 "/api/owner/keys/sign"):
        assert owner.post(path, json={}).status_code == 401
    assert owner.get("/api/owner/passkeys").status_code == 401


def test_passkey_writes_need_the_owner_origin(ada):
    cross = _on_owner_host(ada.app, ada, origin="https://evil.example")
    cross.cookies = ada.cookies
    assert cross.post("/api/owner/passkeys/register/start").status_code == 403


def test_a_frozen_owner_cannot_add_passkeys(ada):
    phone = SoftPasskey()
    approval = _register(ada, phone)
    _exec(ada, "UPDATE owners SET status = 'frozen'")
    assert _sign(ada, phone, approval).status_code == 401


def test_an_unknown_key_log_is_404(relay):
    assert _log(relay, "A" * 22).status_code == 404


def test_the_key_log_is_404_while_owners_are_off(app):
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        assert _log(c, "A" * 22).status_code == 404


def test_audit_records_each_signed_entry(ada):
    phone, _ = _first_passkey(ada)
    actions = [r["action"] for r in _rows(ada, "SELECT action FROM owner_audit ORDER BY id")]
    assert actions[-1] == "key_log_signed"

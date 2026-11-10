"""The owner page (P2c-2b): served at ``/`` on the owner origin.

One HTML file, one module script and two stylesheets, each pinned with an
SRI hash; no inline script or style anywhere. Before it asks a passkey to
sign, the page works out the sentence from the key log entry itself and
recomputes the challenge, and it stops if either differs from the relay's
(spec P2 §3.2). Those checks run here in Node, on entries the Python code
builds.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from tests._passkey import SoftPasskey, b64u, unb64u
from tests.relay._owner_fixtures import (  # noqa: F401  (fixtures are used by name)
    OWNER_ORIGIN,
    codes,
    owner,
    owner_env,
    relay,
)
from uam.protocol.keylog import entry_challenge, next_entry, screen_for
from uam.protocol.signed import canonical, object_hash

STATIC = Path(__file__).resolve().parents[2] / "src/uam/relay/owners/static"
CHECK = Path(__file__).with_name("owner_page_check.mjs")
RP_ID = "test.local"
ASSET = re.compile(r'<(?:script|link)\b[^>]*>')


def _attr(tag: str, name: str) -> str | None:
    m = re.search(rf'\b{name}="([^"]*)"', tag)
    return m.group(1) if m else None


def _sri(data: bytes) -> str:
    return "sha384-" + base64.b64encode(hashlib.sha384(data).digest()).decode()


# ---------------------------------------------------------------- serving


def test_the_page_is_served_at_the_root_of_the_owner_origin(owner):
    resp = owner.get("/")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert "default-src 'self'" in resp.headers["content-security-policy"]
    assert "<title>UAM account</title>" in resp.text


def test_every_asset_is_pinned_by_its_hash(owner):
    tags = ASSET.findall(owner.get("/").text)
    assets = [t for t in tags if _attr(t, "src") or _attr(t, "rel") == "stylesheet"]
    assert len(assets) == 3  # tokens.css, owner.css, owner.js
    for tag in assets:
        url = _attr(tag, "src") or _attr(tag, "href")
        assert re.fullmatch(r"/static/[a-z]+-[0-9a-f]{12}\.(css|js)", url), url
        resp = owner.get(url)
        assert resp.status_code == 200, url
        assert _attr(tag, "integrity") == _sri(resp.content), url


def test_assets_are_the_packaged_files(owner):
    page = owner.get("/").text
    for name, kind in [("tokens.css", "text/css"), ("owner.css", "text/css"),
                       ("owner.js", "text/javascript")]:
        stem, ext = name.split(".")
        [url] = re.findall(rf"/static/{stem}-[0-9a-f]{{12}}\.{ext}", page)
        resp = owner.get(url)
        assert resp.content == (STATIC / name).read_bytes()
        assert resp.headers["content-type"].startswith(kind)


def test_the_script_is_a_module(owner):
    [tag] = [t for t in ASSET.findall(owner.get("/").text) if t.startswith("<script")]
    assert _attr(tag, "type") == "module"


@pytest.mark.parametrize("path", [
    "/static/owner.js", "/static/tokens.css", "/static/owner-000000000000.js",
    "/static/..%2fapp.py", "/static/index.html", "/index.html",
])
def test_only_the_pinned_assets_are_served(owner, path):
    assert owner.get(path).status_code == 404


def test_the_relay_origin_does_not_serve_the_page(relay):
    resp = relay.get("/")
    assert "UAM account" not in resp.text
    assert relay.get("/static/owner.css").status_code == 404 or "--page" not in relay.get(
        "/static/owner.css").text


# ---------------------------------------------------------------- no inline code


def _html() -> str:
    return (STATIC / "index.html").read_text()


def _js() -> str:
    return (STATIC / "owner.js").read_text()


def test_the_html_has_no_inline_script_or_style():
    html = _html()
    assert "<style" not in html
    assert not re.search(r"\sstyle=", html)
    assert not re.search(r"\son[a-z]+=", html)
    assert "javascript:" not in html
    for tag in re.findall(r"<script\b[^>]*>", html):
        assert _attr(tag, "src"), tag
    assert not re.search(r"<script\b[^>]*>\s*[^<\s]", html)


def test_the_html_loads_nothing_from_elsewhere():
    for tag in ASSET.findall(_html()):
        url = _attr(tag, "src") or _attr(tag, "href")
        if url:
            assert url.startswith("{{"), tag  # filled in with /static/<name>-<hash>


@pytest.mark.parametrize("banned", [
    "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
    "new Function", "setAttribute(\"style", ".style.",
])
def test_the_script_never_writes_markup_or_styles(banned):
    assert banned not in _js()


def test_every_element_the_script_uses_is_in_the_page():
    ids = set(re.findall(r'\bid="([^"]+)"', _html()))
    used = set(re.findall(r'\$\("([^"]+)"\)', _js()))
    assert used, "the script looks up no elements"
    assert sorted(used - ids) == []


def test_the_page_uses_only_catalogued_classes():
    css = (STATIC / "owner.css").read_text()
    defined = set(re.findall(r"\.([a-z][a-z0-9-]*)", css))
    used = {c for attr in re.findall(r'\bclass="([^"]+)"', _html()) for c in attr.split()}
    assert sorted(used - defined) == []


# ---------------------------------------------------------------- the page's checks


def _key(passkey: SoftPasskey, label: str) -> dict:
    from uam.protocol.webauthn import verify_registration

    made = passkey.create({"rp": {"id": RP_ID}, "challenge": b64u(b"c" * 32)}, OWNER_ORIGIN)
    cred = verify_registration(
        attestation_object=unb64u(made["attestationObject"]),
        client_data_json=unb64u(made["clientDataJSON"]),
        challenge=b"c" * 32, origin=OWNER_ORIGIN, rp_id=RP_ID,
    )
    return {"id": cred.did, "rpId": RP_ID, "backupEligible": cred.backup_eligible, "label": label}


def _answer(body: dict, previous: dict | None, *, screen: str | None = None) -> dict:
    """What the relay's register/finish answers (screen= a lying relay)."""
    h = object_hash(body)
    shown = screen_for(body, previous) if screen is None else screen
    return {
        "body": canonical(body).decode(), "hash": h, "screen": shown,
        "challenge": b64u(entry_challenge(h, shown)), "allowCredentials": [], "rpId": RP_ID,
    }


def _consistent(text: str, screen: str) -> dict:
    """An answer whose hash, words and challenge all agree with *text*, as
    the page computes them, whatever *text* is."""
    h = b64u(hashlib.sha256(b"UAM-UamOwnerKeys-v1\n" + text.encode()).digest())
    return {"body": text, "hash": h, "screen": screen,
            "challenge": b64u(entry_challenge(h, screen)), "allowCredentials": [], "rpId": RP_ID}


def _entry(body: dict) -> dict:
    return {"body": canonical(body).decode(), "hash": object_hash(body)}


@pytest.fixture(scope="module")
def checked(tmp_path_factory):
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    k1, k2, k3 = (_key(SoftPasskey(), label) for label in
                  ("Ada iPhone", "Ada laptop", "Ada's \\ tablet"))
    e0 = next_entry(None, relay="test.local", add=[k1])
    two = next_entry(None, relay="test.local", add=[k1, k2])
    e1 = next_entry(e0, add=[k2])
    e2 = next_entry(e1, add=[k3])
    e3 = next_entry(e2, remove=[(k2["id"], "removed")])
    e4 = next_entry(e2, remove=[(k2["id"], "compromised")])

    good = _answer(e1, e0)
    approvals = {
        "first": (_answer(e0, None), None),
        "first_two": (_answer(two, None), None),
        "add": (good, _entry(e0)),
        "add_odd_label": (_answer(e2, e1), _entry(e1)),
        "remove": (_answer(e3, e2), _entry(e2)),
        "remove_compromised": (_answer(e4, e2), _entry(e2)),
        # A relay that shows one thing and asks for another to be signed.
        "lying_screen": (_answer(e1, e0, screen="Sign in to UAM."), _entry(e0)),
        "wrong_hash": ({**good, "hash": object_hash(e2)}, _entry(e0)),
        "swapped_body": ({**good, "body": canonical(e2).decode()}, _entry(e0)),
        "wrong_challenge": ({**good, "challenge": _answer(e2, e1)["challenge"]}, _entry(e0)),
        "no_previous": (good, None),
        "other_previous": (good, _entry(two)),
        "forged_previous": (good, {"body": canonical(two).decode(), "hash": object_hash(e0)}),
        "not_a_key_log": (_consistent(canonical(e1).decode().replace(
            '"type":"UamOwnerKeys"', '"type":"UamOwnerKeyz"'), screen_for(e1, e0)), _entry(e0)),
    }
    cases = {
        "approvals": [{"name": n, "answer": a, "previous": p} for n, (a, p) in approvals.items()],
        "labels": ["Ada iPhone", "Ada's laptop", "a" * 64, "~!#$%&()*+,-./:;<=>?@[\\]^_`{|}",
                   "", "a" * 65, 'Say "hi"', "Zoë", "tab\there", " ", "x\n"],
        "dates": ["2026-11-09T10:00:00Z", "2026-01-31T23:59:59Z"],
    }
    path = tmp_path_factory.mktemp("page") / "cases.json"
    path.write_text(json.dumps(cases))
    run = subprocess.run([node, str(CHECK), str(STATIC / "owner.js"), str(path)],
                         capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stderr
    out = json.loads(run.stdout)
    out["approvals"] = {a["name"]: a for a in out["approvals"]}
    out["expected"] = {n: a["screen"] for n, (a, _) in approvals.items()}
    return out


@pytest.mark.parametrize("name", ["first", "first_two", "add", "add_odd_label", "remove",
                                  "remove_compromised"])
def test_the_page_signs_what_the_relay_would(checked, name):
    result = checked["approvals"][name]
    assert result["ok"], result
    assert result["screen"] == checked["expected"][name]


def test_the_page_words_entry_zero_like_the_relay(checked):
    assert checked["approvals"]["first"]["screen"] == (
        'Make "Ada iPhone" the first passkey of your UAM owner account on test.local.'
    )


@pytest.mark.parametrize("name", ["lying_screen", "wrong_hash", "swapped_body", "wrong_challenge",
                                  "no_previous", "other_previous", "forged_previous",
                                  "not_a_key_log"])
def test_the_page_refuses_what_it_did_not_work_out_itself(checked, name):
    assert not checked["approvals"][name]["ok"], checked["approvals"][name]


def test_the_page_accepts_the_labels_the_relay_accepts(checked):
    from uam.relay.owners.app import FinishRegistration

    def relay_accepts(label: str) -> bool:
        try:
            FinishRegistration(attestationObject="a", clientDataJSON="c", label=label)
        except ValidationError:
            return False
        return True

    assert {k: v for k, v in checked["labels"].items()} == {
        k: relay_accepts(k) for k in checked["labels"]
    }
    assert sum(checked["labels"].values()) == 5  # " " too: the page trims before it checks


def test_the_page_says_when_a_passkey_was_added_in_utc(checked):
    assert checked["dates"] == {
        "2026-11-09T10:00:00Z": "9 Nov 2026", "2026-01-31T23:59:59Z": "31 Jan 2026",
    }

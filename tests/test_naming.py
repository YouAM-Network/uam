"""Names: UAM is the protocol, YouAM is what people see (docs/naming.md, DEC-008).

These tests fail when a change breaks the rule in either direction: the
brand "UAM" showing up in something people read, or a protocol name being
renamed. Protocol names are inside signatures, headers and DNS records
that other people's code already depends on, so they never change.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "uam"
STATIC = SRC / "relay" / "owners" / "static"
BRAND_UAM = re.compile(r"(?<![-_A-Za-z])UAM(?![-_A-Za-z])")  # "UAM" as a word, not UAM-*-v1 or UAM_*


def _read(rel: str) -> str:
    return (SRC / rel).read_text(encoding="utf-8")


def _people_text(html: str) -> str:
    """The text a person sees: no comments, tags, attributes or scripts."""
    html = re.sub(r"<!--.*?-->", "", html, flags=re.S)
    html = re.sub(r"<script.*?</script>", "", html, flags=re.S)
    return re.sub(r"<[^>]+>", " ", html)


def test_the_account_page_says_youam():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    seen = _people_text(html)
    assert "YouAM" in seen
    assert not BRAND_UAM.search(seen), "the account page shows 'UAM'; people see YouAM (docs/naming.md)"
    assert "<title>YouAM account</title>" in html


def test_the_header_is_the_youam_lockup_not_typed():
    """docs/design/owner-page/DESIGN.md rule 13: one lockup shape, never the name set in type."""
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert html.count('<symbol id="youam-logo"') == 1
    brands = html.split('<div class="brand">')[1:]
    assert brands, "no brand on the page"
    for brand in brands:
        inner = brand.split("</div>", 1)[0]
        assert '<use href="#youam-logo"/>' in inner and 'aria-label="YouAM"' in inner
        assert "YouAM" not in _people_text(inner), "the brand sets YouAM in type; use the lockup"


def test_sentences_a_passkey_signs_say_youam():
    sources = {
        "protocol/keylog.py": _read("protocol/keylog.py"),
        "protocol/links.py": _read("protocol/links.py"),
        "relay/owners/static/owner.js": (STATIC / "owner.js").read_text(encoding="utf-8"),
    }
    for name, text in sources.items():
        assert "your YouAM account" in text, name  # tests/protocol/test_links.py checks the full sentences
        assert "UAM owner account" not in text and "UAM account" not in text.replace("YouAM account", ""), name


def test_phones_save_the_passkey_under_youam():
    assert '"name": "YouAM"' in _read("relay/owners/passkeys.py")


@pytest.mark.parametrize(("rel", "names"), [
    ("protocol/links.py", ["UAM-AGENT-SIG-v1", "UAM-RELAY-SIG-v1", "UAM-WORDS-v1"]),
    ("protocol/webauthn.py", ["UAM-APPROVAL-v1"]),
    ("relay/owners/crypto.py", ["UAM-EMAIL-v1", "UAM-OWNER-SESSION-v1"]),
    ("relay/owners/static/owner.js", ["UAM-APPROVAL-v1", "UAM-WORDS-v1"]),
    ("relay/webhook.py", ["X-UAM-Signature"]),
    ("sdk/webhook_verify.py", ["X-UAM-Signature"]),
    ("relay/federation.py", ["_uam._tcp."]),
    ("protocol/envelope.py", ["uam_version"]),
])
def test_protocol_names_never_change(rel, names):
    path = SRC / rel if not rel.startswith("relay/owners/static") else STATIC / Path(rel).name
    text = path.read_text(encoding="utf-8")
    for name in names:
        assert name in text, f"{name} left {rel}: protocol names never change (docs/naming.md)"

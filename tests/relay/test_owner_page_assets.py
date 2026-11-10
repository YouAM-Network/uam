"""The owner page's stylesheets follow DESIGN.md's token rules.

docs/design/owner-page/DESIGN.md, rules 7-10: raw values live only in the
base layer of tokens.css; owner.css uses tokens; tokens.json is the same
tokens in DTCG form; both themes define the same meanings.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parents[2] / "src/uam/relay/owners/static"
RAW = [
    (re.compile(r"#[0-9a-fA-F]{3,8}\b"), "hex colour"),
    (re.compile(r"\b(?:rgba?|hsla?|oklch|lab|lch|color)\("), "colour function"),
    (re.compile(r"(?<![\w-])\d*\.?\d+px\b"), "px length"),
    (re.compile(r"(?<![\w-])\d*\.?\d+rem\b"), "rem length"),
]
NAMED = re.compile(
    r":\s*[^;{}]*(?<![\w-])(?:white|black|red|green|blue|gray|grey|orange|yellow|purple)(?![\w-])"
)


def _css(name: str) -> str:
    return re.sub(r"/\*.*?\*/", "", (STATIC / name).read_text(), flags=re.S)


def _blocks(css: str) -> list[tuple[str, dict[str, str]]]:
    """Each rule's selector and its custom properties, @media unwrapped."""
    out = []
    for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", css):
        props = dict(re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", m.group(2)))
        if props:
            out.append((" ".join(m.group(1).split()), props))
    return out


def _tokens() -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    blocks = _blocks(_css("tokens.css"))
    by_sel = {sel: props for sel, props in blocks}
    return (
        by_sel[":root"],
        by_sel[':root, [data-theme="dark"]'],
        by_sel['[data-theme="light"]'],
    )


def test_owner_css_holds_no_raw_values():
    found = []
    for n, line in enumerate(_css("owner.css").splitlines(), 1):
        if line.lstrip().startswith("@media"):
            continue  # var() can't be used in a media query
        for pattern, what in RAW:
            found += [f"line {n}: {what} {m.group(0)!r}" for m in pattern.finditer(line)]
        if NAMED.search(line):
            found.append(f"line {n}: named colour")
    assert found == []


def test_the_lint_catches_a_raw_value():
    line = ".x { color: #fff; padding: 4px; background: rgb(0 0 0); border: 1px solid red; }"
    hits = [what for pattern, what in RAW if pattern.search(line)]
    assert hits == ["hex colour", "colour function", "px length"]
    assert NAMED.search(line)


def test_owner_css_uses_only_tokens_that_exist():
    base, dark, light = _tokens()
    defined = set(base) | set(dark) | set(light)
    used = set(re.findall(r"var\((--[\w-]+)\)", _css("owner.css")))
    assert used, "owner.css uses no tokens"
    assert sorted(used - defined) == []


def test_owner_css_uses_meaning_tokens_not_base_colours():
    base, dark, _ = _tokens()
    colours = {k for k, v in base.items() if v.startswith(("#", "rgb"))}
    used = set(re.findall(r"var\((--[\w-]+)\)", _css("owner.css")))
    assert sorted(used & colours) == []


def test_raw_values_live_only_in_the_base_layer():
    _, dark, light = _tokens()
    for props in (dark, light):
        assert all(re.fullmatch(r"var\(--[\w-]+\)", v.strip()) for v in props.values())


def test_both_themes_define_the_same_meanings():
    _, dark, light = _tokens()
    assert set(dark) == set(light)


def test_the_system_light_theme_matches_the_forced_one():
    blocks = _blocks(_css("tokens.css"))
    system = [p for sel, p in blocks if sel == ':root:not([data-theme="dark"])']
    _, _, forced = _tokens()
    assert system == [forced]


def _flatten(tree: dict, prefix: str = "") -> dict[str, dict]:
    out = {}
    for key, value in tree.items():
        if key.startswith("$"):
            continue
        if isinstance(value, dict) and "$value" in value:
            out[prefix + key] = value
        elif isinstance(value, dict):
            out.update(_flatten(value, f"{prefix}{key}."))
    return out


def _resolve(ref: str) -> str:
    return re.sub(r"^\{base\.([\w-]+)\}$", r"var(--\1)", ref)


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_tokens_json_matches_tokens_css(theme):
    base, dark, light = _tokens()
    flat = _flatten(json.loads((STATIC / "tokens.json").read_text()))
    json_base = {f"--{k[5:]}": v["$value"] for k, v in flat.items() if k.startswith("base.")}
    assert json_base == {k: v.strip() for k, v in base.items()}
    meaning = dark if theme == "dark" else light
    prefix = f"meaning.{theme}."
    json_meaning = {
        f"--{k[len(prefix):]}": _resolve(v["$value"])
        for k, v in flat.items()
        if k.startswith(prefix)
    }
    assert json_meaning == {k: v.strip() for k, v in meaning.items()}


def test_every_json_token_has_a_type():
    flat = _flatten(json.loads((STATIC / "tokens.json").read_text()))
    assert flat
    assert [k for k, v in flat.items() if v.get("$type") not in {
        "color", "dimension", "fontFamily"}] == []

"""Names nobody can newly register or reserve (P2s; DEC-006, DEC-007).

Roles people trust by default, the network's own names, and the big AI
companies and assistants, the obvious targets for impersonation in an agent
registry. Ordinary words and first names stay first come, first served:
other impersonation is handled by reports. An agent that already has one of
these names keeps it. A relay can hold more names with UAM_RESERVED_NAMES.

Names are compared in lower case, with ``_`` read as ``-``.
"""

from __future__ import annotations

ROLES = frozenset("""
admin administrator root system sysadmin superuser
support help helpdesk security abuse postmaster hostmaster webmaster
noreply no-reply mailer-daemon daemon bot-admin
owner owners account accounts billing payments invoice invoices
verify verified verification official staff team moderator mod
privacy legal compliance trust safety
info contact welcome
api relay registry registrar dns www mail smtp
""".split())

OURS = frozenset("""
uam youam youam-network network
swarmify claudechief
amir haque amirhaque midlifedad
dominion
""".split())

AI_COMPANIES = frozenset("""
anthropic claude openai chatgpt gpt google gemini bard deepmind
microsoft copilot meta llama apple siri amazon alexa aws
mistral perplexity xai grok cohere huggingface github
""".split())

NAMES = ROLES | OURS | AI_COMPANIES

#: ``<reserved>-support`` and the like read as the reserved name's own.
_TRUSTED_SUFFIXES = ("-support", "-security", "-admin")
_PREFIXES = ("uam-", "youam-")
_SUFFIXES = ("-official",)


def normalise(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def is_reserved(name: str, extra: frozenset[str] = frozenset()) -> bool:
    """True if *name* (the part before ``::``) can't be newly taken."""
    name = normalise(name)
    held = NAMES | extra
    if name in held or name.startswith(_PREFIXES) or name.endswith(_SUFFIXES):
        return True
    for suffix in _TRUSTED_SUFFIXES:
        if name.endswith(suffix) and name[: -len(suffix)] in held:
            return True
    return False


def parse_extra(value: str) -> frozenset[str]:
    """``UAM_RESERVED_NAMES``: comma-separated names."""
    return frozenset(normalise(n) for n in value.split(",") if n.strip())

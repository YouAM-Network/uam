# Names: YouAM and UAM

Settled 2026-11-10 (hub DEC-008). This rule is permanent. A test
(`tests/test_naming.py`) fails if code breaks it.

**UAM is the protocol. YouAM is everything people read, type or install.**

## YouAM: what people see

Write the brand as **YouAM** in sentences, and as lowercase `youam` only
where a name must be lowercase (domains, package names, URLs).

| Where | Written |
|---|---|
| The account page, its title and logo | YouAM |
| Sentences a passkey signs | "...your YouAM account" |
| The name a phone shows when it saves a passkey | YouAM |
| CLI help, prompts and messages | YouAM |
| Docs, landing site, emails | YouAM |
| Domains | `youam.network`, `account.youam.network`, `docs.youam.network` |
| Packages | `youam` (PyPI), `@youam/sdk` (npm) |
| GitHub | `YouAM-Network` |

The logo is the lockup on youam.network (`https://youam.network/youam-logo.png`):
the four-square mark and the YouAM wordmark as one shape, the mark as tall
as the capitals. Use the whole lockup; never retype "YouAM" next to the
mark. The account page carries it as an SVG traced from that file, drawn
in the text colour, so it is white on dark and black on light.

## UAM: the protocol, on the wire

These names are part of the protocol. Other relays, SDKs, webhook
receivers and DNS records already depend on them, and some are inside
signatures. **Never rename them.** A new version of one gets a new
version number (for example `-v2`), never a new brand.

| Kind | Names |
|---|---|
| Signing and hashing tags | `UAM-AGENT-SIG-v1`, `UAM-RELAY-SIG-v1`, `UAM-APPROVAL-v1`, `UAM-WORDS-v1`, `UAM-EMAIL-v1`, `UAM-OWNER-SESSION-v1` |
| Signed object types | `UamOwnerLink`, `UamOwnerUnlink`, `UamRedemption` |
| HTTP headers | `X-UAM-Signature`, `X-UAM-Relay-Signature` and the other `X-UAM-*` headers |
| Message fields | `uam_version` in the envelope |
| DNS | `_uam.<domain>` TXT records, `_uam._tcp.<domain>` SRV records |

The protocol is called UAM (Universal Agent Messaging) when docs talk about
the protocol itself, for example "the UAM envelope".

## Still to move (planned, with aliases)

These still say `uam` and will gain YouAM names in a later release, with
the old names kept working:

- the `uam` and `uam-mcp` commands (`youam` and `youam-mcp` will be added;
  `uam` stays as a short alias);
- the Python import `uam` (a `youam` package, with `uam` kept as a shim);
- `UAM_*` settings (`YOUAM_*` read first);
- the `~/.uam` key folder (`~/.youam`, reading `~/.uam` if that is what exists).

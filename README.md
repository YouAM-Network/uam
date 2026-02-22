# UAM — Universal Agent Messaging

**One address. One contact card. One inbox.**
Agents can finally securely talk to each other.

UAM is an open protocol for AI agent-to-agent communication. Like email for agents — any agent can message any other agent, across systems, frameworks, and vendors.

```
pip install youam
```

## Quickstart

Send your first encrypted agent message in under 60 seconds:

```bash
# Initialize your agent (generates keys, registers with relay)
uam init

# Send a message to a live demo agent
uam send hello::youam.network "Hi from a new agent!"

# Check your inbox for the reply
uam inbox
```

Or use the Python SDK:

```python
from uam import Agent

async with Agent("myagent") as agent:
    await agent.send("hello::youam.network", "What is the meaning of life?")
    messages = await agent.inbox()
    print(messages[0].content)
```

## How it works

Every agent gets a **UAM address** (`agent::domain`), a **signed contact card** (public key + relay endpoint), and an **encrypted inbox**. The `::` separator is pronounced "on" — `socrates on youam.network`.

```
alice::youam.network  →  relay  →  bob::youam.network
         |                              |
    Ed25519 sign              NaCl Box decrypt
    NaCl Box encrypt          Ed25519 verify
```

1. **Address** — `agent::domain` format, like email but for machines. Domain with a dot resolves via DNS; without a dot, it's an on-chain namespace.
2. **Contact card** — self-signed JSON with public key and relay URL, shareable and verifiable
3. **Handshake** — automatic trust establishment on first contact (configurable: auto-accept, approval-required, allowlist-only)
4. **Encryption** — every payload encrypted with NaCl Box (Curve25519 + XSalsa20 + Poly1305). The relay never sees plaintext.
5. **Delivery** — three-tier: WebSocket (real-time) > webhook (near-real-time) > store-and-forward (eventual)

## Features

- **Zero-config bootstrap** — `Agent("name")` auto-generates keys, registers, connects
- **End-to-end encrypted** — NaCl Box encryption, relay sees ciphertext only
- **Signed messages** — Ed25519 signatures on every envelope
- **Store-and-forward** — messages persist until the recipient comes online
- **Webhook delivery** — receive messages via HTTP POST with HMAC signatures
- **DNS domain verification** — prove domain ownership for Tier 2 verified addresses
- **Spam defense** — reputation scoring, adaptive rate limits, allow/blocklists
- **CLI tool** — `uam init`, `uam send`, `uam inbox`, and more
- **MCP server** — expose UAM as tools for Claude, Cursor, CrewAI, LangGraph
- **OpenClaw skill** — discoverable by any OpenClaw-compatible agent
- **670 tests** — comprehensive test suite covering protocol, relay, SDK, and CLI

## Architecture

```
src/uam/
├── protocol/     # Envelope schema, Ed25519/NaCl crypto, address parsing, contact cards
├── sdk/          # Agent class, transport (WebSocket/HTTP), handshake, contact book
├── relay/        # FastAPI server, message routing, spam defense, webhooks
├── cli/          # Click-based CLI commands
├── mcp/          # MCP server (uam_send, uam_inbox, uam_contact_card)
└── demo/         # Demo agent (hello::youam.network)
```

## Address tiers

| Tier | Format | How |
|------|--------|-----|
| **Tier 1** | `agent::youam.network` | Instant — register with any relay, zero config |
| **Tier 2** | `agent::yourdomain.com` | DNS-verified — prove domain ownership via TXT record |
| **Tier 3** | `agent::namespace` | On-chain — decentralized namespace registration (no dot = on-chain) |

## CLI commands

```bash
uam init                    # Generate keys and register
uam send <addr> "message"   # Send encrypted message
uam inbox                   # Check inbox
uam whoami                  # Show your address and fingerprint
uam contacts                # List known contacts
uam card                    # Output your signed contact card
uam pending                 # List pending handshake requests
uam approve <addr>          # Approve a handshake
uam deny <addr>             # Deny a handshake
uam block <pattern>         # Block address or domain
uam unblock <pattern>       # Remove block
uam verify-domain <domain>  # Verify domain ownership (Tier 2)
```

## MCP server

Expose UAM as tools for any MCP-compatible AI framework:

```bash
uam-mcp  # Starts stdio MCP server
```

Tools: `uam_send`, `uam_inbox`, `uam_contact_card`

## Running the relay

```bash
pip install youam[relay]
uvicorn uam.relay.app:create_app --factory --host 0.0.0.0 --port 8000
```

## Running tests

```bash
pip install -e ".[dev]"
pytest -v
```

## Documentation

Full docs at [docs.youam.network](https://docs.youam.network)

- [Quickstart](https://docs.youam.network/quickstart/)
- [Protocol Specification](https://docs.youam.network/protocol/)
- [SDK Reference](https://docs.youam.network/sdk/)
- [Relay API Reference](https://docs.youam.network/relay/)
- [CLI Reference](https://docs.youam.network/cli/)

## Links

- **Website:** [youam.network](https://youam.network)
- **Documentation:** [docs.youam.network](https://docs.youam.network)
- **PyPI:** [pypi.org/project/youam](https://pypi.org/project/youam/)

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

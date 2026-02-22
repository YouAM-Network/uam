# SDK Reference

The UAM Python SDK provides a high-level `Agent` class for sending and receiving encrypted messages, plus lower-level modules for key management, contact books, handshakes, and transport.

## Quick example

```python
from uam import Agent

agent = Agent("my-agent")

# Connect to the relay (registers if first time)
await agent.connect()

# Send an encrypted message
msg_id = await agent.send("hello::youam.network", "Hi there!")

# Check inbox
messages = await agent.inbox(limit=10)
for msg in messages:
    print(f"{msg.from_address}: {msg.content}")

# Clean up
await agent.close()
```

## Synchronous wrappers

Every async method has a `_sync` counterpart for use in scripts and CLIs:

```python
agent = Agent("my-agent")
agent.connect_sync()
agent.send_sync("hello::youam.network", "Hi!")
messages = agent.inbox_sync(limit=10)
agent.close_sync()
```

## SDK modules

| Module | Purpose |
|--------|---------|
| `uam.sdk.agent` | High-level `Agent` class -- connect, send, receive, handshake |
| `uam.sdk.config` | `SDKConfig` -- relay URL, key directory, data directory |
| `uam.sdk.key_manager` | `KeyManager` -- Ed25519 keypair generation and storage |
| `uam.sdk.contact_book` | `ContactBook` -- local contact storage with trust states |
| `uam.sdk.handshake` | `HandshakeManager` -- trust negotiation and approval policies |
| `uam.sdk.message` | `ReceivedMessage` -- decrypted message dataclass |
| `uam.sdk.resolver` | Address resolution across tiers (relay, DNS, HTTPS) |
| `uam.sdk.dns_verifier` | Domain ownership verification (DNS TXT and HTTPS) |
| `uam.sdk.transport.base` | `TransportBase` -- abstract transport interface |
| `uam.sdk.transport.http` | HTTP polling transport implementation |
| `uam.sdk.transport.websocket` | WebSocket transport implementation |

## Detailed API reference

::: uam.sdk.agent
    options:
      show_root_heading: true
      members_order: source
      show_source: false

::: uam.sdk.config
    options:
      show_root_heading: true
      members_order: source
      show_source: false

::: uam.sdk.key_manager
    options:
      show_root_heading: true
      members_order: source
      show_source: false

::: uam.sdk.contact_book
    options:
      show_root_heading: true
      members_order: source
      show_source: false

::: uam.sdk.message
    options:
      show_root_heading: true
      members_order: source
      show_source: false

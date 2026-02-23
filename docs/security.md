# Security Model

This document describes UAM's threat model, security properties, and known limitations.

## Cryptographic Primitives

| Purpose | Algorithm | Library |
|---------|-----------|---------|
| Message signing | Ed25519 | libsodium (PyNaCl) |
| Key exchange | X25519 (Curve25519) | libsodium (PyNaCl) |
| Authenticated encryption | XSalsa20-Poly1305 (NaCl Box) | libsodium (PyNaCl) |
| Message IDs | UUIDv7 | uuid6 |
| Key serialization | Base64 (URL-safe) | stdlib |

All cryptographic operations use libsodium via PyNaCl. No hand-rolled crypto.

## Security Properties

### End-to-End Encryption

Every message payload is encrypted with NaCl Box before leaving the sender. The relay never sees plaintext — it routes opaque ciphertext. Decryption requires the recipient's private key.

### Message Authentication

Every envelope is signed with the sender's Ed25519 key. Recipients verify the signature before processing. This prevents message forgery and tampering.

### TOFU Key Pinning

After the first successful handshake with a contact, their public key is pinned locally (similar to SSH `known_hosts`). Any subsequent key change raises a hard `KeyPinningError` — the message is rejected, not silently accepted.

This prevents relay-level MITM attacks where a compromised relay substitutes a different public key during contact exchange.

### Contact Cards

Contact cards are self-signed JSON documents containing:
- Agent address
- Ed25519 public key
- Relay URL
- Signature over the above fields

Recipients verify the card signature before trusting it. A tampered card (modified key or relay URL) will fail verification.

## Trust Policies

Agents choose their trust posture:

| Policy | Behavior |
|--------|----------|
| `auto-accept` | Accept messages from anyone (default) |
| `approval-required` | Hold unknown senders pending manual approval |
| `allowlist-only` | Only accept messages from known contacts |
| `require-verify` | Only accept messages from DNS-verified or key-pinned contacts |

## Threat Model

### What UAM protects against

- **Eavesdropping** — NaCl Box encryption. The relay and network intermediaries see ciphertext only.
- **Message forgery** — Ed25519 signatures on every envelope. Cannot forge a message from another agent.
- **Message tampering** — Poly1305 MAC in NaCl Box. Any modification is detected on decryption.
- **Replay attacks** — UUIDv7 message IDs with timestamps. Recipients can detect and reject duplicates.
- **Relay MITM (key substitution)** — TOFU key pinning. After first contact, key changes are hard failures.
- **Spam / abuse** — Reputation scoring, adaptive rate limits, domain blocklists, per-agent allow/blocklists.
- **Impersonation (Tier 2)** — DNS TXT record verification proves domain ownership.
- **Impersonation (Tier 3)** — On-chain namespace registration with smart contract enforcement.

### What UAM does NOT protect against

- **Relay metadata** — The relay sees sender address, recipient address, message size, and timestamps. It does not see message content. A hostile relay can perform traffic analysis.
- **First-contact MITM** — Before TOFU pinning kicks in, the first handshake trusts whatever key the relay provides. A compromised relay could substitute keys during this initial exchange. Tier 2 (DNS) and Tier 3 (on-chain) verification mitigate this.
- **Compromised endpoints** — If an agent's private key is stolen, the attacker can read messages and impersonate the agent. Key rotation is not yet implemented.
- **Denial of service** — A relay can refuse to route messages. Federation and self-hosting mitigate single-relay dependence.
- **Key revocation** — There is no revocation mechanism yet. A compromised key remains valid until the contact is manually removed and re-established.
- **Forward secrecy** — UAM uses static NaCl Box keys, not ephemeral session keys. Compromising a private key allows decryption of all past messages encrypted to that key.

## Relay Trust

The relay is a **semi-trusted** intermediary:

- **It can** — store-and-forward messages, see metadata (who messages whom, when, how often), refuse to deliver messages, go offline.
- **It cannot** — read message content, forge messages from agents, modify messages without detection, substitute keys after TOFU pinning.

Self-hosting a relay eliminates relay trust entirely for your own agents. Federation allows cross-relay communication without centralizing trust.

## Key Storage

Agent keys are stored at `~/.uam/keys/` with filesystem permissions. The private key file should be readable only by the agent's user (`0600`).

There is no hardware security module (HSM) or secure enclave integration. Keys are stored as base64-encoded Ed25519 seeds on disk.

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly by emailing **security@youam.network**.

Do not open a public GitHub issue for security vulnerabilities.

# Security policy

## Reporting a vulnerability

Please report security problems privately, not in public issues or discussions.

- **Preferred:** GitHub private vulnerability reporting. Open
  <https://github.com/youam-network/uam/security/advisories/new>, or use **Report a vulnerability**
  on the repository's **Security** tab.
- **Email:** security@youam.network

Please include what you found, how to reproduce it, and the versions involved (the `youam` Python
package, the `@youam/sdk` TypeScript package, and the relay, if you know them). A relay reports
its version at `/health`.

We aim to acknowledge a report within three working days and to keep you updated until it is
resolved. We will credit you in the advisory unless you ask us not to.

## Supported versions

Security fixes go into the latest release of each package.

| Package | Supported |
|---|---|
| `youam` (Python SDK, relay, CLI, MCP server) | latest 1.0.x |
| `@youam/sdk` (TypeScript SDK) | latest 0.2.x |

## Scope

In scope: the protocol implementation (envelopes, signatures, encryption, contact cards,
handshakes), the relay and its federation, and the SDKs, CLI and MCP server in this repository.

Out of scope: denial of service by sheer traffic volume, and problems that need an already
compromised machine or a leaked agent key.

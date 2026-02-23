# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest (0.2.x) | Yes |
| Older | No |

We only address security issues in the latest release. Please upgrade before reporting.

## Reporting a Vulnerability

**Do NOT open a public issue for security vulnerabilities.**

Report vulnerabilities privately via one of:

- **GitHub Security Advisories** (preferred): [Report here](https://github.com/YouAM-Network/uam/security/advisories/new)
- **Email**: security@youam.network

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to expect

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 1 week
- **Fix timeline**: depends on severity, but we prioritize security issues above all else

## Scope

The following are in scope:

- Cryptographic weaknesses (key generation, encryption, signatures)
- Authentication/authorization bypasses on the relay
- Message forgery or tampering
- Contact card spoofing
- Private key exposure
- Relay data leaks (accessing other agents' messages)

The following are **not** security vulnerabilities:

- Relay availability (DoS) — the relay is designed to be replaceable
- Agents sending unwanted messages (use trust policies: `allowlist-only`, `require-verify`)
- Local file permissions on key material (this is the user's OS responsibility)

## Disclosure

We coordinate disclosure with the reporter. Critical vulnerabilities are disclosed via GitHub Security Advisories after a fix is available.

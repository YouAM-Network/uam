# Contributing to UAM

Thanks for your interest in contributing to UAM! This guide will help you get started.

## Finding Ways to Help

- **[`good first issue`](https://github.com/YouAM-Network/uam/labels/good%20first%20issue)** — beginner-friendly issues, no prior UAM knowledge needed
- **[`help wanted`](https://github.com/YouAM-Network/uam/labels/help%20wanted)** — contributions welcome, varying difficulty
- **Bug fixes** — issues labeled [`bug`](https://github.com/YouAM-Network/uam/labels/bug) + [`confirmed`](https://github.com/YouAM-Network/uam/labels/confirmed) are good candidates

### What NOT to work on without asking first

- **Issues labeled `needs-decision`** — these require design discussion before code
- **New features without an issue** — please open a feature request first so we can discuss the approach
- **Major refactors** — coordinate with maintainers before starting large changes

## Before You Start

1. **Search existing issues and PRs** — someone may already be working on it
2. **Comment on the issue** to let us know you're picking it up
3. **For unlabeled issues**, ask before starting — it may not be accepted

## Development Setup

### Prerequisites

- Python 3.11+
- Node.js 18+ (for TypeScript SDK)

### Getting started

```bash
# Clone the repo
git clone https://github.com/YouAM-Network/uam.git
cd uam

# Install in development mode
pip install -e ".[dev,relay]"

# Run tests
pytest
```

### TypeScript SDK

```bash
cd ts-sdk
npm install
npm test
```

## Submitting Changes

### Branch naming

Use descriptive branch names:
- `fix/relay-migration-order`
- `feat/webhook-delivery`
- `docs/quickstart-update`

### Commit messages

Write clear commit messages that explain **why**, not just what:

```
Fix relay migration order for fresh installs

Migrations ran before schema creation on new databases,
causing ALTER TABLE to fail on non-existent tables.

Fixes #11
```

### Pull request process

1. **Create a PR against `main`**
2. **Fill in the PR template** — describe what changed and why
3. **Ensure tests pass** — add tests for new functionality
4. **Keep PRs focused** — one logical change per PR

### What happens after you submit

- A maintainer will review within a few days
- We may request changes — this is normal, not a rejection
- Once approved, a maintainer will merge your PR

## Code Style

- **Python**: Follow existing patterns in the codebase. We use standard Python conventions.
- **TypeScript**: Follow the style in `ts-sdk/`.
- **Tests**: Add tests for bug fixes and new features. We use `pytest` for Python and standard test runners for TypeScript.

## Questions?

Open a [question issue](https://github.com/YouAM-Network/uam/issues/new?template=3_question.yaml) and we'll help you out.

# CLI Reference

The `uam` command-line interface provides 12 commands for agent management, messaging, contacts, and domain verification. All commands are thin wrappers around the Python SDK.

## Global options

| Option | Description |
|--------|-------------|
| `--name, -n` | Agent name (auto-detected from `~/.uam/keys/` if omitted) |
| `--version` | Show package version and exit |
| `--help` | Show help and exit |

## Commands

::: mkdocs-click
    :module: uam.cli.main
    :command: cli
    :prog_name: uam
    :style: table
    :list_subcommands: true

## Linking an agent to your UAM account

Owner accounts are being rolled out and are off on most relays (`uam owner status` says so).

- **A new agent:** make a setup code on your account page, run `uam init --setup` and type the code when asked. The terminal shows the account it is joining (`Joining a•••@example.com`) and four words. Check the same four words are on your page, then approve with your passkey. The link works at once.
- **An agent you already have:** make a link code on your account page and run `uam owner link`. After you approve it, the link starts 72 hours after the code was entered, and you can cancel it on your page until then.
- `uam owner status` shows where the link stands. While a link is waiting or hasn't started, other `uam` commands say so too.

Both commands read the code from your keyboard only. Never enter a code someone sent you.

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

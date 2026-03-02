# Scanr CLI

`scanr-cli` is the executable crate that provides the `scanr` command.

## Purpose

- Parse user input and dispatch subcommands
- Present stable CLI UX (`--help`, `--version`, command trees)
- Call into `scanr-core` for shared logic

## Commands

Current command structure:

```bash
scanr scan <path>
scanr sbom generate
scanr sbom diff <old.json> <new.json>
```

Examples:

```bash
scanr scan .
scanr sbom generate
scanr sbom diff old.json new.json
```

## Help And Version

```bash
scanr --help
scanr --version
```

## Current Behavior (Milestone 1)

Commands print placeholder output and complete without panic.
This milestone establishes command contracts; scanning and SBOM logic will be implemented in later milestones.

## Crate Location

- `crates/scanr-cli`

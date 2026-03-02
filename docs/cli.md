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
scanr scan <path> --recursive
scanr sbom generate
scanr sbom diff <old.json> <new.json>
```

Examples:

```bash
scanr scan .
scanr scan . --recursive
scanr sbom generate
scanr sbom diff old.json new.json
```

## Help And Version

```bash
scanr --help
scanr --version
```

## Current Behavior (Milestone 2)

- `scanr scan <path>` prints parsed dependencies.
- `--recursive` scans subdirectories for supported package manifests.
- `scanr sbom generate` and `scanr sbom diff` are command placeholders for upcoming milestones.

## Crate Location

- `crates/scanr-cli`

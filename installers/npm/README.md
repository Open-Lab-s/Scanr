# @openlabs/scanr_cli

Install and run the **Scanr CLI** from npm.

Scanr is a dependency security scanner for Node, Python, and Rust projects with:

- OSV vulnerability detection
- risk summary + CI policy checks
- baseline security debt tracking
- offline cache mode
- CycloneDX SBOM generation/diff
- JSON and SARIF output
- interactive terminal UI

## Install

```bash
npm install -g @openlabs/scanr_cli
```

After install, use:

```bash
scanr --version
scanr --help
```

## Quick Start

```bash
scanr scan .
scanr scan . --ci
scanr scan . --json
scanr scan . --sarif
scanr baseline save
scanr baseline status
scanr sbom generate
scanr sbom diff old.cdx.json new.cdx.json
scanr trace minimatch
scanr
```

## CI Usage

```bash
scanr scan . --ci
```

`scanr.toml` example:

```toml
max_critical = 0
max_high = 2
cache_enabled = true
cache_ttl_hours = 24

[license]
enabled = true
block = ["GPL-3.0", "AGPL-3.0"]
allow_only = []
fail_on_unknown = true
enforce_in_ci = true
```

## Exit Codes

- `0`: success
- `1`: execution error
- `2`: vulnerability policy violation
- `3`: license policy violation
- `4`: both vulnerability and license policy violations

## Update / Uninstall

```bash
npm update -g @openlabs/scanr_cli
npm uninstall -g @openlabs/scanr_cli
```

## Links

- Repository: https://github.com/Open-Lab-s/Scanr
- Documentation: https://github.com/Open-Lab-s/Scanr/tree/main/docs

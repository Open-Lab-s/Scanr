# @openlabs/scanr_cli

**Scanr CLI** is an open-source **SCA (Software Composition Analysis)** and dependency vulnerability scanner for **Node.js, Python, and Rust**.

Use it in local development and CI/CD pipelines to detect **CVE/OSV vulnerabilities**, generate **SBOM (CycloneDX)**, enforce security policy, and export **JSON/SARIF** reports.

## Features

- Dependency scanning across `package-lock.json`, `requirements.txt`, `pyproject.toml`, `Cargo.lock`
- CVE/OSV vulnerability lookup with severity and remediation hints
- DevSecOps CI policy checks (`scanr.toml`) with deterministic exit codes
- License compliance policy enforcement
- Baseline security debt tracking (`scanr baseline save/status`)
- Project-local cache with offline mode for stable pipeline runs
- CycloneDX SBOM generation and SBOM diff
- Structured outputs for automation: JSON and SARIF
- Interactive full-screen TUI (`scanr`)

## Install

```bash
npm install -g @openlabs/scanr_cli
```

After install:

```bash
scanr --version
scanr --help
```

Bun users can install the same package:

```bash
bun install -g @openlabs/scanr_cli
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

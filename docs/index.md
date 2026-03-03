# Scanr

Scanr is a Rust dependency security scanner with two first-class crates:

- `scanr-cli`: command and terminal UI layer
- `scanr-core`: parsing, vulnerability, policy, SBOM, and output models

## Core Capabilities

- Dependency parsing for:
  - Node: `package.json`, `package-lock.json`
  - Python: `requirements.txt`, `pyproject.toml`
  - Rust: `Cargo.toml`, `Cargo.lock`
- Vulnerability investigation through OSV
- Severity and risk classification
- Upgrade recommendations (safe version targeting)
- CI policy enforcement using `scanr.toml`
- CycloneDX SBOM generation and SBOM diff
- Structured output modes:
  - `--json`
  - `--sarif`
  - `--raw-json` / `--raw-json-out`
- Interactive TUI with overview, dependencies, and recommendations views

## Quick Start

```bash
scanr scan .
scanr scan . --ci
scanr scan . --json
scanr sbom generate
```

## Architecture

```text
F:\Scanr
├── crates/
│   ├── scanr-core/    # reusable scan engine
│   └── scanr-cli/     # user-facing CLI and TUI
├── installers/        # npm, bun, brew, aur, curl assets
├── docs/              # mkdocs content
├── Cargo.toml         # workspace root
└── mkdocs.yml         # docs site nav/config
```

## Documentation Map

- **Installation**: all supported install channels
- **Scanr CLI**: commands, flags, and command output
- **TUI Mode**: interactive full-screen UI and key bindings
- **Output Formats**: human, JSON, SARIF, raw JSON
- **CI Policy**: `scanr.toml` policy model and CI exit behavior
- **SBOM**: CycloneDX generation and diff behavior
- **Scanr Core**: core models and API surface
- **Development**: build, test, release, and contribution workflow

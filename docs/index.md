# Scanr

Scanr is a Rust dependency security scanner with two first-class crates:

- `scanr-cli`: command and terminal UI layer
- `scanr-engine`: shared engine contracts and unified findings
- `scanr-sca`: SCA implementation (parsing, vulnerability, policy, SBOM, and outputs)

## Core Capabilities

- Dependency parsing for:
  - Node: `package.json`, `package-lock.json`
  - Python: `requirements.txt`, `pyproject.toml`
  - Rust: `Cargo.toml`, `Cargo.lock`
- Vulnerability investigation through OSV
- Project-local OSV caching with TTL
- Offline mode and forced refresh controls
- Severity and risk classification
- Upgrade recommendations (safe version targeting)
- Baseline save/compare/status for incremental adoption
- Node dependency path tracing (`scanr trace <package>`)
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
│   ├── scanr-engine/  # shared engine contracts
│   ├── scanr-sca/     # SCA engine implementation
│   └── scanr-cli/     # user-facing CLI and TUI
├── installers/        # npm, bun, brew, aur, curl assets
├── docs/              # mkdocs content
├── Cargo.toml         # workspace root
└── mkdocs.yml         # docs site nav/config
```

## Documentation Map

- **Installation**: all supported install channels
- **Changelog**: release history by version
- **Scanr CLI**: commands, flags, and command output
- **TUI Mode**: interactive full-screen UI and key bindings
- **Output Formats**: human, JSON, SARIF, raw JSON
- **CI Policy**: `scanr.toml` policy model and CI exit behavior
- **SBOM**: CycloneDX generation and diff behavior
- **Scanr SCA**: SCA models and API surface
- **Development**: build, test, release, and contribution workflow

# Scanr

🔐 Privacy-first, self-hostable, open-source security platform.

[![Release](https://img.shields.io/github/v/release/Open-Lab-s/Scanr?label=release)](https://github.com/Open-Lab-s/Scanr/releases)
[![NPM](https://img.shields.io/npm/v/%40openlabs%2Fscanr_cli?label=npm)](https://www.npmjs.com/package/@openlabs/scanr_cli)
[![Bun](https://img.shields.io/badge/bun-supported-black)](https://www.npmjs.com/package/@openlabs/scanr_cli)
[![Homebrew](https://img.shields.io/badge/homebrew-Open--Lab--s%2Ftap%2Fscanr-FBB040)](https://github.com/Open-Lab-s/homebrew-tap)
[![Cargo](https://img.shields.io/crates/v/scanr-cli?label=cargo)](https://crates.io/crates/scanr-cli)

## 🚀 Platform Vision

Scanr is evolving into an open Security OS for private infrastructure:

- fully local and deterministic by default
- no mandatory SaaS dependency
- unified engine architecture
- CI-native policy enforcement
- composable, extensible security workflow

## 🧱 Engine-First Architecture

```text
scanr-engine      Unified abstraction layer for findings and engine contracts
scanr-sca         Software composition analysis engine (current production engine)
scanr-cli         Local interface (CLI + TUI)
scanr-container   Planned container engine
scanr-iac         Planned IaC engine
scanr-sast        Planned static analysis engine
scanr-secrets     Planned secret scanning engine
```

## ✅ Current Feature Set

- dependency scanning (Node, Python, Rust)
- OSV vulnerability matching with CVE/severity/remediation
- risk summary + CI policy enforcement
- baseline and security debt tracking
- project-local cache + offline mode
- license compliance enforcement
- CycloneDX SBOM generation and SBOM diff
- JSON and SARIF outputs for automation
- dependency path tracing for Node lockfiles
- clean full-screen TUI flow

## 📦 Installation Labels

- `NPM`: `npm install -g @openlabs/scanr_cli`
- `BUN`: `bun install -g @openlabs/scanr_cli`
- `Homebrew`: `brew install Open-Lab-s/tap/scanr`
- `Cargo`: `cargo install scanr-cli --locked`
- `Curl`: `curl -fsSL https://scanr.dev/install.sh | bash`

## 🧩 Which Rust Crate Should I Use?

- `scanr-cli`: for CLI/TUI users who want the `scanr` binary.
- `scanr-sca`: for Rust integrators embedding dependency and vulnerability scanning.
- `scanr-engine`: for custom engine development with shared `Finding`/`ScanResult` contracts.

Published crates:

- `https://crates.io/crates/scanr-cli`
- `https://crates.io/crates/scanr-sca`
- `https://crates.io/crates/scanr-engine`

## 🛠️ Clone and Run for Local Testing

```bash
git clone https://github.com/Open-Lab-s/Scanr.git
cd Scanr

cargo build --workspace --release
cargo run --package scanr-cli --bin scanr -- scan .

# install local binary for repeated manual testing
cargo install --path crates/scanr-cli --force

scanr --version
```

## ⚡ Quick Start

```bash
scanr
scanr scan .
scanr scan . --ci
scanr scan . --json
scanr scan . --sarif
scanr baseline save
scanr trace minimatch
scanr sbom generate
```

## 🗺️ Release Timeline

| Version | Scope | Key outcomes |
| --- | --- | --- |
| `v0.1.0` | Foundation | Core CLI, SCA, OSV, recommendations, CI mode, SBOM, SARIF/JSON, packaging channels |
| `v0.1.1` | Hardening + framework | Baseline, cache/offline, trace, license policy, engine abstraction and multi-engine-ready architecture |

## 📈 Product Timeline

| Phase | Version | Status | Outcome |
| --- | --- | --- | --- |
| Foundation | `v0.1.0` | Completed | Production-ready SCA CLI baseline with CI and reporting outputs |
| Hardening | `v0.1.1` | Completed | Baseline + cache/offline + trace + license + engine abstraction |
| Multi-Engine Expansion | `v0.2.x` | Planned | Container engine first, then IaC/secrets/SAST |
| Security OS | `v1.x` | Planned | Self-hosted server, dashboard, org governance and historical analytics |

## ✅ Phase Checklist

- [x] Phase 1: SCA engine stabilized and production-ready
- [ ] Phase 1: Container engine implementation
- [ ] Phase 1: IaC engine implementation
- [ ] Phase 1: Secrets engine implementation
- [ ] Phase 1: SAST engine implementation
- [x] Phase 2: Local suite foundation (CLI + TUI + CI outputs)
- [ ] Phase 2: Full multi-engine local orchestration
- [ ] Phase 3: Security OS (`scanr-server` + `scanr-dashboard`)
- [ ] Phase 3: SCM integrations and org-level governance

## ✅ Feature Timeline

### Delivered in `v0.1.0`

- dependency parsing (Node/Python/Rust)
- OSV vulnerability investigation and remediation hints
- CI policy checks and risk classification
- CycloneDX SBOM generation + SBOM diff
- JSON and SARIF output modes
- interactive TUI
- install channels (npm, bun, brew, cargo, curl)

### Delivered in `v0.1.1`

- baseline tracking and baseline-aware CI behavior
- local OSV caching with TTL and refresh control
- offline scan mode
- dependency path tracing (Node lockfile)
- license compliance policy enforcement
- engine-layer refactor to `scanr-engine` + `scanr-sca`

## 📚 Documentation Map

- [Installation](installation.md)
- [Changelog](changelog.md)
- [Scanr CLI](cli.md)
- [Scanr SCA](core.md)
- [Output Formats](output-formats.md)
- [CI Policy](ci-policy.md)
- [Baseline](baseline.md)
- [Cache](cache.md)
- [SBOM](sbom.md)
- [TUI](tui.md)
- [Development](development.md)

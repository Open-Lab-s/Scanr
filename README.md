# Scanr

> Open, privacy-first, self-hostable DevSecOps runtime.

[![Release](https://img.shields.io/github/v/release/Open-Lab-s/Scanr?label=release)](https://github.com/Open-Lab-s/Scanr/releases)
[![NPM](https://img.shields.io/npm/v/%40openlabs%2Fscanr_cli?label=npm)](https://www.npmjs.com/package/@openlabs/scanr_cli)
[![Bun](https://img.shields.io/badge/bun-supported-black)](https://www.npmjs.com/package/@openlabs/scanr_cli)
[![Homebrew](https://img.shields.io/badge/homebrew-Open--Lab--s%2Ftap%2Fscanr-FBB040)](https://github.com/Open-Lab-s/homebrew-tap)
[![Cargo](https://img.shields.io/crates/v/scanr-cli?label=cargo)](https://crates.io/crates/scanr-cli)
[![License](https://img.shields.io/github/license/Open-Lab-s/Scanr)](LICENSE)

## 🔭 Vision

Scanr is a multi-engine security framework built for teams that need deterministic security checks without SaaS lock-in.

It is designed around:

- sovereignty
- offline capability
- transparent local execution
- engine-first extensibility
- deterministic CI enforcement

## 🧱 Architecture

```text
scanr-engine      Unified engine contracts and finding model
scanr-sca         Software composition analysis engine (production-ready)
scanr-cli         CLI + TUI interface
scanr-container   Container engine (planned)
scanr-iac         IaC engine (planned)
scanr-sast        SAST engine (planned)
scanr-secrets     Secret scanning engine (planned)
scanr-server      Self-hosted control plane (future)
scanr-dashboard   Web UI (future)
```

## ✅ What Works Today (v0.1.1)

- Node, Python, and Rust dependency parsing
- OSV vulnerability matching with CVE + severity data
- remediation suggestions and upgrade guidance
- baseline tracking (`.scanr/baseline.json`)
- project-local OSV cache (`.scanr/cache`) with offline/refresh modes
- policy enforcement in CI via `scanr.toml`
- deterministic exit codes (`0`, `1`, `2`, `3`, `4`)
- CycloneDX SBOM generation and SBOM diff
- SARIF + JSON + raw JSON structured outputs
- Node dependency path tracing (`scanr trace <package>`)
- full-screen TUI with scan controls

## 📦 Install Channels

```bash
# NPM
npm install -g @openlabs/scanr_cli

# BUN (uses npm package)
bun install -g @openlabs/scanr_cli

# Homebrew
brew install Open-Lab-s/tap/scanr

# Cargo (crates.io)
cargo install scanr-cli --locked

# Curl installer
curl -fsSL https://scanr.dev/install.sh | bash
```

## 🧩 Which Rust Crate Should I Use?

- `scanr-cli`: use this if you want the `scanr` command as an end user.
- `scanr-sca`: use this if you are building a Rust app and want to embed SCA scanning logic.
- `scanr-engine`: use this if you are building your own engine or shared policy/reporting on top of Scanr contracts.

Published crates:

- `https://crates.io/crates/scanr-cli`
- `https://crates.io/crates/scanr-sca`
- `https://crates.io/crates/scanr-engine`

Library integration example:

```toml
[dependencies]
scanr-sca = "0.1.1"
scanr-engine = "0.1.1"
```

```rust
use std::path::Path;
use scanr_sca::ScaEngine;

#[tokio::main]
async fn main() -> Result<(), scanr_sca::ScanError> {
    let engine = ScaEngine::new();
    let result = engine.scan_detailed(Path::new(".")).await?;
    println!("dependencies: {}", result.total_dependencies);
    Ok(())
}
```

## 🛠️ Run From Source (Clone + Test Locally)

```bash
# 1) Clone
git clone https://github.com/Open-Lab-s/Scanr.git
cd Scanr

# 2) Build release workspace
cargo build --workspace --release

# 3) Run without installing (dev run)
cargo run --package scanr-cli --bin scanr -- scan .

# 4) Install local CLI binary for testing (overwrites old local install)
cargo install --path crates/scanr-cli --force

# 5) Verify installed CLI
scanr --version
scanr --help
```

Optional validation:

```bash
cargo test --workspace
```

## ⚡ Quick Start

```bash
# interactive UI
scanr

# core scanning
scanr scan .
scanr scan . --ci
scanr scan . --json
scanr scan . --sarif

# caching and baseline
scanr scan . --offline
scanr scan . --refresh
scanr baseline save
scanr baseline status
scanr scan . --baseline --ci

# investigation + sbom
scanr trace minimatch
scanr sbom generate
scanr sbom diff old.cdx.json new.cdx.json
```

## 🗺️ Release Timeline

| Version | Theme | Highlights |
| --- | --- | --- |
| `v0.1.0` | Foundation | CLI skeleton, SCA scanning, OSV integration, recommendations, CI policy, SBOM, SARIF/JSON, TUI, distribution setup |
| `v0.1.1` | Enterprise hardening | Baseline/security debt tracking, OSV cache + offline mode, dependency tracing, license compliance, engine abstraction (`scanr-engine`) |

## 📈 Product Timeline

| Phase | Version | Status | Outcome |
| --- | --- | --- | --- |
| Foundation | `v0.1.0` | Completed | Built Scanr CLI + SCA core, CI mode, SBOM, SARIF/JSON outputs, install channels |
| Hardening | `v0.1.1` | Completed | Added baseline, cache/offline, tracing, license enforcement, and engine abstraction |
| Multi-Engine Expansion | `v0.2.x` | Planned | Add container engine, then IaC/secrets/SAST engines on the same contract |
| Security OS Layer | `v1.x` | Planned | Self-hosted server, dashboard, org policy management, and governance workflows |

## ✅ Phase Checklist (From Roadmap)

- [x] Phase 1: Engine Stabilization - SCA engine complete (`scanr-sca`)
- [ ] Phase 1: Engine Stabilization - Container engine (`scanr-container`)
- [ ] Phase 1: Engine Stabilization - IaC engine (`scanr-iac`)
- [ ] Phase 1: Engine Stabilization - Secrets engine (`scanr-secrets`)
- [ ] Phase 1: Engine Stabilization - SAST engine (`scanr-sast`)
- [x] Phase 2: Local Security Suite - CLI + TUI foundation complete
- [ ] Phase 2: Local Security Suite - Multi-engine invocation UX
- [ ] Phase 3: Security OS - `scanr-server` (self-hosted control plane)
- [ ] Phase 3: Security OS - `scanr-dashboard` (web UI)
- [ ] Phase 3: Security OS - SCM/GitHub integration + org governance

## ✅ Feature Timeline (What Is Done)

### `v0.1.0` delivered

- CLI command system (`scan`, `sbom`, `trace` foundations)
- dependency parsing for Node/Python/Rust
- OSV vulnerability lookup with remediation hints
- risk summary and CI policy checks
- CycloneDX SBOM generation and SBOM diff
- JSON/SARIF/raw JSON outputs
- interactive TUI experience
- packaging for npm/bun/homebrew/cargo/curl

### `v0.1.1` delivered

- baseline save/status/compare workflow
- security debt delta behavior in CI with baseline mode
- project-local OSV cache with TTL
- offline mode and forced refresh mode
- Node dependency path tracing
- license policy enforcement with dedicated exit semantics
- refactor to `scanr-engine` + `scanr-sca` architecture

## 🧠 Workspace

```text
F:\Scanr
├── crates/
│   ├── scanr-engine/
│   ├── scanr-sca/
│   └── scanr-cli/
├── installers/
├── docs/
├── Cargo.toml
└── mkdocs.yml
```

## 📚 Docs

- [Documentation index](docs/index.md)
- [Installation](docs/installation.md)
- [Scanr CLI](docs/cli.md)
- [Scanr SCA](docs/core.md)
- [Output formats](docs/output-formats.md)
- [CI policy](docs/ci-policy.md)
- [Baseline](docs/baseline.md)
- [Cache](docs/cache.md)
- [SBOM](docs/sbom.md)
- [TUI](docs/tui.md)
- [Changelog](docs/changelog.md)

Run docs locally:

```bash
mkdocs serve
```

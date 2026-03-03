# Changelog

All notable changes to Scanr are documented in this file.

## v0.1.1

Release scope: baseline, cache/offline, dependency tracing, and license compliance.

### Baseline & Security Debt Tracking

- Added baseline snapshot support at `.scanr/baseline.json`.
- Added `scanr baseline save`.
- Added `scanr baseline status`.
- Added `scanr scan <path> --baseline`.
- Added deterministic delta reporting (`NEW` and `FIXED`) and security debt change output.
- Added CI baseline behavior: fail only for new vulnerabilities when baseline mode is active.

### OSV Caching & Offline Mode

- Added project-local cache under `.scanr/cache`.
- Added cache key model: ecosystem + package + version.
- Added TTL-based cache usage with configurable `cache_ttl_hours` (default 24).
- Added `scanr scan <path> --offline` (no network calls, cache-only).
- Added `scanr scan <path> --refresh` (force OSV refresh, ignore TTL).
- Added cache/offline visibility in scan output and raw output model.

### Dependency Path Tracing (Node Focused)

- Added `scanr trace <package> [path]`.
- Implemented Node dependency path tracing from `package-lock.json`.
- Added support for multiple paths from root to target package.
- Added safe limits for path count and traversal depth.
- Added vulnerability context in trace output (severity, CVE, fix when available).
- Kept tracing isolated from normal scan pipeline to avoid scan regressions.

### License Compliance Enforcement

- Added license policy model under `[license]` in `scanr.toml`:
  - `enabled`
  - `block`
  - `allow_only`
  - `fail_on_unknown`
  - `enforce_in_ci`
- Added license metadata extraction and normalized license summary.
- Added pure license evaluation function with structured violations.
- Added license compliance section to CLI output.
- Added license evaluation to raw JSON output payload.
- Implemented final CI exit code strategy:
  - `0` success
  - `1` execution error
  - `2` vulnerability policy violation
  - `3` license policy violation
  - `4` both vulnerability and license policy violations

## v0.1.0

Release scope: initial public release feature set.

### Project Bootstrap & CLI Skeleton

- Initialized Rust workspace with `scanr-core` and `scanr-cli`.
- Integrated `clap` and basic command structure.
- Added CI build workflow and base docs structure.

### Dependency Parsing Engine

- Implemented dependency parsing for Node and Python.
- Added internal dependency model and scan command output.
- Expanded support to Rust manifests/lockfiles in project scope.

### OSV Vulnerability Investigation

- Integrated OSV API vulnerability lookups with async execution.
- Added severity, CVE, description, references, and no-vuln handling.
- Improved CLI output formatting and advisories table rendering.

### Upgrade Recommendation Engine

- Added safe upgrade recommendation output.
- Added major version bump warning behavior.
- Added registry-assisted recommendation flow for supported ecosystems.

### Risk Summary & CI Mode

- Added severity counters and risk level classification.
- Added CI mode policy enforcement via `scanr.toml`.
- Added non-zero CI exits for violation scenarios.

### SBOM Generation (CycloneDX)

- Added `scanr sbom generate`.
- Added CycloneDX JSON generation compatible with downstream tools.

### SBOM Diff Engine

- Added `scanr sbom diff <old> <new>`.
- Added dependency delta reporting:
  - added
  - removed
  - version changes
- Added vulnerability delta on introduced dependencies.

### Structured Output & Security Reporting

- Added `scanr scan <path> --json` deterministic machine output.
- Added `scanr scan <path> --sarif` (SARIF v2.1.0).
- Added extended raw output options for automation and GUI integration.

### Distribution & Packaging

- Added release packaging workflow for multi-platform binaries.
- Added npm wrapper package and install scripts.
- Added Homebrew tap/formula assets.
- Added installer assets for curl and AUR/paru channels.

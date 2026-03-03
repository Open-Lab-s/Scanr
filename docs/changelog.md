# Changelog

This page tracks Scanr release history by version.

## v0.1.1

Release scope: baseline, cache/offline, dependency tracing, and license compliance.

### Baseline & Security Debt Tracking

- Baseline snapshot file at `.scanr/baseline.json`.
- `scanr baseline save`.
- `scanr baseline status`.
- `scanr scan <path> --baseline`.
- Deterministic baseline delta (`NEW` and `FIXED`) and security debt output.
- CI baseline flow that fails only on new vulnerabilities.

### OSV Caching & Offline Mode

- Project-local OSV cache at `.scanr/cache`.
- Configurable TTL (`cache_ttl_hours`, default 24).
- `scanr scan <path> --offline`.
- `scanr scan <path> --refresh`.
- Cache and offline indicators in CLI/raw output.

### Dependency Path Tracing (Node)

- `scanr trace <package> [path]`.
- Node `package-lock.json` graph tracing.
- Multiple root-to-target paths with safety limits.
- Vulnerability context in trace output.

### License Compliance Enforcement

- Added `[license]` policy in `scanr.toml`.
- Added license extraction + evaluation + summary.
- Added license violations to CLI output and raw output payload.
- Final CI exit codes:
  - `0` success
  - `1` execution error
  - `2` vulnerability policy violation
  - `3` license policy violation
  - `4` both vulnerability and license policy violations

## v0.1.0

Release scope: initial public release feature set.

### Project Bootstrap & CLI Skeleton

- Rust workspace, CLI skeleton, and CI bootstrap.

### Dependency Parsing Engine

- Dependency parsing across Node, Python, and Rust manifests.

### OSV Vulnerability Investigation

- OSV integration with CVE/severity/details and CLI reporting.

### Upgrade Recommendation Engine

- Safe-version recommendations and major bump warning.

### Risk Summary & CI Mode

- Risk summary, policy enforcement, and CI failure behavior.

### SBOM Generation (CycloneDX)

- `scanr sbom generate` with CycloneDX JSON export.

### SBOM Diff Engine

- `scanr sbom diff` dependency/version/vulnerability delta output.

### Structured Output & Security Reporting

- JSON output, SARIF output, and raw payload support.

### Distribution & Packaging

- Release packaging and installer channels (`cargo`, `npm`, `curl`, `brew`, `paru` assets).

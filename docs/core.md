# Scanr Core

`scanr-core` is the shared security engine crate used by `scanr-cli`.

## Responsibilities

- Parse dependencies from supported manifest formats
- Query OSV and normalize vulnerability records
- Manage project-local OSV cache with TTL/offline controls
- Generate upgrade recommendations
- Summarize risk and evaluate CI policy
- Save/load baseline snapshots and compute deterministic deltas
- Build temporary Node dependency graphs for path tracing
- Generate and diff CycloneDX SBOM documents
- Convert scan results to SARIF

## Key Data Models

```rust
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub direct: bool,
}

pub struct Vulnerability {
    pub cve_id: String,
    pub severity: Severity,
    pub score: Option<String>,
    pub affected_version: String,
    pub description: String,
    pub references: Vec<String>,
    pub remediation: Option<String>,
}

pub struct ScanResult {
    pub target: String,
    pub path: String,
    pub total_dependencies: u32,
    pub dependencies: Vec<Dependency>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub upgrade_recommendations: Vec<UpgradeRecommendation>,
    pub risk_score: u32,
    pub severity_summary: SeveritySummary,
    pub risk_level: RiskLevel,
    pub queried_dependencies: u32,
    pub failed_queries: u32,
    pub offline_missing: u32,
    pub lookup_error: Option<String>,
    pub cache_events: Vec<String>,
}
```

## Public API Surface

- `scan_dependencies(path)`
- `scan_path(path)`
- `scan_path_with_options(path, options)`
- `trace_dependency_paths(path, package_name)`
- `save_baseline_for_target(path, scan_result)`
- `load_baseline_for_target(path)`
- `compare_scan_result_to_baseline(scan_result, baseline)`
- `investigate_vulnerabilities(dependencies)`
- `investigate_vulnerabilities_with_options(dependencies, options)`
- `summarize_risk(vulnerabilities)`
- `evaluate_policy(summary, policy)`
- `load_policy_for_target(path)`
- `generate_cyclonedx_sbom(path)`
- `diff_cyclonedx_sbom_files(old, new)`
- `scan_result_to_sarif(scan_result)`

## Supported Ecosystems And Sources

- Node:
  - `package.json`
  - `package-lock.json`
- Python:
  - `requirements.txt`
  - `pyproject.toml`
- Rust:
  - `Cargo.toml`
  - `Cargo.lock`

## Vulnerability and Recommendation Engine

- Source: OSV API (`https://api.osv.dev/v1/query`)
- Async concurrency: `8` parallel dependency lookups
- Retry strategy: up to `4` retries for retryable failures
- Upgrade recommendation sources:
  - npm registry for Node packages
  - PyPI for Python packages
  - OSV remediation fallback when registries do not provide a candidate

## Risk Model

- Risk level:
  - `HIGH` if any critical/high
  - `MODERATE` if any medium/unknown and no high/critical
  - `LOW` otherwise
- Risk score formula:
  - `critical*100 + high*40 + medium*10 + low*1 + unknown*5`

## Crate Location

- `crates/scanr-core`

# Output Formats

`scanr-cli` exposes one scan engine and multiple presentation layers.

All formats originate from the same core `ScanResult` model in `scanr-core`.

## Human-Readable Output (default)

Command:

```bash
scanr scan .
```

Behavior:

- Prints scan header
- Prints vulnerability table when findings exist
- Prints upgrade recommendation table when available
- Prints risk summary
- In `--ci` mode, prints policy evaluation and violations

## Canonical JSON (`--json`)

Command:

```bash
scanr scan . --json
```

Behavior:

- Emits only serialized `ScanResult`
- No formatted tables
- No extra logs
- Intended for pipelines, scripts, and API consumers

Example (trimmed):

```json
{
  "target": "my-project",
  "path": "F:\\my-project",
  "total_dependencies": 120,
  "dependencies": [],
  "vulnerabilities": [],
  "upgrade_recommendations": [],
  "risk_score": 0,
  "severity_summary": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "unknown": 0
  },
  "risk_level": "LOW",
  "queried_dependencies": 120,
  "failed_queries": 0,
  "lookup_error": null
}
```

## SARIF (`--sarif`)

Command:

```bash
scanr scan . --sarif
```

Behavior:

- Emits SARIF v2.1.0 JSON
- Suitable for GitHub Code Scanning and other SARIF-compatible tooling

Severity mapping:

- `critical` -> `error`
- `high` -> `error`
- `medium` -> `warning`
- `low` -> `note`
- `unknown` -> `note`

## Extended Raw Payload (`--raw-json`, `--raw-json-out`)

Commands:

```bash
scanr scan . --raw-json
scanr scan . --raw-json-out reports/scan.raw.json
```

Behavior:

- Includes additional CLI context:
  - `ci_mode`
  - `policy_path`
  - `policy`
  - `policy_evaluation`
  - `baseline` summary (when `--baseline` is used)
  - query statistics and lookup status
- Useful for GUI frontends (for example, Tauri) and custom reporting workflows

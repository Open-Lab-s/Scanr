# Baseline and Security Debt

A baseline is a saved snapshot of vulnerability identities at a known point in time.

Baseline location:

- `.scanr/baseline.json`

Scanr never auto-commits this file. Repository teams choose whether to commit it.

## Commands

Save baseline:

```bash
scanr baseline save
```

Compare scan to baseline:

```bash
scanr scan . --baseline
```

Show baseline status:

```bash
scanr baseline status
```

CI with baseline gate:

```bash
scanr scan . --ci --baseline
```

## Baseline File Format

Baseline stores only deterministic identity keys:

- `cve`
- `package`
- `version`

Example:

```json
{
  "version": "0.1.0",
  "generated_at": "2026-03-03T10:00:00Z",
  "vulnerabilities": [
    {
      "cve": "CVE-2026-27606",
      "package": "rollup",
      "version": "4.57.1"
    },
    {
      "cve": "CVE-2026-27903",
      "package": "minimatch",
      "version": "10.2.2"
    }
  ]
}
```

Identity key:

- `(cve, package, version)`

## Delta Logic

Given:

- `B`: baseline vulnerabilities
- `C`: current vulnerabilities

Compute:

- `NEW = C - B`
- `FIXED = B - C`

## CI Behavior

With `--ci --baseline` and baseline file present:

- fail only when `NEW > 0`
- pass when there are no new vulnerabilities
- report improvements when `FIXED > 0`

If baseline file is missing:

- Scanr warns and falls back to normal policy mode (`scanr.toml`)

## Security Debt Delta

Scanr reports:

- total new vulnerabilities
- total fixed vulnerabilities
- severity change from new vulnerabilities

Example:

```text
Security debt delta: +1 new, -2 fixed
Risk change: +0 CRITICAL, +1 HIGH, +0 MEDIUM, +0 LOW, +0 UNKNOWN
```

## Edge Cases

- Missing baseline file:
  - `scan --baseline`: warning and normal scan output
  - `scan --ci --baseline`: warning and fallback to policy mode
  - `baseline status`: error with guidance
- Corrupted baseline JSON:
  - explicit parse error
- Baseline version mismatch:
  - warning is printed

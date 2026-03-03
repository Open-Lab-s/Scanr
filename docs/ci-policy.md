# CI Policy

Scanr supports policy enforcement mode for CI pipelines.

Command:

```bash
scanr scan . --ci
```

## Policy File

Policy file name:

- `scanr.toml`

Example:

```toml
max_critical = 0
max_high = 2
cache_enabled = true
cache_ttl_hours = 24
```

Resolution rules:

- If scan target is a directory, Scanr reads `<target>/scanr.toml`
- If scan target is a file, Scanr reads `<target-parent>/scanr.toml`
- If file is missing, defaults are used:
  - `max_critical = 0`
  - `max_high = 0`

## CI Evaluation

Checks:

- Critical findings must be `<= max_critical`
- High findings must be `<= max_high`
- Vulnerability lookup must be complete (no lookup outage / no failed queries / no offline cache misses)

Result output:

- `Result: PASS` when policy is satisfied
- `Result: FAIL` with explicit violation lines when policy is exceeded

## Exit Behavior

- `0`: success
- `1`: runtime or serialization failure
- `2`: policy violation or policy load failure
- `3`: lookup incomplete in CI mode

## Baseline-Aware CI Mode

Command:

```bash
scanr scan . --ci --baseline
```

Behavior when baseline file exists:

- Uses `.scanr/baseline.json` comparison instead of threshold policy
- Fails only when **new** vulnerabilities are detected
- Passes when only baseline-known vulnerabilities remain
- Passes and reports improvement when vulnerabilities are fixed

Delta model:

- `NEW = current - baseline`
- `FIXED = baseline - current`

When baseline file is missing:

- Scanr prints a warning and falls back to normal `scanr.toml` policy mode

## Example Output

```text
CI Policy Check
Policy file: F:\repo\scanr.toml
Rules: max_critical=0 | max_high=2
Result: FAIL
Violations:
- high vulnerabilities 4 exceed max_high 2
```

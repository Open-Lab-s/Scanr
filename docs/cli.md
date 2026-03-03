# Scanr CLI

`scanr-cli` is the executable crate that exposes the `scanr` command.

## Command Tree

```bash
scanr
scanr scan <path> [options]
scanr baseline save [path]
scanr baseline status [path]
scanr sbom generate [path] [-o <file>]
scanr sbom diff <old.json> <new.json>
```

## Main Commands

### `scanr`

Starts the full-screen interactive TUI.

### `scanr scan <path>`

Runs dependency parsing, OSV vulnerability investigation, risk summary, and upgrade suggestions.

Flags:

- `-c, --ci`: enable CI policy enforcement
- `--json`: print canonical `ScanResult` JSON only
- `--sarif`: print SARIF v2.1.0 only
- `--list-deps`: print parsed dependency list before vulnerability summary
- `--raw-json`: print extended raw payload after human-readable output
- `--raw-json-out <FILE>`: write extended raw payload to file
- `--baseline`: compare current findings to `.scanr/baseline.json`
- `--offline`: use only local cache and skip OSV HTTP calls
- `--refresh`: ignore TTL and force fresh OSV fetch
- `-r, --recursive`: accepted CLI flag (reserved for recursive manifest discovery)

Mutual exclusions:

- `--json` and `--sarif` cannot be used together
- `--ci` cannot be combined with `--json` or `--sarif`
- `--offline` and `--refresh` cannot be used together

### `scanr sbom generate`

Generates a CycloneDX JSON SBOM.

```bash
scanr sbom generate
scanr sbom generate . -o my.sbom.cdx.json
```

### `scanr sbom diff`

Compares two CycloneDX JSON SBOM files and prints:

- added dependencies
- removed dependencies
- version changes
- introduced dependency vulnerability delta

```bash
scanr sbom diff old.cdx.json new.cdx.json
```

### `scanr baseline save`

Runs a full scan and writes a deterministic vulnerability snapshot to:

- `.scanr/baseline.json`

```bash
scanr baseline save
scanr baseline save .
```

### `scanr baseline status`

Loads `.scanr/baseline.json`, runs current scan, and prints:

- baseline vulnerability count
- current vulnerability count
- new vulnerabilities (`current - baseline`)
- fixed vulnerabilities (`baseline - current`)
- security debt/risk delta summary

```bash
scanr baseline status
scanr baseline status .
```

## CLI Output Example

Command:

```bash
scanr scan .
```

Sample output:

```text
Scanr Security Scan
Target: my-project
Path: F:\my-project
Dependencies analyzed: 120

Vulnerabilities found: 2
#    CVE                  SEV      SCORE    AFFECTED       PACKAGE            FIX
---------------------------------------------------------------------------------
1    CVE-2026-0001       high     3.1      1.2.3          package-a          1.2.5
2    CVE-2026-0002       medium   4.0      4.5.0          package-b          4.5.7

Upgrade recommendations: 2
#    PACKAGE             ECO      CURRENT        SUGGESTED      STATUS
-----------------------------------------------------------------------
1    package-a           node     1.2.3          1.2.5          safe
2    package-b           python   4.5.0          5.0.1          safe (major upgrade)

Risk Summary
critical: 0 | high: 1 | medium: 1 | low: 0 | unknown: 0
risk level: HIGH
```

## Help And Version

```bash
scanr --help
scanr --version
```

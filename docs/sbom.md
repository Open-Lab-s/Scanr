# SBOM

Scanr supports CycloneDX SBOM generation and SBOM diff analysis.

## Generate SBOM

Command:

```bash
scanr sbom generate
```

Optional parameters:

```bash
scanr sbom generate <path> -o <output-file>
```

Defaults:

- `path`: `.`
- `output`: `scanr.sbom.cdx.json`

Sample output:

```text
CycloneDX SBOM generated
Target: my-project
Path: F:\my-project
Components: 120
Output: scanr.sbom.cdx.json
```

## Diff SBOMs

Command:

```bash
scanr sbom diff old.cdx.json new.cdx.json
```

Diff output includes:

- added dependencies
- removed dependencies
- version changes
- count of introduced package versions
- vulnerability delta for introduced dependencies

Sample output:

```text
SBOM Diff
Old: old.cdx.json
New: new.cdx.json
Components: 118 -> 120

Added: 3
- axios@1.2.0 [node]

Removed: 1
- left-pad@1.3.0 [node]

Version changes: 1
- lodash [node]: 4.17.20 -> 4.17.21

Introduced package versions: 4
New Vulnerabilities: 1 HIGH
```

## Format Notes

- Generated SBOM is CycloneDX JSON (`specVersion: 1.5`)
- Dependencies are encoded as components with package URLs (PURLs)
- Direct dependencies are represented as required scope where possible

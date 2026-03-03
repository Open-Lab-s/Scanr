# OSV Cache and Offline Mode

Scanr uses a project-local cache for OSV responses.

Cache root:

- `.scanr/cache`

## Cache Key

Cache file naming:

- `{ecosystem}_{package}_{version}.json`

Examples:

- `node_minimatch_10.2.2.json`
- `node_rollup_4.57.1.json`
- `python_requests_2.31.0.json`

## Cache Entry Format

Each file stores:

```json
{
  "fetched_at": "2026-03-03T12:00:00Z",
  "ecosystem": "node",
  "package": "minimatch",
  "version": "10.2.2",
  "osv_response": { "vulns": [] }
}
```

`osv_response` keeps the full OSV payload used by Scanr.

## TTL and Refresh Rules

Default TTL:

- `24` hours

Behavior:

- cache missing -> fetch and store
- cache fresh -> use cache
- cache expired -> refresh
- `--refresh` -> force refresh
- `--offline` -> never refresh (cache only)

## CLI Flags

Offline mode:

```bash
scanr scan . --offline
```

Force refresh:

```bash
scanr scan . --refresh
```

## scanr.toml Settings

```toml
cache_enabled = true
cache_ttl_hours = 24
```

Defaults:

- `cache_enabled = true`
- `cache_ttl_hours = 24`

## Runtime Messages

When cache is used:

```text
Using cached OSV data for minimatch@10.2.2
```

When cache is refreshed:

```text
Refreshing OSV data for minimatch@10.2.2
```

When offline cache is missing:

```text
Offline cache miss for minimatch@10.2.2; vulnerability status unknown (offline)
```

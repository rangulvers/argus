# API Overview

REST API for automation and integrations.

## Base URL

```
http://localhost:8080/api
```

## Authentication

### API Key (recommended)

```bash
curl -H "X-API-Key: argus_xxxxx" http://localhost:8080/api/devices
```

Or as Bearer token:

```bash
curl -H "Authorization: Bearer argus_xxxxx" http://localhost:8080/api/devices
```

Create keys in Settings → API Keys.

### Session Cookie

Automatically included when logged in via web UI.

## Response Format

```json
{
  "data": { ... },
  "error": null
}
```

Errors return:

```json
{
  "detail": "Error message"
}
```

## Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 400 | Bad request |
| 401 | Unauthorized |
| 404 | Not found |
| 500 | Server error |

## Pagination

```bash
curl "http://localhost:8080/api/devices?limit=10&offset=0"
```

## Filtering

```bash
curl "http://localhost:8080/api/devices?risk_level=high"
curl "http://localhost:8080/api/changes?scan_id=5"
```

## Quick Examples

```bash
# Get devices
curl -H "X-API-Key: $KEY" http://localhost:8080/api/devices

# Trigger scan
curl -X POST -H "X-API-Key: $KEY" "http://localhost:8080/api/scan/trigger?profile=quick"

# Get stats
curl -H "X-API-Key: $KEY" http://localhost:8080/api/stats
```

## OpenAPI Docs

Interactive documentation at `http://localhost:8080/docs`

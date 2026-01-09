# API Overview

Argus provides a RESTful API for automation and integration with other tools.

## Base URL

```
http://localhost:8080/api
```

## Authentication

All API endpoints require authentication. You can authenticate using:

### Session Cookie

When logged in via the web UI, your session cookie is automatically included.

### API Key

For programmatic access, use an API key:

=== "X-API-Key Header (Recommended)"

    ```bash
    curl -H "X-API-Key: argus_xxxxx" http://localhost:8080/api/devices
    ```

=== "Bearer Token"

    ```bash
    curl -H "Authorization: Bearer argus_xxxxx" http://localhost:8080/api/devices
    ```

See [Authentication](authentication.md) for details on creating and managing API keys.

## Response Format

All responses are JSON:

```json
{
  "data": { ... },
  "error": null
}
```

### Error Responses

```json
{
  "detail": "Error message here"
}
```

Common HTTP status codes:

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request |
| 401 | Unauthorized |
| 404 | Not Found |
| 500 | Server Error |

## Quick Examples

### Get All Devices

```bash
curl -H "X-API-Key: argus_xxxxx" \
  http://localhost:8080/api/devices
```

### Trigger a Scan

```bash
curl -X POST -H "X-API-Key: argus_xxxxx" \
  "http://localhost:8080/api/scan/trigger?profile=quick"
```

### Get Network Stats

```bash
curl -H "X-API-Key: argus_xxxxx" \
  http://localhost:8080/api/stats
```

### Get Device Details

```bash
curl -H "X-API-Key: argus_xxxxx" \
  http://localhost:8080/api/devices/1
```

## Interactive Documentation

Full interactive API documentation is available at:

```
http://localhost:8080/docs
```

This Swagger UI lets you:

- Browse all endpoints
- See request/response schemas
- Try API calls directly

## Rate Limiting

Currently, Argus does not enforce rate limits. However, be mindful of:

- Scan frequency (each scan uses network resources)
- Database queries (large result sets)

## Pagination

List endpoints support pagination:

```bash
# Get first 10 devices
curl "http://localhost:8080/api/devices?limit=10"

# Get next 10 devices
curl "http://localhost:8080/api/devices?limit=10&offset=10"
```

## Filtering

Many endpoints support filtering:

```bash
# Devices with high risk
curl "http://localhost:8080/api/devices?risk_level=high"

# Changes from a specific scan
curl "http://localhost:8080/api/changes?scan_id=5"
```

## Integration Ideas

- **Home Assistant**: Monitor network devices
- **Grafana**: Visualize security metrics
- **Slack/Discord**: Alert on new devices
- **Scripts**: Automate security responses
- **SIEM**: Feed security events

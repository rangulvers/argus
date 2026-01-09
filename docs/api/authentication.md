# Authentication

## API Keys

Preferred for scripts and integrations.

### Creating Keys

**Web UI:** Settings → API Keys → Create

**API:**
```bash
curl -X POST "http://localhost:8080/api/keys" \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"name": "my-script"}'
```

Key is shown once. Store securely.

### Using Keys

```bash
# X-API-Key header (recommended)
curl -H "X-API-Key: argus_xxxxx" http://localhost:8080/api/devices

# Bearer token
curl -H "Authorization: Bearer argus_xxxxx" http://localhost:8080/api/devices
```

### Key Format

```
argus_<base64_random>
```

~49 characters total.

### Managing Keys

```bash
# List
curl -H "X-API-Key: $KEY" http://localhost:8080/api/keys

# Revoke
curl -X DELETE -H "X-API-Key: $KEY" http://localhost:8080/api/keys/1
```

## Session Auth

Cookie-based, automatic when logged into web UI.

## Error Handling

401 Unauthorized:
```json
{"detail": "Not authenticated"}
```

Causes: missing key, invalid key, revoked key, expired session.

## Examples

### Python

```python
import os
import requests

KEY = os.environ["ARGUS_API_KEY"]
BASE = "http://localhost:8080/api"

resp = requests.get(f"{BASE}/devices", headers={"X-API-Key": KEY})
devices = resp.json()
```

### Shell

```bash
#!/bin/bash
KEY="${ARGUS_API_KEY}"
curl -s -H "X-API-Key: $KEY" "http://localhost:8080/api/stats" | jq .
```

## Best Practices

- Use env vars, not hardcoded keys
- Create separate keys per integration
- Revoke unused keys
- Rotate periodically

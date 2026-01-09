# API Authentication

Argus supports two authentication methods for API access.

## Session Authentication

When using the web interface, authentication is handled via session cookies. This is automatic when you're logged in.

## API Key Authentication

For programmatic access, API keys provide a secure way to authenticate without session management.

### Creating an API Key

#### Via Web UI

1. Go to **Settings**
2. Scroll to **API Keys**
3. Click **"Create API Key"**
4. Enter a descriptive name
5. Copy the generated key

!!! warning "Important"
    The full API key is only displayed once. Copy it immediately and store it securely.

#### Via API (with session)

```bash
curl -X POST "http://localhost:8080/api/keys" \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"name": "My Integration"}'
```

Response:

```json
{
  "id": 1,
  "name": "My Integration",
  "key": "argus_abc123xyz...",
  "key_prefix": "argus_ab",
  "created_at": "2024-01-15T10:30:00Z"
}
```

### Using API Keys

Include the key in every request using one of these methods:

#### X-API-Key Header (Recommended)

```bash
curl -H "X-API-Key: argus_your_key_here" \
  http://localhost:8080/api/devices
```

#### Authorization Bearer Header

```bash
curl -H "Authorization: Bearer argus_your_key_here" \
  http://localhost:8080/api/devices
```

### API Key Format

API keys follow this format:

```
argus_<random_string>
```

- Prefix: `argus_` (6 characters)
- Random: URL-safe base64 (43 characters)
- Total: ~49 characters

### Managing API Keys

#### List Keys

```bash
curl -H "X-API-Key: argus_xxxxx" \
  http://localhost:8080/api/keys
```

Response:

```json
[
  {
    "id": 1,
    "name": "Home Assistant",
    "key_prefix": "argus_ab",
    "created_at": "2024-01-15T10:30:00Z",
    "last_used_at": "2024-01-16T08:00:00Z"
  }
]
```

#### Revoke a Key

```bash
curl -X DELETE -H "X-API-Key: argus_xxxxx" \
  http://localhost:8080/api/keys/1
```

### Security Best Practices

!!! tip "Use Descriptive Names"
    Name keys after their purpose:

    - "Home Assistant Integration"
    - "Grafana Dashboard"
    - "Backup Script"

!!! tip "Separate Keys per Integration"
    Create individual keys for each integration. This allows you to revoke one without affecting others.

!!! tip "Rotate Keys Regularly"
    Periodically create new keys and revoke old ones, especially for critical integrations.

!!! warning "Never Share Keys"
    - Don't commit keys to version control
    - Don't share keys in chat or email
    - Use environment variables or secret managers

!!! warning "Revoke Compromised Keys"
    If a key might be exposed, revoke it immediately in Settings.

### Handling Authentication Errors

#### 401 Unauthorized

```json
{
  "detail": "Not authenticated"
}
```

Causes:

- Missing API key
- Invalid API key
- Revoked API key
- Expired session

Solution: Include a valid API key in your request.

#### Example Error Handling

```python
import requests

response = requests.get(
    "http://localhost:8080/api/devices",
    headers={"X-API-Key": "argus_xxxxx"}
)

if response.status_code == 401:
    print("Authentication failed - check your API key")
elif response.status_code == 200:
    devices = response.json()
```

### Environment Variables

Store API keys securely using environment variables:

```bash
export ARGUS_API_KEY="argus_xxxxx"

curl -H "X-API-Key: $ARGUS_API_KEY" \
  http://localhost:8080/api/devices
```

### Integration Examples

#### Python

```python
import os
import requests

API_KEY = os.environ.get("ARGUS_API_KEY")
BASE_URL = "http://localhost:8080/api"

headers = {"X-API-Key": API_KEY}

# Get all devices
response = requests.get(f"{BASE_URL}/devices", headers=headers)
devices = response.json()

# Trigger a scan
response = requests.post(
    f"{BASE_URL}/scan/trigger",
    headers=headers,
    params={"profile": "quick"}
)
```

#### JavaScript/Node.js

```javascript
const API_KEY = process.env.ARGUS_API_KEY;
const BASE_URL = "http://localhost:8080/api";

async function getDevices() {
  const response = await fetch(`${BASE_URL}/devices`, {
    headers: { "X-API-Key": API_KEY }
  });
  return response.json();
}
```

#### Shell Script

```bash
#!/bin/bash
API_KEY="${ARGUS_API_KEY}"
BASE_URL="http://localhost:8080/api"

# Get device count
count=$(curl -s -H "X-API-Key: $API_KEY" "$BASE_URL/stats" | jq '.total_devices')
echo "Total devices: $count"
```

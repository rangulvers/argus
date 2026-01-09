# API Endpoints

Complete reference for all Argus API endpoints.

## Scans

### Trigger Scan

Start a new network scan.

```http
POST /api/scan/trigger
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `profile` | string | `normal` | Scan profile: `quick`, `normal`, `intensive` |
| `subnet` | string | config | Network to scan (CIDR notation) |

**Example:**

```bash
curl -X POST -H "X-API-Key: $KEY" \
  "http://localhost:8080/api/scan/trigger?profile=quick"
```

**Response:**

```json
{
  "status": "started",
  "scan_id": 15,
  "profile": "quick",
  "subnet": "192.168.1.0/24"
}
```

---

### Scan Status

Get current scan status.

```http
GET /api/scan/status
```

**Response:**

```json
{
  "scanning": true,
  "scan_id": 15,
  "subnet": "192.168.1.0/24",
  "profile": "quick",
  "started_at": "2024-01-15T10:30:00Z"
}
```

---

### List Scans

Get scan history.

```http
GET /api/scans
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 50 | Maximum results |
| `offset` | int | 0 | Skip results |

**Response:**

```json
[
  {
    "id": 15,
    "started_at": "2024-01-15T10:30:00Z",
    "completed_at": "2024-01-15T10:31:00Z",
    "status": "completed",
    "scan_type": "network",
    "scan_profile": "quick",
    "subnet": "192.168.1.0/24",
    "devices_found": 23
  }
]
```

---

### Get Scan Devices

Get devices from a specific scan.

```http
GET /api/scans/{scan_id}/devices
```

**Response:**

```json
[
  {
    "id": 1,
    "ip_address": "192.168.1.1",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "hostname": "router.local",
    "vendor": "Cisco",
    "risk_level": "low",
    "risk_score": 15
  }
]
```

---

## Devices

### List Devices

Get all devices from the latest scan.

```http
GET /api/devices
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `scan_id` | int | Get devices from specific scan |
| `risk_level` | string | Filter by risk level |
| `is_trusted` | bool | Filter by trusted status |
| `zone` | string | Filter by zone |

---

### Get Device

Get detailed device information.

```http
GET /api/devices/{device_id}
```

**Response:**

```json
{
  "id": 1,
  "ip_address": "192.168.1.100",
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "hostname": "mycomputer.local",
  "vendor": "Dell Inc.",
  "device_type": "computer",
  "os_name": "Linux 5.x",
  "label": "Work Laptop",
  "zone": "Workstations",
  "is_trusted": true,
  "notes": "Primary development machine",
  "risk_level": "low",
  "risk_score": 10,
  "threat_summary": "Low risk device with minimal exposed services",
  "first_seen": "2024-01-01T00:00:00Z",
  "last_seen": "2024-01-15T10:30:00Z",
  "ports": [
    {
      "port_number": 22,
      "protocol": "tcp",
      "state": "open",
      "service_name": "ssh",
      "service_product": "OpenSSH",
      "service_version": "8.9"
    }
  ]
}
```

---

### Update Device

Update device properties.

```http
PUT /api/devices/{device_id}
```

**Request Body:**

```json
{
  "label": "Living Room TV",
  "zone": "IoT",
  "is_trusted": true,
  "notes": "Samsung Smart TV"
}
```

All fields are optional - only include fields to update.

**Response:**

```json
{
  "id": 5,
  "ip_address": "192.168.1.50",
  "label": "Living Room TV",
  "zone": "IoT",
  "is_trusted": true,
  "notes": "Samsung Smart TV"
}
```

---

### Scan Single Device

Trigger a scan of a specific device.

```http
POST /api/scan/device/{ip_address}
```

**Example:**

```bash
curl -X POST -H "X-API-Key: $KEY" \
  "http://localhost:8080/api/scan/device/192.168.1.100"
```

---

## Changes

### List Changes

Get network change history.

```http
GET /api/changes
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `scan_id` | int | Filter by scan |
| `change_type` | string | Filter by type |
| `severity` | string | Filter by severity |
| `limit` | int | Maximum results |

**Response:**

```json
[
  {
    "id": 1,
    "scan_id": 15,
    "change_type": "device_added",
    "severity": "warning",
    "device_ip": "192.168.1.200",
    "device_mac": "11:22:33:44:55:66",
    "description": "New device discovered",
    "detected_at": "2024-01-15T10:30:00Z",
    "acknowledged": false
  }
]
```

**Change Types:**

- `device_added`
- `device_removed`
- `port_opened`
- `port_closed`
- `service_changed`

---

## Zones

### List Zones

Get all defined zones.

```http
GET /api/zones
```

**Response:**

```json
[
  "Workstations",
  "Servers",
  "IoT",
  "Network",
  "Mobile"
]
```

---

## Statistics

### Get Stats

Get network statistics (useful for dashboards).

```http
GET /api/stats
```

**Response:**

```json
{
  "total_devices": 25,
  "devices_at_risk": 3,
  "critical": 0,
  "high": 1,
  "last_scan": "2024-01-15T10:30:00Z"
}
```

---

### Get Trends

Get historical trend data.

```http
GET /api/trends
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `days` | int | 30 | Number of days of history |

**Response:**

```json
{
  "trends": {
    "labels": ["2024-01-14 10:00", "2024-01-15 10:00"],
    "device_counts": [23, 25],
    "risk_scores": [12.5, 14.2],
    "port_counts": [45, 48],
    "change_counts": [0, 3],
    "at_risk_counts": [2, 3]
  },
  "summary": {
    "total_scans": 14,
    "days": 30,
    "avg_devices": 24.1,
    "avg_risk_score": 13.2,
    "total_changes": 8
  }
}
```

---

## API Keys

### List API Keys

Get all API keys for the current user.

```http
GET /api/keys
```

---

### Create API Key

Generate a new API key.

```http
POST /api/keys
```

**Request Body:**

```json
{
  "name": "Home Assistant"
}
```

**Response:**

```json
{
  "id": 1,
  "name": "Home Assistant",
  "key": "argus_abc123...",
  "key_prefix": "argus_ab",
  "created_at": "2024-01-15T10:30:00Z"
}
```

---

### Revoke API Key

Revoke an API key.

```http
DELETE /api/keys/{key_id}
```

---

## Audit Logs

### List Audit Logs

Get audit log entries.

```http
GET /api/audit-logs
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `action` | string | Filter by action type |
| `limit` | int | Maximum results |
| `offset` | int | Skip results |

---

### List Audit Actions

Get available audit action types.

```http
GET /api/audit-logs/actions
```

---

## Updates

### Check for Updates

Check GitHub for new releases.

```http
GET /api/updates/check
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `force` | bool | false | Force refresh cache |

**Response:**

```json
{
  "current_version": "v0.1.0",
  "latest_version": "v0.2.0",
  "update_available": true,
  "release_url": "https://github.com/rangulvers/argus/releases/tag/v0.2.0",
  "release_notes": "Bug fixes and improvements...",
  "published_at": "2024-01-20T00:00:00Z",
  "checked_at": "2024-01-21T10:30:00Z"
}
```

---

## Health

### Health Check

Simple health check endpoint.

```http
GET /health
```

**Response:**

```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

## Configuration

### Get Config

Get current configuration.

```http
GET /api/config
```

---

### Update Config

Update configuration.

```http
PUT /api/config
```

**Request Body:**

```json
{
  "network": {
    "subnet": "192.168.1.0/24",
    "scan_profile": "normal"
  },
  "scanning": {
    "port_range": "1-1000",
    "enable_os_detection": true
  }
}
```

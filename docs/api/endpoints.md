# API Endpoints

All endpoints require authentication. See [Authentication](authentication.md).

## Scans

### Trigger Scan

```http
POST /api/scan/trigger?profile=quick&subnet=192.168.1.0/24
```

| Param | Default | Values |
|-------|---------|--------|
| `profile` | `normal` | `quick`, `normal`, `intensive` |
| `subnet` | config | CIDR notation |

Response:
```json
{"status": "started", "scan_id": 15, "profile": "quick", "subnet": "192.168.1.0/24"}
```

### Scan Status

```http
GET /api/scan/status
```

```json
{"scanning": true, "scan_id": 15, "subnet": "192.168.1.0/24", "profile": "quick"}
```

### List Scans

```http
GET /api/scans?limit=50&offset=0
```

### Get Scan Devices

```http
GET /api/scans/{scan_id}/devices
```

---

## Devices

### List Devices

```http
GET /api/devices
```

| Param | Description |
|-------|-------------|
| `scan_id` | From specific scan |
| `risk_level` | `critical`, `high`, `medium`, `low`, `none` |
| `is_trusted` | `true` or `false` |
| `zone` | Zone name |

### Get Device

```http
GET /api/devices/{device_id}
```

Full device with ports, risk details, CVEs.

### Update Device

```http
PUT /api/devices/{device_id}
```

```json
{"label": "proxmox-01", "zone": "Servers", "is_trusted": true, "notes": "Main hypervisor"}
```

### Scan Single Device

```http
POST /api/scan/device/{ip_address}
```

---

## Changes

### List Changes

```http
GET /api/changes
```

| Param | Description |
|-------|-------------|
| `scan_id` | Filter by scan |
| `change_type` | `device_added`, `device_removed`, `port_opened`, `port_closed`, `service_changed` |
| `severity` | Filter by severity |
| `limit` | Max results |

---

## Stats

### Get Stats

```http
GET /api/stats
```

```json
{"total_devices": 25, "devices_at_risk": 3, "critical": 0, "high": 1, "last_scan": "..."}
```

### Get Trends

```http
GET /api/trends?days=30
```

Historical data for charts.

---

## Zones

### List Zones

```http
GET /api/zones
```

```json
["Servers", "Network", "IoT", "Workstations"]
```

---

## API Keys

### List Keys

```http
GET /api/keys
```

### Create Key

```http
POST /api/keys
```

```json
{"name": "grafana"}
```

### Revoke Key

```http
DELETE /api/keys/{key_id}
```

---

## Config

### Get Config

```http
GET /api/config
```

### Update Config

```http
PUT /api/config
```

```json
{"network": {"subnet": "192.168.1.0/24"}, "scanning": {"port_range": "1-1000"}}
```

---

## Audit

### List Logs

```http
GET /api/audit-logs?action=login_failed&limit=100
```

### List Actions

```http
GET /api/audit-logs/actions
```

---

## Updates

### Check Updates

```http
GET /api/updates/check?force=false
```

---

## Network

### Detect Network

Auto-detect the local network for scan configuration.

```http
GET /api/network/detect
```

```json
{
  "local_ip": "192.168.1.50",
  "suggested_subnet": "192.168.1.0/24",
  "hostname": "argus-server"
}
```

---

## Health

```http
GET /health
```

```json
{"status": "healthy", "timestamp": "..."}
```

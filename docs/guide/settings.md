# Settings

Configuration and security management.

## Network

| Setting | Description |
|---------|-------------|
| Subnet | Target CIDR (e.g., `192.168.1.0/24`) |
| Scan Profile | Default: quick, normal, intensive |

## Scanning

| Setting | Description |
|---------|-------------|
| Port Range | `1-1000`, `1-65535`, `common`, or specific |
| OS Detection | Fingerprinting (requires root) |

## Scheduled Scans

Create automated scan schedules:

1. Click **Add Schedule**
2. Set name, cron expression, profile
3. Enable/disable as needed

| Expression | Schedule |
|------------|----------|
| `0 2 * * *` | Daily 2am |
| `0 */6 * * *` | Every 6h |
| `0 2 * * 0` | Sunday 2am |

## API Keys

For programmatic access without session cookies.

### Create

1. Settings → API Keys → Create
2. Copy key immediately (shown once)

### Usage

```bash
curl -H "X-API-Key: argus_xxxxx" http://localhost:8080/api/devices
```

### Manage

- View: name, prefix, created, last used
- Revoke: immediately invalidates key

## Audit Log

Security event history:

| Event | Description |
|-------|-------------|
| `login_success` | Successful auth |
| `login_failed` | Failed attempt |
| `scan_started` | Scan triggered |
| `device_updated` | Device settings changed |
| `api_key_created` | New key generated |
| `config_updated` | Settings modified |

Filter by action type, paginate with **Load More**.

## Config File

Settings persist to `config.yaml`. Edit directly or via UI.

```yaml
network:
  subnet: "192.168.1.0/24"
  scan_profile: "normal"

scanning:
  port_range: "1-1000"
  enable_os_detection: true
```

Restart or click **Reload Config** after manual edits.

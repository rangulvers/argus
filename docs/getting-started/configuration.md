# Configuration

All configuration is in `config.yaml`. For Docker, mount it to `/app/config.yaml`.

## Full Example

```yaml
network:
  subnet: "192.168.1.0/24"
  scan_profile: "normal"

scanning:
  port_range: "1-1000"
  enable_os_detection: true
  enable_service_detection: true

alerts:
  new_device: true
  new_port: true

database:
  path: "data/argus.db"
```

## Network Settings

### subnet

Target network in CIDR notation.

```yaml
network:
  subnet: "192.168.1.0/24"
```

Common values: `192.168.1.0/24`, `192.168.0.0/24`, `10.0.0.0/24`, `172.16.0.0/16`

Find yours: `ip route | grep default`

### scan_profile

| Profile | nmap Args | Description |
|---------|-----------|-------------|
| `quick` | `-sn -T4` | Ping only, ~30s |
| `normal` | `-sV -T4 -p 1-1000` | Ports 1-1000 + service detection |
| `intensive` | `-A -T4` | All ports + OS + scripts, slow |

## Scanning Settings

### port_range

```yaml
scanning:
  port_range: "1-1000"       # First 1000 (default)
  port_range: "1-65535"      # All ports
  port_range: "common"       # nmap top 1000
  port_range: "22,80,443"    # Specific ports
```

### enable_os_detection

OS fingerprinting. Requires root/sudo.

### enable_service_detection

Banner grabbing for service versions.

## Alert Settings

```yaml
alerts:
  new_device: true   # Alert on new devices
  new_port: true     # Alert on new open ports
```

## Database

```yaml
database:
  path: "data/argus.db"
```

SQLite database location. Mount this directory for persistence in Docker.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ARGUS_SECRET_KEY` | Session encryption key |
| `ARGUS_DB_PATH` | Override database path |

## Tips

- Use `quick` for frequent scans, `intensive` for weekly audits
- For large networks (100+ devices), scan smaller subnets separately
- Changes are persisted to `config.yaml` when saved via UI

## Next Steps

- [First Scan](first-scan.md)

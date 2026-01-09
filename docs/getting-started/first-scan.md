# First Scan

## Running a Scan

### Web UI

1. Open `http://localhost:8080`
2. Create admin account on first visit
3. Click **Run Scan** → select profile

### CLI

```bash
# Quick (ping only)
python scan_cli.py scan --profile quick

# Normal (ports 1-1000 + services)
python scan_cli.py scan --profile normal --detect-changes

# Specific subnet
python scan_cli.py scan --subnet 10.0.0.0/24
```

### API

```bash
# Trigger scan
curl -X POST "http://localhost:8080/api/scan/trigger?profile=quick"

# Check status
curl http://localhost:8080/api/scan/status
```

## Scan Profiles

| Profile | Use Case | Time (50 hosts) |
|---------|----------|-----------------|
| `quick` | Device presence check | ~30s |
| `normal` | Security audit | 3-5 min |
| `intensive` | Deep analysis | 15-30 min |

Start with `quick` to verify connectivity, then run `normal` for baseline.

## Understanding Results

### Risk Levels

| Level | Meaning |
|-------|---------|
| Critical | Immediate action needed (e.g., telnet exposed) |
| High | Significant risk (e.g., SMB, RDP open) |
| Medium | Moderate concern |
| Low | Minor issue |
| None | No detected issues |

### Risky Ports

| Port | Service | Risk |
|------|---------|------|
| 21 | FTP | High - cleartext auth |
| 23 | Telnet | Critical - cleartext |
| 445 | SMB | High - common target |
| 3389 | RDP | High - brute force target |
| 5900 | VNC | High - often weak auth |

## Device Organization

### Zones

Group devices by function:

- `Servers` - NAS, Docker hosts, VMs
- `Network` - Routers, switches, APs
- `Workstations` - Desktops, laptops
- `IoT` - Smart devices, cameras
- `DMZ` - Exposed services

### Labels

Add descriptive names: `proxmox-01`, `unifi-ap-garage`, `synology-nas`

### Trusted

Mark known devices as trusted to reduce noise.

## Scheduled Scans

### Cron

```bash
# Quick every 6 hours
0 */6 * * * cd /path/to/argus && python scan_cli.py scan --profile quick --detect-changes

# Normal nightly
0 2 * * * cd /path/to/argus && python scan_cli.py scan --profile normal --detect-changes
```

### Docker Environment

```yaml
environment:
  - SCAN_SCHEDULE=0 2 * * *
```

## Next Steps

- [Dashboard Guide](../guide/dashboard.md)
- [API Reference](../api/endpoints.md)

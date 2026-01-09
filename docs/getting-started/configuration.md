# Configuration

Argus is configured through a `config.yaml` file. This guide covers all available options.

## Configuration File

The configuration file should be located at:

- **Docker**: `/app/config.yaml` (mount your local file)
- **Manual**: `config.yaml` in the project root

### Example Configuration

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

The network range to scan in CIDR notation.

```yaml
network:
  subnet: "192.168.1.0/24"
```

!!! tip "Finding Your Subnet"
    ```bash
    # Linux/macOS
    ip route | grep default
    # or
    ifconfig | grep "inet "
    ```

Common home network subnets:

| Subnet | Range | Devices |
|--------|-------|---------|
| `192.168.1.0/24` | 192.168.1.1 - 192.168.1.254 | 254 |
| `192.168.0.0/24` | 192.168.0.1 - 192.168.0.254 | 254 |
| `10.0.0.0/24` | 10.0.0.1 - 10.0.0.254 | 254 |
| `172.16.0.0/24` | 172.16.0.1 - 172.16.0.254 | 254 |

### scan_profile

The default scan intensity level.

```yaml
network:
  scan_profile: "normal"  # quick, normal, or intensive
```

| Profile | Description | Time (20 devices) |
|---------|-------------|-------------------|
| `quick` | Ping only - just discovers devices | ~30 seconds |
| `normal` | Ports 1-1000 + service detection | 5-10 minutes |
| `intensive` | All ports + OS detection + scripts | 15-30 minutes |

## Scanning Settings

### port_range

Which ports to scan during normal and intensive scans.

```yaml
scanning:
  port_range: "1-1000"
```

Options:

| Value | Ports Scanned |
|-------|---------------|
| `"1-1000"` | First 1000 ports (default) |
| `"1-65535"` | All ports |
| `"common"` | Nmap's top 1000 common ports |
| `"22,80,443,8080"` | Specific ports only |

### enable_os_detection

Attempt to identify the operating system of each device.

```yaml
scanning:
  enable_os_detection: true
```

!!! note
    OS detection requires root/sudo privileges and may slow down scans.

### enable_service_detection

Identify services running on open ports.

```yaml
scanning:
  enable_service_detection: true
```

## Alert Settings

### new_device

Alert when a new device is discovered.

```yaml
alerts:
  new_device: true
```

### new_port

Alert when a new port opens on an existing device.

```yaml
alerts:
  new_port: true
```

## Database Settings

### path

Location of the SQLite database file.

```yaml
database:
  path: "data/argus.db"
```

!!! warning "Docker Users"
    Mount a volume for the `data` directory to persist your database:
    ```yaml
    volumes:
      - ./data:/app/data
    ```

## Environment Variables

Some settings can also be configured via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `ARGUS_VERSION` | Application version | Auto-detected |
| `ARGUS_SECRET_KEY` | Session encryption key | Auto-generated |
| `ARGUS_DB_PATH` | Database file path | `data/argus.db` |

## Configuration Tips

### Multiple Networks

To scan multiple networks, you'll need to run multiple scans with different subnet settings. The UI allows you to specify a different subnet when triggering manual scans.

### Performance Tuning

For large networks (>100 devices):

1. Use `quick` profile for frequent scans
2. Run `intensive` scans during off-hours
3. Consider scanning in smaller subnet ranges

### Security Recommendations

1. Use a strong admin password
2. Don't expose Argus to the internet
3. Keep your network subnet private

## Next Steps

- [Run your first scan](first-scan.md)
- [Explore the dashboard](../guide/dashboard.md)

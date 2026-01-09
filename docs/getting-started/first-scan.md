# Running Your First Scan

This guide walks you through running your first network scan with Argus.

## Before You Begin

Make sure you have:

1. [Installed Argus](installation.md)
2. [Configured your network subnet](configuration.md)
3. Created an admin account (prompted on first visit)

## Starting a Scan

### From the Web UI

1. **Log in** to Argus at [http://localhost:8080](http://localhost:8080)

2. **Click "Run Scan"** in the top-right corner of any page

3. **Choose a scan profile**:

    | Profile | When to Use |
    |---------|-------------|
    | **Quick Scan** | First scan, or regular check-ins |
    | **Normal Scan** | Daily/weekly security audits |
    | **Intensive Scan** | Deep analysis, use sparingly |

4. **Monitor progress** - The scan status appears in the top bar

!!! tip "First Scan Recommendation"
    Start with a **Quick Scan** to verify everything works. This only takes about 30 seconds and will discover all active devices.

### From the Command Line

```bash
# Quick scan
python scan_cli.py scan --profile quick

# Normal scan with change detection
python scan_cli.py scan --profile normal --detect-changes

# Scan a specific subnet
python scan_cli.py scan --subnet 192.168.1.0/24
```

### Via the API

```bash
# Trigger a quick scan
curl -X POST "http://localhost:8080/api/scan/trigger?profile=quick"

# Trigger a normal scan
curl -X POST "http://localhost:8080/api/scan/trigger?profile=normal"
```

## Understanding Scan Results

After the scan completes, you'll see:

### Dashboard Overview

- **Total Devices**: Number of devices found
- **At Risk**: Devices with security concerns
- **Recent Changes**: New devices or port changes

### Device List

Each device shows:

- **IP Address**: Network address
- **Hostname**: Device name (if available)
- **Vendor**: Manufacturer based on MAC address
- **Risk Level**: Security assessment
- **Open Ports**: Number of accessible ports

### Risk Levels

| Level | Color | Meaning |
|-------|-------|---------|
| **Critical** | Red | Immediate attention required |
| **High** | Orange | Significant security risk |
| **Medium** | Yellow | Moderate concern |
| **Low** | Blue | Minor issue |
| **None** | Green | No detected issues |

## What to Look For

### New Devices

After your first scan, review all discovered devices:

1. Go to **Devices** page
2. Check each device - do you recognize it?
3. **Label** known devices (e.g., "Living Room TV", "Dad's Laptop")
4. **Mark trusted** devices you own
5. Investigate any unknown devices

### Open Ports

Common ports and their implications:

| Port | Service | Risk |
|------|---------|------|
| 22 | SSH | Medium - ensure strong passwords |
| 23 | Telnet | High - unencrypted, disable if possible |
| 80/443 | HTTP/HTTPS | Low - web interfaces |
| 445 | SMB | High - file sharing, often targeted |
| 3389 | RDP | High - remote desktop, secure carefully |

### Risky Devices

Pay attention to devices with:

- High risk scores
- Many open ports
- Telnet or other insecure services
- Unknown vendors

## Organizing Your Network

### Create Zones

Organize devices into logical groups:

1. Click on a device
2. Edit the **Zone** field
3. Common zones:
    - `Workstations` - Computers and laptops
    - `IoT` - Smart home devices
    - `Servers` - NAS, home servers
    - `Mobile` - Phones and tablets
    - `Network` - Routers, switches, APs

### Mark Trusted Devices

For devices you own and trust:

1. Click on the device
2. Toggle **Trusted** to on
3. Trusted devices are excluded from some alerts

### Add Labels

Give devices friendly names:

1. Click on the device
2. Edit the **Label** field
3. Example: "Kitchen Sonos Speaker"

## Setting Up Regular Scans

### Scheduled Scans (Docker)

The Docker image includes a cron job for automatic scans. Edit `docker-compose.yml`:

```yaml
environment:
  - SCAN_SCHEDULE=0 2 * * 0  # Sunday at 2 AM
```

### Manual Scheduling (Crontab)

```bash
# Edit crontab
crontab -e

# Add weekly scan
0 2 * * 0 cd /path/to/argus && /path/to/venv/bin/python scan_cli.py scan --detect-changes
```

## Next Steps

Now that you've run your first scan:

- [Learn about the dashboard](../guide/dashboard.md)
- [Understand device management](../guide/devices.md)
- [Set up scheduled scans](../guide/scans.md)
- [Explore the API](../api/overview.md)

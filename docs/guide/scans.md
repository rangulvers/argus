# Scans

Argus uses nmap to scan your network and discover devices. This guide covers scan types, history, and scheduling.

## Scan Profiles

### Quick Scan

**Command**: `nmap -sn -T4`

- Ping scan only
- Discovers which hosts are online
- No port scanning
- Fastest option (~30 seconds for 254 hosts)

**Use when**:

- Running frequent checks
- Just need to know what's online
- Network is large (100+ devices)

### Normal Scan

**Command**: `nmap -sV -T4 -p 1-1000`

- Scans ports 1-1000
- Service version detection
- OS hints from service banners

**Use when**:

- Daily/weekly security checks
- Need port and service information
- Balanced speed vs. detail

### Intensive Scan

**Command**: `nmap -A -T4`

- Scans all 65535 ports
- Aggressive OS detection
- Script scanning (NSE)
- Traceroute

**Use when**:

- Deep security audits
- Investigating specific devices
- Initial baseline scan

!!! warning "Intensive Scan Performance"
    Intensive scans can take 15-30 minutes for 20 devices. Run during off-hours to avoid network impact.

## Running Scans

### From the Web UI

1. Click **"Run Scan"** in the top navigation
2. Select a scan profile
3. Monitor progress in the status indicator

### From the CLI

```bash
# Quick scan
python scan_cli.py scan --profile quick

# Normal scan
python scan_cli.py scan --profile normal

# Intensive scan
python scan_cli.py scan --profile intensive

# Custom subnet
python scan_cli.py scan --subnet 10.0.0.0/24

# Enable change detection
python scan_cli.py scan --detect-changes
```

### Via API

```bash
# Quick scan
curl -X POST "http://localhost:8080/api/scan/trigger?profile=quick"

# Normal scan with custom subnet
curl -X POST "http://localhost:8080/api/scan/trigger?profile=normal&subnet=192.168.1.0/24"
```

## Scan History

The **Scan History** page shows all past scans:

| Column | Description |
|--------|-------------|
| ID | Unique scan identifier |
| Started | When the scan began |
| Completed | When the scan finished |
| Status | Completed, Running, or Failed |
| Profile | Scan type used |
| Subnet | Network range scanned |
| Devices | Number of devices found |

### Viewing Scan Results

Click any scan to see:

- Devices discovered in that scan
- Comparison with previous scans
- Changes detected

### Comparing Scans

Use the **Compare** page to see differences between two scans:

1. Go to **Compare Scans**
2. Select two scans to compare
3. View:
    - Devices added
    - Devices removed
    - Port changes
    - Service changes

## Change Detection

When `--detect-changes` is enabled (or via UI), Argus compares the new scan to the previous one and records:

### Device Added

A new device appeared on the network.

**Possible causes**:

- New device connected
- Device was offline during previous scan
- DHCP assigned new IP to existing device

### Device Removed

A device is no longer responding.

**Possible causes**:

- Device turned off or disconnected
- Device moved to different network
- Firewall blocking scans

### Port Opened

A new port is accessible on an existing device.

**Possible causes**:

- New service started
- Firewall rule changed
- Malware opened backdoor (investigate!)

### Port Closed

A port is no longer accessible.

**Possible causes**:

- Service stopped
- Firewall rule added
- Service crashed

### Service Changed

The service on a port changed (different version, product, etc.).

## Scheduled Scans

### Using Cron (Manual Installation)

Add to your crontab:

```bash
# Edit crontab
crontab -e

# Quick scan every 6 hours
0 */6 * * * cd /path/to/argus && /path/to/venv/bin/python scan_cli.py scan --profile quick --detect-changes

# Normal scan every night at 2 AM
0 2 * * * cd /path/to/argus && /path/to/venv/bin/python scan_cli.py scan --profile normal --detect-changes

# Intensive scan weekly on Sunday at 3 AM
0 3 * * 0 cd /path/to/argus && /path/to/venv/bin/python scan_cli.py scan --profile intensive --detect-changes
```

### Using Docker

The Docker image supports scheduled scans via environment variable:

```yaml
environment:
  - SCAN_SCHEDULE=0 2 * * *  # Every day at 2 AM
```

### Using the Settings Page

1. Go to **Settings**
2. Scroll to **Scheduled Scans**
3. Add a new schedule:
    - Name (e.g., "Nightly Scan")
    - Cron expression
    - Scan profile
4. Enable/disable schedules as needed

## Scan Tips

!!! tip "Baseline First"
    Run an intensive scan first to establish a complete baseline. Then use normal or quick scans for regular monitoring.

!!! tip "Quick for Presence"
    Use quick scans to detect device presence changes without the overhead of port scanning.

!!! tip "Normal for Security"
    Normal scans provide the best balance of security insight and scan speed.

!!! tip "Intensive Sparingly"
    Reserve intensive scans for:

    - Initial setup
    - Monthly deep audits
    - Investigating suspicious devices

!!! warning "Network Impact"
    Scans generate network traffic. On slower networks or with many devices, consider:

    - Running scans during off-hours
    - Using quick scans more frequently
    - Scanning subnets separately

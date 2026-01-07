# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Argus is a home network security monitoring application that performs scheduled network scans using nmap, discovers devices and open ports, and tracks changes over time. It provides both a CLI and web interface for managing scans.

## Commands

### Development

```bash
# Install dependencies (Python 3.11+)
pip install -r requirements.txt

# Start web server (requires nmap installed: sudo apt-get install nmap)
uvicorn app.main:app --host 0.0.0.0 --port 8080

# Run CLI scan (requires root for full nmap features)
sudo python scan_cli.py scan --subnet 192.168.1.0/24 --detect-changes

# Quick ping-only scan
python scan_cli.py scan --profile quick

# List scans/devices/changes
python scan_cli.py list-scans
python scan_cli.py list-devices
python scan_cli.py list-changes
```

### Docker

```bash
docker-compose build
docker-compose up -d
docker-compose logs -f
```

### Database

```bash
# Initialize/reset database
python -c "from app.database import init_db; init_db()"

# Database location: ./data/argus.db (SQLite)
```

## Architecture

### Core Components

- **`app/main.py`**: FastAPI application with REST API (`/api/*`) and web UI routes (Jinja2 templates)
- **`app/scanner.py`**: `NetworkScanner` class wrapping python-nmap. Performs scans and merges data from previous scans (preserves user labels, first_seen dates, ports from quick scans)
- **`app/utils/change_detector.py`**: `ChangeDetector` class compares scans to detect device/port additions, removals, and service changes
- **`app/utils/threat_detector.py`**: `ThreatDetector` with `THREAT_DATABASE` mapping ports to risk levels and recommendations
- **`app/utils/mac_vendor.py`**: Downloads and caches Wireshark manuf database for MAC vendor lookups
- **`scan_cli.py`**: CLI entry point for running scans without the web server

### Data Flow

1. Scan triggered via CLI or API (`POST /api/scans`)
2. `NetworkScanner.perform_scan()` runs nmap with profile-specific arguments
3. For each host, `_process_host()` creates Device records, merging with previous scan data
4. `ThreatDetector.assess_device()` calculates risk scores from open ports
5. `ChangeDetector.detect_changes()` compares with previous scan
6. Results stored in SQLite via SQLAlchemy models

### Scan Profiles

- **quick**: Ping scan only (`-sn -T4`), carries forward ports from previous scans
- **normal**: Port scan 1-1000, service detection (`-sV`), OS detection (`-O`)
- **intensive**: Aggressive scan with scripts (`-A`)

### Database Models (app/models.py)

- `Scan`: Scan metadata (status, subnet, devices_found)
- `Device`: Discovered devices (IP, MAC, vendor, OS, risk_level, threat_details JSON)
- `Port`: Open ports per device
- `Change`: Detected changes between scans
- `DeviceHistory`: Persistent device tracking by MAC address
- `Alert`: Triggered alerts (unused in Phase 1)

### Configuration

Config loaded from `config.yaml` (see `config.yaml.example`). Pydantic settings in `app/config.py` with `.env` fallback.

Key settings:
- `network.subnet`: Target network CIDR
- `network.scan_profile`: Default scan profile
- `scanning.port_range`: Port range ("1-1000", "common", "all")
- `database.path`: SQLite file location

### Web UI

Templates in `templates/` use Jinja2 with htmx for dynamic updates:
- `dashboard.html`: Overview with stats and recent changes
- `devices.html`: Device list from selected scan
- `device_detail.html`: Single device with ports and threat info
- `scans.html`: Scan history
- `changes.html`: Change log
- `compare.html`: Side-by-side scan comparison

## Key Patterns

- Device identification uses MAC address primarily, falls back to IP
- Quick scans carry forward port data from previous scans to avoid redundant scanning
- User-defined labels and trusted status persist across scans via `DeviceHistory`
- Threat assessment happens per-device based on `THREAT_DATABASE` port mappings
- Background tasks used for scans via FastAPI `BackgroundTasks`

## Requirements

- Python 3.11+
- nmap installed on host (`sudo apt-get install nmap`)
- Root/sudo for full nmap functionality (OS detection, raw packets)
- Docker with `NET_ADMIN` and `NET_RAW` capabilities for containerized scanning

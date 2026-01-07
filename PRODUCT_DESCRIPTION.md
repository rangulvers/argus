# Argus - Home Network Security Monitor

## Product Overview

Argus is an automated network security monitoring solution designed for home networks. It performs weekly network scans using nmap to discover devices and open ports, maintaining a historical record of network state changes to identify potential security threats or unauthorized devices.

## Core Features

### 1. Network Scanning Engine
- **Automated Weekly Scans**: Scheduled nmap scans of the entire home network
- **Device Discovery**: Identify all active devices on the network
- **Port Scanning**: Comprehensive port scan (configurable range) for each discovered device
- **Service Detection**: Identify services running on open ports
- **OS Fingerprinting**: Detect operating systems of network devices
- **MAC Address Tracking**: Track devices by MAC address for persistent identification
- **Custom Scan Profiles**: Configure scan intensity (quick, normal, intensive)

### 2. Data Management
- **Scan History**: Store results from all scans with timestamps
- **Device Inventory**: Maintain database of known devices
- **Change Detection**: Compare scans to identify:
  - New devices joining the network
  - Devices that have disappeared
  - New open ports on existing devices
  - Closed ports that were previously open
  - Changes in services/versions
- **Device Labeling**: Allow users to label known devices (e.g., "Living Room TV", "John's Laptop")
- **Alerting System**: Notify on significant changes

### 3. Web-Based Dashboard
- **Scan Results Overview**: Display latest scan with device count and status
- **Device List View**: Comprehensive list of all discovered devices showing:
  - IP address
  - MAC address
  - Hostname (if available)
  - OS detection results
  - Last seen timestamp
  - User-assigned label
  - Status (active/inactive)
- **Port Details**: For each device, show:
  - Port number
  - Protocol (TCP/UDP)
  - Service name
  - Service version
  - State (open/closed/filtered)
- **Change Comparison View**: Side-by-side comparison between scans showing:
  - Devices added/removed
  - Ports opened/closed
  - Service changes
  - Visual diff highlighting
- **Historical Timeline**: View scan history over time
- **Search & Filter**: Filter devices by IP, MAC, hostname, or port
- **Export Functionality**: Export scan results to CSV/JSON

### 4. Security & Notifications
- **Alert Rules**: Configurable alerts for:
  - New device detected
  - Suspicious port openings (e.g., common malware ports)
  - Device disappearance
  - Service version changes
- **Notification Channels**: Email, webhook, or web UI notifications
- **Baseline Mode**: Mark current network state as "trusted baseline"
- **Whitelist Management**: Mark known devices as trusted

## Technology Stack (Optimized for Raspberry Pi)

### Backend
- **Language**: Python 3.11+
- **Framework**: Flask (lightweight) or FastAPI (if you prefer modern features)
- **Nmap Integration**: python-nmap library
- **Task Scheduling**: Linux cron (most efficient) or APScheduler (if you prefer Python-based)
- **API**: RESTful API

### Database
- **Primary DB**: SQLite (perfect for this use case)
- **Schema**:
  - Scans table (scan metadata)
  - Devices table (device information)
  - Ports table (port scan results)
  - Changes table (detected changes)
  - Alerts table (triggered alerts)
- **Why SQLite**: Single file, no daemon, minimal overhead, perfect for weekly writes

### Frontend
- **Framework**: htmx + Alpine.js (highly recommended - ~50KB total)
- **Alternative**: Svelte (~15KB compiled) for more interactivity
- **UI Styling**: Tailwind CSS or simple CSS
- **Templates**: Jinja2 (server-side rendering)
- **Why htmx**: Minimal JavaScript, fast on Pi, server-side rendering approach

### DevOps & Deployment
- **Containerization**: Single Docker container (not 4 separate containers)
- **Alternative**: Bare metal with systemd (most efficient for Pi)
- **Web Server**: Gunicorn (production) or Flask dev server (simple setups)
- **Reverse Proxy**: Nginx (optional, for HTTPS)
- **Logging**: Structured logging with rotation

### Resource Footprint
- **Single Container**: ~100-150MB RAM
- **Bare Metal**: ~50-80MB RAM
- **Startup Time**: <10 seconds (container) or <5 seconds (bare metal)

## Architecture (Optimized)

### Single Container / Application Architecture
```
┌──────────────────────────────────────────────────┐
│         Flask Application (Single Process)       │
│                                                  │
│  ┌────────────────────────────────────────────┐ │
│  │  Web UI (htmx + Alpine.js + Jinja2)       │ │
│  │  - Dashboard view                          │ │
│  │  - Device list with port details           │ │
│  │  - Scan comparison view                    │ │
│  │  - Server-side rendered HTML               │ │
│  └────────────────────────────────────────────┘ │
│                                                  │
│  ┌────────────────────────────────────────────┐ │
│  │  REST API (Flask Routes)                   │ │
│  │  - /api/scans                              │ │
│  │  - /api/devices                            │ │
│  │  - /api/changes                            │ │
│  └────────────────────────────────────────────┘ │
│                                                  │
│  ┌────────────────────────────────────────────┐ │
│  │  Scanner Service                           │ │
│  │  - Nmap wrapper (python-nmap)              │ │
│  │  - Change detection logic                  │ │
│  │  - Alert triggering                        │ │
│  └────────────────────────────────────────────┘ │
│                                                  │
│  ┌────────────────────────────────────────────┐ │
│  │  SQLite Database (single file)             │ │
│  │  - /data/argus.db (volume mount)       │ │
│  └────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────┘
         ▲
         │
         │ Triggered by cron OR APScheduler
         │ (weekly: 0 2 * * 0)
```

## Deployment Options

### Option 1: Single Docker Container (Recommended)
**Pros**:
- Easy to deploy and update
- Consistent environment
- Works on both Raspberry Pi and other systems
- Easy backup (just backup SQLite file)
- Isolated from host system
- Low overhead (~100-150MB RAM)

**Setup**:
```bash
docker run -d \
  --name argus \
  --network=host \
  --cap-add=NET_ADMIN \
  -v /path/to/data:/app/data \
  -p 8080:8080 \
  argus:latest
```

**Components** (all in one container):
- Flask application
- htmx/Alpine.js frontend (served as static files)
- SQLite database (volume mounted)
- Python-nmap scanner
- Cron or APScheduler for scheduling

### Option 2: Bare Metal on Raspberry Pi (Most Efficient)
**Pros**:
- Direct hardware access
- Lowest overhead (~50-80MB RAM)
- Fastest startup (<5 seconds)
- No Docker complexity

**Requirements**:
- Python 3.11+
- Nmap installed
- SQLite (built into Python)
- Systemd service for auto-start
- Cron for scheduling

**Setup**:
```bash
# Install dependencies
pip install flask python-nmap jinja2 sqlalchemy

# Setup systemd service
sudo systemctl enable argus
sudo systemctl start argus

# Setup weekly cron
echo "0 2 * * 0 /opt/argus/scan.py" | sudo tee /etc/cron.d/argus
```

## System Requirements

### Raspberry Pi (Bare Metal)
- **Model**: Raspberry Pi 3+ (1GB RAM sufficient), Pi 4 or Pi 5
- **OS**: Raspberry Pi OS (64-bit) or Ubuntu Server
- **Storage**: 8GB+ SD card (SSD recommended for better performance)
- **Network**: Ethernet connection recommended for accurate scanning
- **RAM Usage**: ~50-80MB
- **Disk Space**: ~200MB for application + data

### Docker Container
- **Model**: Raspberry Pi 4 (2GB+ RAM) or any Docker host
- **RAM**: 512MB minimum, 1GB recommended
- **Storage**: 2GB+ free space for container image
- **Docker**: Version 20.10+
- **RAM Usage**: ~100-150MB
- **Disk Space**: ~500MB for container + data

### General Requirements
- **Nmap**: Version 7.80+ installed
- **Python**: 3.11+ (for bare metal)
- **Network Access**: Full subnet access for scanning

## Network Configuration

### Required Permissions
- Nmap requires root/CAP_NET_RAW for certain scan types
- Configure Docker with appropriate capabilities
- Ensure firewall allows web UI access (default port 8080)

### Recommended Network Setup
- Static IP for the scanning device
- Access to entire subnet (e.g., 192.168.1.0/24)
- Router configuration to allow port scanning (some routers may block aggressive scans)

## Security Considerations

### Application Security
- **Authentication**: Basic auth or OAuth for web UI access
- **HTTPS**: SSL/TLS for web interface
- **API Security**: JWT tokens for API authentication
- **Database**: Encrypted connections, strong passwords
- **Secrets Management**: Environment variables, never hardcoded

### Scanning Ethics & Legal
- Only scan your own network
- Inform household members about scanning activity
- Some aggressive scans may trigger ISP alerts
- Configure scan intensity appropriately

## Development Phases

### Phase 1: Core Scanner (MVP)
- Basic nmap scanning functionality
- Database schema and storage (SQLite)
- Simple CLI interface
- Weekly scheduling (cron or APScheduler)
- Change detection logic

### Phase 2: Flask Backend & API
- Flask application setup
- REST API endpoints (scans, devices, changes)
- Scan management endpoints
- Device management
- Data models and database integration

### Phase 3: Web UI (htmx + Jinja2)
- Dashboard implementation with Jinja2 templates
- Device list view
- Scan results display
- Basic change comparison view
- htmx for dynamic updates
- Alpine.js for minimal interactivity

### Phase 4: Advanced Features
- Alert system with configurable rules
- Device labeling and whitelisting
- Advanced filtering and search
- Export functionality (CSV/JSON)
- Email/webhook notifications

### Phase 5: Polish & Deploy
- Docker containerization (single container)
- Bare metal installation scripts
- Documentation (user guide, API docs)
- Performance optimization
- Security hardening (auth, HTTPS)

## Configuration File Example

```yaml
# config.yaml
network:
  subnet: "192.168.1.0/24"
  scan_schedule: "0 2 * * 0"  # 2 AM every Sunday
  scan_profile: "normal"  # quick, normal, intensive

scanning:
  port_range: "1-1000"  # or "common" or "all"
  enable_os_detection: true
  enable_service_detection: true
  timeout: 300  # seconds

alerts:
  enabled: true
  new_device: true
  new_port: true
  threshold_ports: 10  # Alert if more than X new ports

notifications:
  email:
    enabled: false
    smtp_server: ""
    recipients: []
  webhook:
    enabled: false
    url: ""

database:
  type: "sqlite"  # or "postgresql"
  path: "./data/argus.db"
  retention_days: 365

web:
  host: "0.0.0.0"
  port: 8080
  enable_auth: true
```

## Future Enhancements

- **Mobile App**: iOS/Android companion app
- **Vulnerability Detection**: Integration with CVE databases
- **Network Topology Map**: Visual network diagram
- **Traffic Analysis**: Integration with packet capture for deeper analysis
- **Machine Learning**: Anomaly detection using ML models
- **Multi-Network Support**: Scan multiple networks/VLANs
- **Integration**: Home Assistant, Splunk, or SIEM integration
- **Reporting**: PDF reports generation
- **2FA**: Two-factor authentication for web UI

## Success Metrics

- Successfully detect all devices on network
- Identify port changes within scan interval
- Alert on new/suspicious devices within 5 minutes of scan completion
- Web UI loads in < 2 seconds
- Scan completion time < 10 minutes for typical home network (< 20 devices)
- Zero false positives in trusted device detection

## Maintenance & Operations

- **Backup**: Regular database backups (automated)
- **Updates**: Keep nmap and dependencies updated
- **Logs**: Rotate logs, monitor disk usage
- **Performance**: Monitor scan duration and resource usage
- **Database**: Periodic cleanup of old scan data (configurable retention)

# Argus - Home Network Security Monitor

Argus is an automated network security monitoring solution for home networks. It performs scheduled network scans using nmap to discover devices and open ports, maintaining historical records to identify potential security threats or unauthorized devices.

## Features (Phase 1 - Core Scanner)

- ✅ Automated network scanning using nmap
- ✅ Device discovery with MAC address, hostname, and vendor detection
- ✅ Port scanning with service detection
- ✅ OS fingerprinting
- ✅ Change detection between scans
- ✅ SQLite database for storing scan history
- ✅ RESTful API built with FastAPI
- ✅ CLI tool for manual scans
- ✅ Docker containerization with cron scheduling

## Technology Stack

- **Backend**: Python 3.11+ with FastAPI
- **Database**: SQLite
- **Scanner**: python-nmap
- **Scheduling**: Linux cron
- **Deployment**: Single Docker container

## Quick Start (Docker)

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- For Raspberry Pi: Model 3+ or higher

### 1. Clone and Configure

```bash
# Navigate to project directory
cd /home/macoso/Projects/argus

# Create config file from example
cp config.yaml.example config.yaml

# Edit config to match your network
nano config.yaml
# Change subnet to your network (e.g., 192.168.1.0/24)
```

### 2. Build and Run

```bash
# Build the container
docker-compose build

# Start the container
docker-compose up -d

# Check logs
docker-compose logs -f
```

### 3. Access the Application

- **Web UI**: http://localhost:8080
- **API Docs**: http://localhost:8080/docs
- **Health Check**: http://localhost:8080/health

## Manual Installation (Bare Metal)

### Prerequisites

- Python 3.11+
- nmap installed (`sudo apt-get install nmap`)
- Root privileges (for nmap scanning)

### Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Copy and configure
cp config.yaml.example config.yaml
nano config.yaml

# Initialize database and run first scan
python scan_cli.py scan --detect-changes

# Start the web service
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

### Setup Cron for Weekly Scans

```bash
# Edit crontab
crontab -e

# Add this line for Sunday 2 AM scans
0 2 * * 0 cd /home/macoso/Projects/argus && /usr/bin/python3 scan_cli.py scan --detect-changes
```

## CLI Usage

The CLI tool provides direct access to scanning functionality:

### Run a Scan

```bash
# Basic scan with default settings
python scan_cli.py scan

# Scan specific subnet with change detection
python scan_cli.py scan --subnet 192.168.1.0/24 --detect-changes

# Quick scan (ping only, no port scan)
python scan_cli.py scan --profile quick

# Intensive scan with OS detection
python scan_cli.py scan --profile intensive

# Custom port range
python scan_cli.py scan --ports 1-1000
python scan_cli.py scan --ports common  # Top 100 ports
python scan_cli.py scan --ports all     # All 65535 ports
```

### List Scans

```bash
# List recent scans
python scan_cli.py list-scans

# Limit results
python scan_cli.py list-scans --limit 5
```

### List Devices

```bash
# List devices from most recent scan
python scan_cli.py list-devices

# List devices from specific scan
python scan_cli.py list-devices --scan-id 5
```

### List Changes

```bash
# List all recent changes
python scan_cli.py list-changes

# List changes from specific scan
python scan_cli.py list-changes --scan-id 5

# Limit results
python scan_cli.py list-changes --limit 10
```

## API Usage

### Trigger a Scan

```bash
curl -X POST http://localhost:8080/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "subnet": "192.168.1.0/24",
    "scan_profile": "normal",
    "detect_changes": true
  }'
```

### List Scans

```bash
curl http://localhost:8080/api/scans
```

### Get Scan Details

```bash
curl http://localhost:8080/api/scans/1
```

### List Devices from Scan

```bash
curl http://localhost:8080/api/scans/1/devices
```

### List Changes

```bash
# All changes
curl http://localhost:8080/api/changes

# Changes from specific scan
curl http://localhost:8080/api/changes?scan_id=1
```

### Compare Scans

```bash
curl http://localhost:8080/api/scans/2/compare/1
```

### Device History

```bash
curl http://localhost:8080/api/device-history
```

## Configuration

Edit `config.yaml` to customize:

```yaml
network:
  subnet: "192.168.1.0/24"          # Your network subnet
  scan_schedule: "0 2 * * 0"         # Cron format (2 AM Sunday)
  scan_profile: "normal"             # quick, normal, intensive

scanning:
  port_range: "1-1000"               # Port range to scan
  enable_os_detection: true          # OS fingerprinting
  enable_service_detection: true     # Service version detection
  timeout: 300                       # Scan timeout in seconds

alerts:
  enabled: true
  new_device: true                   # Alert on new devices
  new_port: true                     # Alert on new ports
  threshold_ports: 10                # Alert if >10 new ports

database:
  type: "sqlite"
  path: "./data/argus.db"
  retention_days: 365                # Keep data for 1 year

web:
  host: "0.0.0.0"
  port: 8080
  enable_auth: false                 # Enable basic auth
```

## Project Structure

```
argus/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── models.py            # Database models
│   ├── database.py          # Database setup
│   ├── scanner.py           # Nmap scanner
│   ├── config.py            # Configuration management
│   └── utils/
│       └── change_detector.py  # Change detection logic
├── templates/               # Jinja2 templates (Phase 3)
├── static/                  # CSS, JS files (Phase 3)
├── data/                    # SQLite database storage
├── scan_cli.py              # CLI tool
├── requirements.txt         # Python dependencies
├── Dockerfile               # Docker configuration
├── docker-compose.yml       # Docker Compose config
├── config.yaml.example      # Example configuration
└── README.md                # This file
```

## Database Schema

### Scans
Stores scan metadata and results.

### Devices
Discovered devices with IP, MAC, hostname, vendor, OS info.

### Ports
Open ports for each device with service information.

### Changes
Detected changes between scans (new devices, ports, etc.).

### DeviceHistory
Persistent device tracking across scans by MAC address.

### Alerts
Triggered alerts based on detected changes.

## Security Considerations

### Network Scanning
- **Only scan your own network** - Scanning networks you don't own may be illegal
- **Inform household members** - Let them know about the scanning activity
- **Use appropriate timing** - Default 2 AM Sunday minimizes disruption
- **Adjust scan intensity** - Aggressive scans may trigger ISP alerts

### Application Security
- **Enable authentication** in production (set `web.enable_auth: true`)
- **Use HTTPS** with a reverse proxy like Nginx
- **Protect the database** - Ensure `/data` volume is properly secured
- **Review alerts** - Regularly check for suspicious changes

### Docker Security
- Container runs with `NET_ADMIN` and `NET_RAW` capabilities (required for nmap)
- Uses `--network=host` to access local network
- Database stored in mounted volume for persistence

## Troubleshooting

### Nmap Permission Errors

If you get permission errors:

```bash
# Docker: Ensure capabilities are set
# Check docker-compose.yml has cap_add: NET_ADMIN, NET_RAW

# Bare metal: Run as root or with sudo
sudo python scan_cli.py scan
```

### No Devices Found

- Verify your subnet is correct (check `ip addr` or `ifconfig`)
- Ensure your firewall allows nmap scanning
- Try a quick ping scan first: `python scan_cli.py scan --profile quick`
- Check if devices are actually connected to the network

### Database Errors

```bash
# Reset database (WARNING: deletes all data)
rm data/argus.db
python -c "from app.database import init_db; init_db()"
```

### Port Already in Use

If port 8080 is in use:

```bash
# Change port in config.yaml or environment variable
export PORT=8081
uvicorn app.main:app --host 0.0.0.0 --port 8081
```

## Resource Usage

### Docker Container
- **RAM**: ~100-150MB
- **CPU**: Minimal when idle, spike during scans
- **Disk**: ~500MB (container) + scan data
- **Network**: Burst traffic during scans

### Bare Metal
- **RAM**: ~50-80MB
- **CPU**: Minimal when idle, spike during scans
- **Disk**: ~200MB + scan data

### Scan Duration
- **Quick scan** (ping only): ~30 seconds for 20 devices
- **Normal scan** (1-1000 ports): 5-10 minutes for 20 devices
- **Intensive scan** (all ports + OS): 15-30 minutes for 20 devices

## Roadmap

### Phase 1: Core Scanner ✅ (Current)
- Network scanning with nmap
- Database storage
- Change detection
- CLI tool
- REST API
- Docker deployment

### Phase 2: Advanced API (Coming Soon)
- Enhanced API endpoints
- Filtering and search
- Export functionality (CSV/JSON)
- Scan scheduling API

### Phase 3: Web UI
- Dashboard with htmx + Alpine.js
- Device list view
- Scan comparison view
- Change timeline
- Device labeling

### Phase 4: Alerts & Notifications
- Email notifications
- Webhook integration
- Alert rules configuration
- Trusted device whitelisting

### Phase 5: Polish
- Authentication
- HTTPS support
- Performance optimization
- Enhanced documentation

## Contributing

This is a personal home network security project. Feel free to fork and modify for your needs.

## License

This project is for personal use. Use at your own risk.

## Disclaimer

This tool is designed for monitoring your own home network. Ensure you have proper authorization before scanning any network. Unauthorized network scanning may be illegal in your jurisdiction.

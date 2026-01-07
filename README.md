# Argus - Home Network Security Monitor

Argus is a lightweight network security monitoring tool for home networks. It uses nmap to discover devices and open ports, tracks changes over time, and alerts you to potential security threats.

![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Docker](https://img.shields.io/badge/docker-ready-blue.svg)

## Features

- **Network Scanning** - Automated discovery using nmap with configurable scan profiles
- **Device Tracking** - MAC address, hostname, vendor detection, and OS fingerprinting
- **Port Monitoring** - Service detection with version information
- **Change Detection** - Alerts for new devices, open ports, and network changes
- **Threat Assessment** - Risk scoring based on open ports and known vulnerabilities
- **Web Dashboard** - Clean UI built with htmx and Tailwind CSS
- **REST API** - Full API for integration and automation
- **Docker Ready** - Single container deployment with cron scheduling

## Screenshots

The web interface provides:
- Dashboard with network overview and threat summary
- Device list with risk indicators
- Scan history and comparison
- Change log with severity levels

## Quick Start

### Docker (Recommended)

#### Option 1: Use Pre-built Image (Easiest)

```bash
# Create directory
mkdir argus && cd argus

# Download docker-compose file
curl -O https://raw.githubusercontent.com/rangulvers/argus/main/docker-compose.yml

# Create config file
curl -o config.yaml https://raw.githubusercontent.com/rangulvers/argus/main/config.yaml.example
# Edit config.yaml - set your network subnet (e.g., 192.168.1.0/24)

# Pull and run
docker compose pull
docker compose up -d

# View logs
docker compose logs -f
```

Or use Docker directly:

```bash
docker run -d \
  --name argus \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -v ./data:/app/data \
  -v ./config.yaml:/app/config.yaml:ro \
  ghcr.io/rangulvers/argus:latest
```

#### Option 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/rangulvers/argus.git
cd argus

# Create config file
cp config.yaml.example config.yaml
# Edit config.yaml - set your network subnet (e.g., 192.168.1.0/24)

# Build and run
docker compose up -d

# View logs
docker compose logs -f
```

Access the web UI at **http://localhost:8080**

### Manual Installation

```bash
# Install nmap
sudo apt-get install nmap

# Clone and setup
git clone https://github.com/rangulvers/argus.git
cd argus
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Configure
cp config.yaml.example config.yaml
# Edit config.yaml with your network settings

# Run first scan (requires sudo for full nmap features)
sudo .venv/bin/python scan_cli.py scan --detect-changes

# Start web server
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## Configuration

Edit `config.yaml`:

```yaml
network:
  subnet: "192.168.1.0/24"      # Your network CIDR
  scan_profile: "normal"         # quick, normal, or intensive

scanning:
  port_range: "1-1000"           # Ports to scan
  enable_os_detection: true
  enable_service_detection: true

alerts:
  new_device: true               # Alert on new devices
  new_port: true                 # Alert on new open ports
```

### Scan Profiles

| Profile | Description | Duration (20 devices) |
|---------|-------------|----------------------|
| `quick` | Ping scan only, no ports | ~30 seconds |
| `normal` | Ports 1-1000, service detection | 5-10 minutes |
| `intensive` | All ports, OS detection, scripts | 15-30 minutes |

## CLI Usage

```bash
# Run a scan
python scan_cli.py scan --subnet 192.168.1.0/24 --detect-changes

# Quick ping scan
python scan_cli.py scan --profile quick

# List recent scans
python scan_cli.py list-scans

# List devices from latest scan
python scan_cli.py list-devices

# List detected changes
python scan_cli.py list-changes
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scans` | Trigger a new scan |
| `GET` | `/api/scans` | List all scans |
| `GET` | `/api/scans/{id}` | Get scan details |
| `GET` | `/api/scans/{id}/devices` | List devices from scan |
| `GET` | `/api/changes` | List detected changes |
| `GET` | `/api/device-history` | Persistent device tracking |
| `GET` | `/health` | Health check |

Full API documentation available at `/docs` when running.

## Architecture

```
argus/
├── app/
│   ├── main.py              # FastAPI application
│   ├── scanner.py           # Nmap integration
│   ├── models.py            # SQLAlchemy models
│   ├── config.py            # Configuration management
│   └── utils/
│       ├── change_detector.py   # Scan comparison
│       ├── threat_detector.py   # Risk assessment
│       └── mac_vendor.py        # Vendor lookup
├── templates/               # Jinja2 templates
├── static/                  # Static assets
├── data/                    # SQLite database
├── scan_cli.py             # CLI tool
├── Dockerfile
└── docker-compose.yml
```

## Scheduled Scans

### Docker
Scans run automatically via cron (default: Sunday 2 AM). Configure in `docker-compose.yml`.

### Bare Metal
Add to crontab:
```bash
# Weekly scan on Sunday at 2 AM
0 2 * * 0 cd /path/to/argus && /path/to/venv/bin/python scan_cli.py scan --detect-changes
```

## Security Notes

- **Only scan networks you own** - Unauthorized scanning may be illegal
- **Requires elevated privileges** - nmap needs root/sudo for OS detection
- **Docker uses host networking** - Required for accurate network scanning
- **Enable authentication** for production use (`web.enable_auth: true`)

## Requirements

- Python 3.11+
- nmap 7.80+
- Docker 20.10+ (for containerized deployment)

## Resource Usage

- **RAM**: ~100-150MB (Docker) / ~50-80MB (bare metal)
- **Disk**: ~500MB container + scan data
- **CPU**: Minimal idle, spikes during scans

## Contributing

Contributions welcome! Please open an issue or submit a PR.

## License

MIT License - See [LICENSE](LICENSE) for details.

## Disclaimer

This tool is for monitoring your own home network. Ensure you have proper authorization before scanning any network. The authors are not responsible for misuse.

# Argus - Self-Hosted Home Network Security Scanner

Open-source network monitoring for homelabs. Argus automatically discovers all devices on your network, detects vulnerabilities, and alerts you to changes - all running locally on Docker or bare metal.

![GitHub Stars](https://img.shields.io/github/stars/rangulvers/argus?style=social)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Docker](https://img.shields.io/badge/docker-ready-blue.svg)

## Why Argus?

Your home network is growing. Smart TVs, IoT devices, phones, computers - it's hard to keep track of what's connected. Argus gives you visibility and control:

- **Know what's connected** - See every device on your network with detailed information
- **Spot intruders** - Get alerts when new devices appear
- **Find vulnerabilities** - Identify risky open ports and known CVEs
- **Track changes** - Monitor your network over time with scan history

## Who Is This For?

- **Homelab enthusiasts** - Get visibility into your self-hosted infrastructure
- **Privacy-conscious users** - All data stays local, no cloud required
- **IoT device owners** - Monitor smart home devices for security risks
- **Small office/home office** - Inventory and secure your network without enterprise tools

## Features

### Network Discovery & Device Scanning
- Automatic device detection using nmap
- MAC address, hostname, and vendor identification
- OS fingerprinting to identify device types
- Multiple scan profiles (quick, normal, intensive)

### Vulnerability Detection & Risk Scoring
- Risk scoring based on open ports and services
- CVE vulnerability matching for common services (SSH, SMB, RDP, etc.)
- Threat severity classification (Critical, High, Medium, Low)
- Actionable remediation recommendations

### Device Management
- Custom labels and notes for devices
- Mark devices as trusted to reduce noise
- Organize devices by zones (e.g., IoT, Servers, Workstations)
- Persistent tracking across scans via MAC address

### Change Detection
- New device alerts
- Port open/close notifications
- Service change detection
- Historical comparison between scans

### Self-Hosted Web Dashboard
- Clean, responsive web dashboard
- Dark mode support
- Real-time scan progress
- Mobile-friendly tables

### Network Visualization
- **Interactive Topology Map** - See your network structure with device connections
- **Risk Heat Map** - Visual overview of device risk levels
- **Traffic Analysis** - Monitor bandwidth usage per device (requires UniFi)
- **Wireless Insights** - Signal strength and AP distribution (requires UniFi)
- **DNS Analytics** - Query patterns and blocked domains (requires Pi-hole/AdGuard)
- **Port Matrix** - See all open ports across devices at a glance
- **Timeline** - Track network changes over time

### Integrations
- **UniFi Network** - Pull device details, traffic stats, and wireless data
- **Pi-hole** - DNS query analytics and blocking statistics
- **AdGuard Home** - Alternative DNS filtering integration
- **CVE Database** - Match services against known vulnerabilities

### Security (v2.0)
- **Environment-based secrets** - All sensitive data (passwords, API keys) stored as environment variables
- **Command injection protection** - Strict input validation for all user-provided parameters
- **Optimized API authentication** - 100x faster key verification with DoS protection
- **Secure session management** - Production-grade session cookie signing
- **Session-based authentication** - Secure user sessions with configurable expiration
- **API key support** - Programmatic access with prefix-based lookup
- **Protected endpoints** - Authentication required for all sensitive operations
- **Audit logging** - Track all security-relevant actions

**📋 Upgrading to v2.0?** See [docs/SECURITY_MIGRATION.md](docs/SECURITY_MIGRATION.md) for migration instructions.

## Quick Start

### Docker (Recommended)

```bash
# Create directory and download files
mkdir argus && cd argus
curl -O https://raw.githubusercontent.com/rangulvers/argus/main/docker-compose.yml
curl -o config.yaml https://raw.githubusercontent.com/rangulvers/argus/main/config.yaml.example

# Edit config.yaml - set your network (e.g., 192.168.1.0/24)
nano config.yaml

# Start Argus
docker compose up -d
```

Access the web UI at **http://localhost:8080**

On first visit, you'll be prompted to create an admin account.

### Docker Run (Alternative)

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

### Manual Installation

```bash
# Install nmap
sudo apt-get install nmap   # Debian/Ubuntu
brew install nmap           # macOS

# Clone and setup
git clone https://github.com/rangulvers/argus.git
cd argus
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Configure
cp config.yaml.example config.yaml
nano config.yaml  # Set your network subnet

# Start the server
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## Configuration

Edit `config.yaml` to customize Argus:

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

| Profile | What it does | Time (20 devices) |
|---------|--------------|-------------------|
| **Quick** | Ping only - just finds devices | ~30 seconds |
| **Normal** | Ports 1-1000 + service detection | 5-10 minutes |
| **Intensive** | All ports + OS detection + scripts | 15-30 minutes |

## Security & Environment Variables

### Overview

Argus v2.0 stores all secrets as **environment variables** for enhanced security. Never store passwords or API keys in `config.yaml`.

### Required Configuration

Create a `.env` file in the Argus root directory:

```bash
# Required: Session secret for cookie signing
# Generate with: python -c 'import secrets; print(secrets.token_urlsafe(32))'
ARGUS_SESSION_SECRET=your_secure_session_secret_here

# Recommended: Production mode (enforces strict security)
ARGUS_ENVIRONMENT=production
```

### Optional Secrets (if features enabled)

Only add these if you're using the corresponding integration:

```bash
# Email notifications
ARGUS_EMAIL_SMTP_PASSWORD=your_smtp_password

# Webhook notifications
ARGUS_WEBHOOK_SECRET=your_webhook_secret

# CVE vulnerability checking
ARGUS_CVE_API_KEY=your_nvd_api_key

# UniFi controller integration
ARGUS_UNIFI_PASSWORD=your_unifi_password
ARGUS_UNIFI_API_KEY=your_unifi_api_key

# Pi-hole integration
ARGUS_PIHOLE_API_TOKEN=your_pihole_token

# AdGuard Home integration
ARGUS_ADGUARD_PASSWORD=your_adguard_password
```

### Docker Configuration

Mount the `.env` file in your `docker-compose.yml`:

```yaml
services:
  argus:
    image: ghcr.io/rangulvers/argus:latest
    env_file:
      - .env  # Load all ARGUS_* variables
    environment:
      - ARGUS_ENVIRONMENT=production
    # ... rest of configuration
```

### File Permissions

Protect your `.env` file:

```bash
chmod 600 .env
echo ".env" >> .gitignore  # Never commit secrets!
```

### Upgrading from v1.x

If upgrading from v1.x (where secrets were in `config.yaml`):

```bash
# 1. Run automated migration
python migrate_secrets.py

# 2. Generate session secret
python -c 'import secrets; print(secrets.token_urlsafe(32))'

# 3. Add to .env file
echo "ARGUS_SESSION_SECRET=<generated_secret>" >> .env

# 4. Restart Argus
docker-compose restart  # or systemctl restart argus
```

**Full migration guide:** [docs/SECURITY_MIGRATION.md](docs/SECURITY_MIGRATION.md)

## Using Argus

### Dashboard
The dashboard shows your network at a glance:
- Total devices and security status
- Risk distribution chart
- Devices requiring attention
- Recent changes

### Devices
Browse all discovered devices with:
- Risk level indicators
- Open port counts
- Quick filters by zone, risk, or trusted status
- Search by IP, hostname, MAC, or label

### Device Details
Click any device to see:
- Full device information
- Open ports with service details
- CVE vulnerabilities affecting the device
- Threat analysis and recommendations
- Device settings (label, zone, trusted status)

### Scan History
View past scans and compare changes between them.

### Running Scans
Click "Run Scan" in the top right to start a new scan. Choose:
- **Quick Scan** - Fast discovery, no port scanning
- **Normal Scan** - Balanced speed and detail
- **Intensive Scan** - Full analysis (use sparingly)

## Scheduled Scans

### Docker
Scans run automatically via cron (default: Sunday 2 AM). Adjust the schedule in `docker-compose.yml`.

### Manual/Crontab
```bash
# Weekly scan on Sunday at 2 AM
0 2 * * 0 cd /path/to/argus && /path/to/venv/bin/python scan_cli.py scan --detect-changes
```

## CLI Reference

```bash
# Run a scan
python scan_cli.py scan --subnet 192.168.1.0/24 --detect-changes

# Quick ping scan
python scan_cli.py scan --profile quick

# List recent scans
python scan_cli.py list-scans

# List devices
python scan_cli.py list-devices

# List changes
python scan_cli.py list-changes
```

## API

Argus provides a REST API for automation and integration.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan/trigger` | Start a new scan |
| `GET` | `/api/scans` | List all scans |
| `GET` | `/api/scans/{id}/devices` | Devices from a scan |
| `GET` | `/api/devices/{id}` | Device details |
| `PUT` | `/api/devices/{id}` | Update device settings |
| `GET` | `/api/changes` | Change history |
| `GET` | `/api/zones` | List device zones |

Full API docs available at `/docs` when running.

## Security Considerations

- **Only scan networks you own** - Unauthorized scanning may be illegal
- **Requires elevated privileges** - nmap needs root/sudo for full features
- **Docker uses host networking** - Required for accurate network discovery
- **Change the default password** - Create a strong admin password on setup

## Requirements

- Python 3.11+
- nmap 7.80+
- Docker 20.10+ (for containerized deployment)

## Resource Usage

| Metric | Docker | Bare Metal |
|--------|--------|------------|
| RAM | ~100-150MB | ~50-80MB |
| Disk | ~500MB + data | ~100MB + data |
| CPU | Low idle, spikes during scans | Same |

## Alternatives & Comparison

How does Argus compare to other network scanning tools?

| Tool | Self-Hosted | Vulnerability Detection | Change Tracking | Web UI |
|------|-------------|------------------------|-----------------|--------|
| **Argus** | Yes | Yes | Yes | Yes |
| Fing/Fingbox | No (cloud) | Limited | Yes | Yes |
| Angry IP Scanner | Yes | No | No | No |
| OpenVAS | Yes | Yes | No | Yes |
| Nmap (CLI) | Yes | Manual | No | No |

Argus is designed for homelab users who want a self-hosted, open-source alternative to commercial network scanners like Fing - with vulnerability detection, change tracking, and a clean web interface.

## Contributing

Contributions welcome! Please open an issue or submit a PR on GitHub.

## License

MIT License - See [LICENSE](LICENSE) for details.

---

Built with love for the homelab community.

[GitHub](https://github.com/rangulvers/argus) | [Report an Issue](https://github.com/rangulvers/argus/issues)

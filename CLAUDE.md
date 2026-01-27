# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Argus is a self-hosted home network security monitoring application that performs scheduled network scans using nmap, discovers devices and open ports, and tracks changes over time. It provides both a CLI and web interface for managing scans. Built with Python FastAPI, SQLAlchemy, and Jinja2 templates with htmx for dynamic UI updates.

**Current Version**: v2.0.0 (Security Hardening Release - January 2026)

**Key Technologies**:
- Python 3.11+ (tested on 3.13)
- FastAPI (REST API + Jinja2 templates)
- SQLAlchemy ORM with SQLite
- python-nmap for network scanning
- APScheduler for scheduled scans
- htmx for dynamic UI
- Session-based + API key authentication

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

**Time Estimates** (for ~20 devices):
- Quick: ~30 seconds
- Normal: 5-10 minutes
- Intensive: 15-30 minutes

### Database Models (app/models.py)

- `Scan`: Scan metadata (status, subnet, devices_found)
- `Device`: Discovered devices (IP, MAC, vendor, OS, risk_level, threat_details JSON)
- `Port`: Open ports per device
- `Change`: Detected changes between scans
- `DeviceHistory`: Persistent device tracking by MAC address
- `Alert`: Triggered alerts (unused in Phase 1)

### Configuration

Config loaded from `config.yaml` (see `config.yaml.example`). Pydantic settings in `app/config.py` with `.env` fallback.

**Key settings**:
- `network.subnet`: Target network CIDR (e.g., "192.168.1.0/24")
- `network.scan_profile`: Default scan profile (quick/normal/intensive)
- `scanning.port_range`: Port range ("1-1000", "common", "all")
- `database.path`: SQLite file location (default: "./data/argus.db")

**Security settings** (environment variables only):
- `ARGUS_SESSION_SECRET`: Session cookie signing key (required in production)
- `ARGUS_ENVIRONMENT`: "production" or "development"
- `ARGUS_EMAIL_SMTP_PASSWORD`: SMTP password for email notifications
- `ARGUS_WEBHOOK_SECRET`: Webhook authentication secret
- `ARGUS_CVE_API_KEY`: NVD CVE API key for vulnerability checking
- `ARGUS_UNIFI_PASSWORD`: UniFi controller password
- `ARGUS_PIHOLE_API_TOKEN`: Pi-hole API token
- `ARGUS_ADGUARD_PASSWORD`: AdGuard Home password

**Configuration reload**: Use `reload_config()` function to reload settings without restart.

### Web UI

Templates in `templates/` use Jinja2 with htmx for dynamic updates:
- `dashboard.html`: Overview with stats and recent changes
- `devices.html`: Device list from selected scan
- `device_detail.html`: Single device with ports and threat info
- `scans.html`: Scan history
- `changes.html`: Change log
- `compare.html`: Side-by-side scan comparison

## Key Patterns

- **Device identification**: Uses MAC address primarily, falls back to IP
- **Quick scans**: Carry forward port data from previous scans to avoid redundant scanning
- **User data persistence**: Labels and trusted status persist across scans via `DeviceHistory`
- **Threat assessment**: Per-device based on `THREAT_DATABASE` port mappings
- **Background tasks**: Long-running scans use FastAPI `BackgroundTasks`
- **Session management**: itsdangerous for cookie signing, configurable expiration
- **API authentication**: Prefix-based key lookup (O(1)) before hash verification
- **Input validation**: Strict regex validation for all command-line parameters

## Database Patterns

### Session Management
```python
# Always use get_db() dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# In routes
@app.get("/api/devices")
def list_devices(db: Session = Depends(get_db)):
    devices = db.query(Device).all()
    return devices
```

### Safe Commits
```python
try:
    scan = Scan(started_at=datetime.utcnow(), status="running")
    db.add(scan)
    db.commit()
    db.refresh(scan)  # Populate auto-generated fields
except SQLAlchemyError as e:
    db.rollback()
    logger.error(f"Database error: {e}")
    raise HTTPException(status_code=500, detail="Database error")
```

## Logging Patterns

```python
import logging
logger = logging.getLogger(__name__)

# Log levels
logger.info(f"Starting scan of {subnet}")
logger.warning(f"No devices found in scan {scan_id}")
logger.error(f"Scan failed: {error_message}")
logger.debug(f"Processing host {ip}")  # Verbose debugging
```

## FastAPI Patterns

### Dependency Injection
```python
from fastapi import Depends, HTTPException
from app.auth import get_current_user

@app.get("/api/protected")
def protected_route(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    # Route logic
    pass
```

### Background Tasks
```python
from fastapi import BackgroundTasks

@app.post("/api/scan/trigger")
def trigger_scan(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    scan = Scan(status="running")
    db.add(scan)
    db.commit()

    background_tasks.add_task(perform_scan_task, scan.id)
    return {"scan_id": scan.id}
```

### Input Validation
```python
from pydantic import BaseModel, Field, validator

class ScanRequest(BaseModel):
    subnet: str = Field(..., regex=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$")
    profile: str = Field("normal", regex="^(quick|normal|intensive)$")

    @validator("port_range")
    def validate_port_range(cls, v):
        if not re.match(r"^[0-9,\-]+$", v):
            raise ValueError("Invalid port range format")
        return v
```

## Requirements

- Python 3.11+ (tested on 3.13)
- nmap 7.80+ installed on host (`sudo apt-get install nmap`)
- Root/sudo for full nmap functionality (OS detection, raw packets)
- Docker 20.10+ with `NET_ADMIN` and `NET_RAW` capabilities for containerized scanning

## Recent Changes (v2.0.0)

### Security Improvements
1. **Command Injection Protection** (Issue #4)
   - Strict port range validation with regex: `^[0-9,\-]+$`
   - Blocks all shell metacharacters in `_validate_port_range()` method

2. **API Key DoS Fix** (Issue #5)
   - Prefix-based lookup before expensive hash verification
   - Performance: 100x faster (500ms → 5ms per request)
   - Uses `key_prefix` field for O(1) database lookup

3. **Secrets Management** (Issue #3)
   - All secrets now via environment variables (`ARGUS_*` prefix)
   - `config.yaml` contains only `***REDACTED***` placeholders
   - `save_config()` auto-redacts secrets when writing config
   - Migration script: `migrate_secrets.py`

4. **Session Secret Security** (Issue #2)
   - Production mode requires `ARGUS_SESSION_SECRET` env var
   - Development mode allows file-based fallback with warnings
   - Explicit environment specification via `ARGUS_ENVIRONMENT`

### Breaking Changes
- Secrets **must** be stored as environment variables (not in `config.yaml`)
- Session secret required for production deployments
- See `docs/SECURITY_MIGRATION.md` for migration guide

## Testing

### Running Tests
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_api.py

# Run with coverage
pytest --cov=app --cov-report=html

# Run tests matching pattern
pytest -k "device"

# Verbose output
pytest -v
```

### Test Patterns
- All test functions start with `test_`
- Use fixtures from `conftest.py` for setup
- `test_db` fixture provides isolated database
- `authenticated_client` fixture for API tests requiring auth
- Database cleared between tests for isolation
- Mock external dependencies (nmap, API calls)

### Test Files
- `tests/test_scanner_security.py` - Command injection and port validation
- `tests/test_api_keys.py` - API key performance and prefix lookup
- `tests/test_api.py` - API endpoint tests
- `tests/conftest.py` - Shared fixtures

## Code Style Guidelines

### Naming Conventions
- **Classes**: `PascalCase` (e.g., `NetworkScanner`, `ThreatDetector`)
- **Functions/methods**: `snake_case` (e.g., `perform_scan`, `detect_changes`)
- **Variables**: `snake_case` (e.g., `device_id`, `scan_profile`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `THREAT_DATABASE`, `SESSION_MAX_AGE`)
- **Private methods**: Prefix with `_` (e.g., `_process_host`, `_validate_port_range`)

### Type Hints
Always use type hints for function signatures:
```python
def perform_scan(
    self,
    subnet: str,
    scan_profile: str = "normal",
    enable_os_detection: bool = True
) -> Scan:
    """Perform a network scan"""
    ...
```

### Error Handling
- Use specific exceptions rather than bare `except`
- Log errors with context using `logging` module
- Return HTTP 4xx for client errors, 5xx for server errors
- Validate inputs at API boundaries to prevent injection attacks

### Security Best Practices
- **Always validate user inputs** - especially for command execution (nmap args)
- **Use parameterized queries** - SQLAlchemy protects against SQL injection
- **Store secrets in environment variables** - never in code or config files
- **Use constant-time comparisons** for API keys/passwords
- **Log security events** - authentication attempts, validation failures
- **Apply rate limiting** - protect against brute force and DoS

## Important Notes

- **Never commit database files** (`*.db`, `data/` contents)
- **Never commit secrets** (`.env`, API keys, passwords)
- **Requires nmap installed** on host system
- **Requires root/sudo** for full nmap functionality (OS detection, raw packets)
- **Database location**: `./data/argus.db` (SQLite)
- **Templates**: Jinja2 in `templates/` with htmx for dynamic updates
- **Test isolation**: Middleware accesses SessionLocal directly, some tests skipped
- **Git branch**: Current work on `feature_update`, merge to `main` for releases

## Integrations

### UniFi Network Controller
- Pulls device details, traffic stats, and wireless data
- Configuration in `config.yaml` under `unifi_integration`
- Password stored as `ARGUS_UNIFI_PASSWORD` environment variable

### Pi-hole
- DNS query analytics and blocking statistics
- Configuration in `config.yaml` under `pihole_integration`
- API token stored as `ARGUS_PIHOLE_API_TOKEN` environment variable

### AdGuard Home
- Alternative DNS filtering integration
- Configuration in `config.yaml` under `adguard_integration`
- Password stored as `ARGUS_ADGUARD_PASSWORD` environment variable

### CVE Database (NVD)
- Matches detected services against known vulnerabilities
- Configuration in `config.yaml` under `cve_integration`
- API key stored as `ARGUS_CVE_API_KEY` environment variable

## Network Visualization Features

The visualization system provides multiple views of network data:

1. **Interactive Topology Map** - Device connections and network structure
2. **Risk Heat Map** - Visual overview of device risk levels
3. **Traffic Analysis** - Bandwidth usage per device (requires UniFi)
4. **Wireless Insights** - Signal strength and AP distribution (requires UniFi)
5. **DNS Analytics** - Query patterns and blocked domains (requires Pi-hole/AdGuard)
6. **Port Matrix** - All open ports across devices at a glance
7. **Timeline** - Track network changes over time

Templates: `templates/visualization.html`

## Planned Features (Roadmap)

See `FEATURES.md` for detailed feature roadmap.

**Priority 0 (Critical)**:
- User authentication and access control (✅ Complete in v2.0)
- Alerting and notifications (Email, Webhook, Push)

**Priority 1 (High)**:
- Device management enhancements (zones/groups, bulk operations)
- Reporting and export (CSV, PDF, scheduled reports)
- Advanced scanning (multi-subnet, CVE integration)

**Priority 2 (Medium)**:
- Network visualization improvements
- Network intelligence (ARP monitoring, DHCP integration)
- Integrations (Prometheus, Home Assistant, Grafana)

**Priority 3 (Low)**:
- UX improvements (dark mode, mobile responsive)
- Operations tools (backup/restore, health dashboard)

## File Structure Reference

### Core Application
- `app/main.py` - FastAPI app, routes, middleware, authentication
- `app/scanner.py` - NetworkScanner class (nmap wrapper)
- `app/models.py` - SQLAlchemy database models
- `app/database.py` - Database session management, init_db()
- `app/auth.py` - Authentication and authorization helpers
- `app/config.py` - Pydantic Settings configuration management

### Utilities
- `app/utils/threat_detector.py` - ThreatDetector with THREAT_DATABASE
- `app/utils/change_detector.py` - ChangeDetector for scan comparison
- `app/utils/mac_vendor.py` - MAC address vendor lookup (Wireshark manuf DB)

### CLI & Scripts
- `scan_cli.py` - CLI entry point for scans
- `migrate_secrets.py` - Migration script for v1.x → v2.0 (secrets to env vars)

### Testing
- `tests/conftest.py` - pytest fixtures and test database setup
- `tests/test_api.py` - API endpoint tests
- `tests/test_scanner_security.py` - Command injection and validation tests
- `tests/test_api_keys.py` - API key performance and security tests

### Templates
- `templates/dashboard.html` - Overview dashboard with stats
- `templates/devices.html` - Device list from selected scan
- `templates/device_detail.html` - Single device details with ports/threats
- `templates/scans.html` - Scan history
- `templates/changes.html` - Change log
- `templates/compare.html` - Side-by-side scan comparison
- `templates/visualization.html` - Network visualization views

### Configuration & Docs
- `config.yaml` - Main configuration file (no secrets!)
- `config.yaml.example` - Example configuration template
- `.env` - Environment variables for secrets (never commit!)
- `.env.example` - Example environment variables template
- `CLAUDE.md` - This file - guidance for Claude Code
- `AGENTS.md` - Detailed coding guidelines for AI agents
- `FEATURES.md` - Feature roadmap and planned enhancements
- `CHANGELOG.md` - Version history and release notes
- `README.md` - Project documentation and quick start guide
- `docs/SECURITY_MIGRATION.md` - v2.0 migration guide

## Additional Resources

For detailed coding guidelines, style conventions, and architecture patterns, see:
- **`AGENTS.md`** - Comprehensive coding guidelines for AI agents
- **`FEATURES.md`** - Feature roadmap with priorities and complexity estimates
- **`docs/SECURITY_MIGRATION.md`** - Security migration guide for v2.0 upgrade

## Quick Reference

### Database Models
- `Scan` - Scan metadata (status, subnet, devices_found)
- `Device` - Discovered devices (IP, MAC, vendor, OS, risk_level, threat_details)
- `Port` - Open ports per device
- `Change` - Detected changes between scans
- `DeviceHistory` - Persistent device tracking by MAC address
- `Alert` - Triggered alerts (configured but not fully implemented)

### Scan Flow
1. Create `Scan` record with status "running"
2. Run nmap via `NetworkScanner.perform_scan()`
3. Process each host with `_process_host()` (merges with previous data)
4. Calculate risk scores via `ThreatDetector.assess_device()`
5. Detect changes via `ChangeDetector.detect_changes()`
6. Update scan status to "completed" or "failed"

### API Endpoints
- `POST /api/scan/trigger` - Start a new scan
- `GET /api/scans` - List all scans
- `GET /api/scans/{id}/devices` - Devices from a scan
- `GET /api/devices/{id}` - Device details
- `PUT /api/devices/{id}` - Update device settings
- `GET /api/changes` - Change history
- `GET /api/zones` - List device zones

Full API documentation available at `/docs` when running the server.

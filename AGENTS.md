# AGENTS.md

Coding guidelines for AI agents working on the Argus network security monitoring application.

## Project Overview

Argus is a Python FastAPI application for home network security monitoring using nmap. It scans networks, detects devices/ports, tracks changes over time, and provides both CLI and web interfaces. Uses SQLite for storage, SQLAlchemy for ORM, Jinja2 templates with htmx for UI, and APScheduler for scheduled scans.

## Build & Test Commands

### Testing
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_api.py

# Run single test function
pytest tests/test_api.py::TestDevicesAPI::test_list_devices_empty

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=app --cov-report=html

# Run tests matching pattern
pytest -k "device"
```

### Development
```bash
# Install dependencies (Python 3.11+)
pip install -r requirements.txt

# Start web server (requires nmap: sudo apt-get install nmap)
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload

# Initialize/reset database
python -c "from app.database import init_db; init_db()"

# Run CLI scan (requires root for full nmap features)
sudo python scan_cli.py scan --subnet 192.168.1.0/24 --detect-changes

# Quick ping-only scan
python scan_cli.py scan --profile quick
```

### Docker
```bash
docker-compose build
docker-compose up -d
docker-compose logs -f
```

### Linting (No formal linters configured yet)
- Follow PEP 8 style conventions
- Use consistent formatting (see style guide below)

## Code Style Guidelines

### Imports
Standard library → Third-party → Local application imports, separated by blank lines:
```python
# Standard library
from datetime import datetime
from typing import List, Optional

# Third-party
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session

# Local
from app.models import Scan, Device, Port
from app.utils.change_detector import ChangeDetector
```

### Naming Conventions
- **Classes**: `PascalCase` (e.g., `NetworkScanner`, `ThreatDetector`)
- **Functions/methods**: `snake_case` (e.g., `perform_scan`, `detect_changes`)
- **Variables**: `snake_case` (e.g., `device_id`, `scan_profile`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `THREAT_DATABASE`, `SESSION_MAX_AGE`)
- **Private methods**: Prefix with `_` (e.g., `_process_host`, `_build_nmap_args`)

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

### Docstrings
Use triple-quoted strings for all classes, functions, and modules:
```python
"""Network scanner using nmap"""

class NetworkScanner:
    """Network scanner using nmap"""
    
    def perform_scan(self, subnet: str) -> Scan:
        """
        Perform a network scan
        
        Args:
            subnet: Network subnet to scan (e.g., "192.168.1.0/24")
            
        Returns:
            Scan object with results
        """
```

### Error Handling
- Use specific exceptions rather than bare `except` clauses
- Log errors with appropriate context using `logging` module
- Return HTTP 4xx for client errors, 5xx for server errors
```python
try:
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
except SQLAlchemyError as e:
    logger.error(f"Database error: {e}")
    raise HTTPException(status_code=500, detail="Database error")
```

### Database Operations
- Always use SQLAlchemy sessions via `get_db()` dependency
- Commit after inserts/updates, rollback on errors
- Use relationships for joins, not manual queries
- Close sessions properly (handled by FastAPI dependencies)
```python
scan = Scan(started_at=datetime.utcnow(), status="running")
db.add(scan)
db.commit()
db.refresh(scan)
```

### Logging
Use module-level logger:
```python
import logging
logger = logging.getLogger(__name__)

logger.info(f"Starting scan of {subnet}")
logger.warning(f"No devices found in scan {scan_id}")
logger.error(f"Scan failed: {error_message}")
```

### FastAPI Patterns
- Use Pydantic models for request/response validation
- Use dependency injection for database sessions
- Use `BackgroundTasks` for long-running operations (scans)
- Use `HTTPException` for error responses
- Mount static files and templates appropriately

### Testing Patterns
- All test functions must start with `test_`
- Use fixtures from `conftest.py` for database setup
- Use `test_db` fixture for database operations
- Use `authenticated_client` fixture for API tests requiring auth
- Tests are isolated - database is cleared between tests
- Mock external dependencies (nmap scans, API calls)

## Key Architecture Patterns

### Device Identification
- Devices tracked primarily by MAC address (persistent across IP changes)
- Falls back to IP address if MAC unavailable
- `DeviceHistory` table stores user labels/notes across scans
- Quick scans preserve port data from previous scans

### Scan Flow
1. Create `Scan` record with status "running"
2. Run nmap via `NetworkScanner.perform_scan()`
3. Process each host with `_process_host()` (merges with previous data)
4. Calculate risk scores via `ThreatDetector.assess_device()`
5. Detect changes via `ChangeDetector.detect_changes()`
6. Update scan status to "completed" or "failed"

### Configuration
- Primary config: `config.yaml` (see `config.yaml.example`)
- Fallback: `.env` file or environment variables
- Managed by Pydantic settings in `app/config.py`
- Reload config with `reload_config()` function

### Security
- Authentication via session cookies (using itsdangerous)
- API key support with hashed storage (pbkdf2_sha256)
- Password hashing via passlib (pbkdf2_sha256)
- Rate limiting via slowapi
- Audit logging for sensitive operations

## Important Notes

- **Never commit database files** (`*.db`, `data/` contents)
- **Requires nmap installed** on host system
- **Requires root/sudo** for full nmap functionality (OS detection, raw packets)
- **Database location**: `./data/argus.db` (SQLite)
- **Templates**: Jinja2 in `templates/` with htmx for dynamic updates
- **Python version**: 3.11+ (tested on 3.13)
- **Test isolation**: Middleware accesses SessionLocal directly, so some tests are skipped

## File Reference

- `app/main.py`: FastAPI app, routes, middleware
- `app/scanner.py`: NetworkScanner class (nmap wrapper)
- `app/models.py`: SQLAlchemy database models
- `app/database.py`: Database session management
- `app/auth.py`: Authentication/authorization helpers
- `app/utils/threat_detector.py`: Port risk assessment
- `app/utils/change_detector.py`: Scan comparison logic
- `scan_cli.py`: CLI entry point for scans
- `tests/conftest.py`: Pytest fixtures and test setup

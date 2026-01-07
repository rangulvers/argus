# Argus - Optimized Technology Stack Analysis

## Critical Issues with Original Choices ❌

### 1. Frontend: React/Vue - TOO HEAVY
**Problems**:
- React bundle: ~140KB minified (300KB+ unminified)
- Vue bundle: ~90KB minified
- Requires Node.js build process (500MB+ RAM during build)
- Runtime overhead for simple dashboard
- Overkill for Raspberry Pi

### 2. Task Queue: Celery + Redis - MASSIVE OVERKILL
**Problems**:
- Redis daemon: ~15-30MB RAM constantly
- Celery worker: Additional Python process
- Complex setup for just weekly scheduled scans
- Unnecessary when cron exists

### 3. Docker Setup: 4 Containers - RESOURCE WASTE
**Problems**:
- Each container adds overhead (~50MB RAM each minimum)
- PostgreSQL container: 30-50MB RAM for simple data
- Redis container: 15-30MB RAM for scheduling
- Slow I/O on SD cards with container layers
- Total overhead: ~200MB+ RAM for infrastructure

## Optimized Technology Stack ✅

### Backend Framework

**RECOMMENDED: Flask**
```
Why: Lightweight, mature, perfect for this use case
RAM: ~30-50MB
Startup: <1 second
```

**Alternative: FastAPI** (if you want modern features)
```
Why: Async, auto-docs, type hints
RAM: ~50-80MB
Tradeoff: Slightly heavier but still acceptable
```

**Winner**: **Flask** for simplicity and efficiency, **FastAPI** if you value modern DX

### Frontend Framework

**RECOMMENDED: htmx + Alpine.js**
```
Bundle size: ~50KB total
Approach: Server-side rendering with HTML over the wire
RAM: Minimal (server-side templates)
Why: Perfect for dashboards, minimal JavaScript, fast on Pi
```

**Alternative 1: Svelte**
```
Bundle size: ~15-30KB compiled
Why: Compiles to vanilla JS, no runtime overhead
Good for: More interactive UI needs
```

**Alternative 2: Jinja2 Templates (Server-Side Only)**
```
Bundle size: 0KB JavaScript
Why: Pure server-side rendering, fastest option
Good for: Simple dashboards, minimal interactivity
```

**Winner**: **htmx + Alpine.js** - Best balance of simplicity and interactivity

### Database

**RECOMMENDED: SQLite**
```
Why:
- Single file database
- No daemon process
- Zero configuration
- Perfect for write-once-weekly pattern
- 10-20MB RAM for normal operations
- Built into Python

NO POSTGRESQL NEEDED - it's overkill for this use case
```

**Winner**: **SQLite** (no contest)

### Scheduling

**RECOMMENDED: Linux cron + systemd**
```
Why:
- Native to Linux
- Zero overhead
- Battle-tested reliability
- Perfect for weekly schedules
- Easy to configure: `0 2 * * 0 /path/to/scan.py`
```

**Alternative: APScheduler** (if you want Python-based)
```
Why:
- In-process scheduling
- No external dependencies
- Good for dynamic schedules
Tradeoff: Slightly more complex than cron
```

**Winner**: **cron** for simplicity, **APScheduler** if you need programmatic control

### Nmap Integration

**RECOMMENDED: python-nmap**
```
Why:
- Mature library
- Good abstraction over nmap CLI
- Active maintenance
```

**Alternative: Direct subprocess calls to nmap**
```python
subprocess.run(['nmap', '-sn', '192.168.1.0/24'])
```
```
Why: More control, no dependency
Tradeoff: More code to parse output
```

**Winner**: **python-nmap** for ease of use

## Revised Architecture

### Option 1: Single Container (Recommended for Docker)

```
┌─────────────────────────────────────────────┐
│         Single Docker Container             │
│                                             │
│  ┌────────────────────────────────────┐   │
│  │  Flask App + htmx Frontend         │   │
│  │  - Serves static HTML/CSS/JS       │   │
│  │  - REST API endpoints              │   │
│  │  - Background scan trigger         │   │
│  └────────────────────────────────────┘   │
│                                             │
│  ┌────────────────────────────────────┐   │
│  │  SQLite Database                   │   │
│  │  (mounted volume)                  │   │
│  └────────────────────────────────────┘   │
│                                             │
│  ┌────────────────────────────────────┐   │
│  │  nmap binary                       │   │
│  └────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
         │
         │ Scheduled via cron OR
         │ APScheduler internally
         ▼
```

**Resource Usage**:
- Total RAM: ~100-150MB
- Disk: ~500MB container image
- CPU: Minimal when idle

### Option 2: Bare Metal (Most Efficient)

```
Raspberry Pi / Linux Host
├── /opt/argus/
│   ├── app.py (Flask application)
│   ├── scanner.py (Nmap scan logic)
│   ├── templates/ (HTML templates)
│   ├── static/ (CSS, JS)
│   └── data/
│       └── argus.db (SQLite)
├── /etc/systemd/system/
│   └── argus.service (Web service)
└── /etc/cron.d/
    └── argus (Weekly scan schedule)
```

**Resource Usage**:
- Total RAM: ~50-80MB
- Disk: ~100MB (Python + dependencies)
- CPU: Minimal when idle

**Winner**: **Bare metal** for maximum efficiency, **single container** for portability

## Deployment Comparison

| Aspect | Original (4 containers) | Optimized (1 container) | Bare Metal |
|--------|-------------------------|-------------------------|------------|
| RAM Usage | ~300-400MB | ~100-150MB | ~50-80MB |
| Startup Time | 30-60s | 5-10s | <5s |
| Complexity | High | Low | Medium |
| Portability | High | High | Low |
| Performance | Medium | Good | Best |
| Maintenance | Medium | Easy | Easy |

## Updated Technology Stack Summary

```yaml
Backend:
  Framework: Flask (or FastAPI if preferred)
  Language: Python 3.11+
  Scanner: python-nmap
  Scheduling: Linux cron (or APScheduler)

Frontend:
  Framework: htmx + Alpine.js
  Styling: Tailwind CSS or simple CSS
  Templates: Jinja2
  Bundle: <50KB

Database:
  Primary: SQLite
  ORM: SQLAlchemy (optional) or raw SQL

Deployment:
  Recommended: Single Docker container
  Alternative: Bare metal with systemd
  Scheduler: cron or APScheduler

Infrastructure:
  Web Server: Gunicorn (production) or Flask dev (simple)
  Reverse Proxy: Nginx (optional, for HTTPS)
  Process Manager: systemd
```

## Key Improvements

1. **RAM savings**: ~200-300MB (75% reduction)
2. **Startup time**: 6x faster
3. **Complexity**: Much simpler architecture
4. **Maintenance**: Fewer moving parts
5. **Performance**: Better responsiveness on Pi

## Implementation Recommendations

### For Raspberry Pi 4 (2-4GB RAM)
```
✅ Single Docker container with SQLite
✅ htmx + Alpine.js frontend
✅ Flask backend
✅ cron scheduling
✅ Nginx for HTTPS (optional)

Total footprint: ~150MB RAM, boots in ~10 seconds
```

### For Raspberry Pi Zero/3 (512MB-1GB RAM)
```
✅ Bare metal installation
✅ Pure Jinja2 templates (no Alpine.js)
✅ Flask backend
✅ SQLite
✅ cron scheduling

Total footprint: ~50MB RAM, boots in <5 seconds
```

### For Docker on NAS/Server
```
✅ Single container
✅ htmx + Alpine.js or Svelte
✅ FastAPI (can leverage more resources)
✅ SQLite (or PostgreSQL if shared with other apps)
✅ Internal scheduler or cron

Total footprint: ~200MB RAM (resources less critical)
```

## Removed Unnecessaries

- ❌ Redis (replaced with cron/APScheduler)
- ❌ Celery (not needed for weekly tasks)
- ❌ PostgreSQL (SQLite is sufficient)
- ❌ React/Vue (too heavy, replaced with htmx)
- ❌ Separate frontend container (serve static files from backend)
- ❌ Node.js runtime (pre-build if needed)

## Development Workflow

### With Docker:
```bash
# Build once
docker build -t argus .

# Run
docker run -d \
  --network=host \
  --cap-add=NET_ADMIN \
  -v /path/to/data:/app/data \
  argus
```

### Bare Metal:
```bash
# Install dependencies
pip install flask python-nmap sqlalchemy

# Run as service
sudo systemctl enable argus
sudo systemctl start argus

# Setup cron
echo "0 2 * * 0 /opt/argus/scan.py" | sudo tee /etc/cron.d/argus
```

## Conclusion

The original stack was designed for large-scale web applications, not a lightweight home network scanner on a Raspberry Pi. The optimized stack:

- **Uses 70% less RAM**
- **Starts 6x faster**
- **Has 1/4 the complexity**
- **Costs nothing in functionality**
- **Is easier to maintain**

For this specific use case (weekly scans, simple dashboard, low traffic), the optimized stack is objectively superior.

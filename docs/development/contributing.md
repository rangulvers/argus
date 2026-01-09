# Contributing

## Setup

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/argus.git
cd argus

# Environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Config
cp config.yaml.example config.yaml

# Run dev server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8080
```

## Workflow

```bash
# Create branch
git checkout -b feature/my-feature

# Make changes, test locally

# Run tests
python -m pytest tests/ -v

# Commit
git commit -m "Add feature X"

# Push and open PR
git push origin feature/my-feature
```

Branch naming: `feature/`, `fix/`, `docs/`, `refactor/`

## Project Structure

```
app/
├── main.py           # FastAPI routes
├── models.py         # SQLAlchemy models
├── database.py       # DB connection
├── scanner.py        # nmap wrapper
├── auth.py           # Authentication
├── config.py         # Configuration
└── utils/
    ├── change_detector.py
    ├── threat_detector.py
    └── mac_vendor.py
templates/            # Jinja2 HTML
static/               # Assets
tests/                # Pytest
docs/                 # MkDocs
```

## Adding Features

### New API Endpoint

1. Add route in `app/main.py`
2. Add Pydantic models for request/response
3. Add tests in `tests/`
4. Update `docs/api/endpoints.md`

### New Template

1. Create in `templates/`
2. Extend `base.html`
3. Add route in `app/main.py`

### New Model

1. Add in `app/models.py`
2. Reinit DB or create migration
3. Add tests

## Code Style

- PEP 8, 100 char lines
- Double quotes
- Type hints where practical

## Tests

```bash
python -m pytest tests/ -v
python -m pytest tests/ --cov=app --cov-report=html
```

## Docs

```bash
pip install mkdocs-material
mkdocs serve  # http://localhost:8000
```

## License

MIT - contributions under same license.

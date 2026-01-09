# Contributing

Thank you for your interest in contributing to Argus! This guide will help you get started.

## Getting Started

### Prerequisites

- Python 3.11+
- nmap installed
- Git
- A GitHub account

### Setting Up the Development Environment

1. **Fork the repository** on GitHub

2. **Clone your fork**:

    ```bash
    git clone https://github.com/YOUR_USERNAME/argus.git
    cd argus
    ```

3. **Create a virtual environment**:

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

4. **Install dependencies**:

    ```bash
    pip install -r requirements.txt
    pip install -r requirements-dev.txt  # If available
    ```

5. **Copy the example config**:

    ```bash
    cp config.yaml.example config.yaml
    ```

6. **Run the development server**:

    ```bash
    uvicorn app.main:app --reload --host 0.0.0.0 --port 8080
    ```

## Development Workflow

### Creating a Feature Branch

```bash
git checkout -b feature/my-new-feature
```

Branch naming conventions:

- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring

### Making Changes

1. Write your code
2. Add tests if applicable
3. Update documentation if needed
4. Run tests locally

### Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_api_keys.py -v

# Run with coverage
python -m pytest tests/ --cov=app --cov-report=html
```

### Code Style

We follow PEP 8 with some modifications:

- Max line length: 100 characters
- Use double quotes for strings
- Use type hints where practical

### Committing Changes

Write clear, descriptive commit messages:

```bash
git commit -m "Add device export functionality

- Add CSV export endpoint
- Add JSON export endpoint
- Update documentation"
```

### Creating a Pull Request

1. Push your branch:

    ```bash
    git push origin feature/my-new-feature
    ```

2. Open a Pull Request on GitHub

3. Fill out the PR template:
    - Description of changes
    - Related issues
    - Testing performed
    - Screenshots (if UI changes)

## Code Organization

```
argus/
├── app/
│   ├── main.py           # FastAPI application
│   ├── models.py         # SQLAlchemy models
│   ├── database.py       # Database connection
│   ├── scanner.py        # Nmap scanning logic
│   ├── auth.py           # Authentication
│   ├── audit.py          # Audit logging
│   ├── config.py         # Configuration management
│   ├── scheduler.py      # Scheduled scans
│   ├── version.py        # Version management
│   └── utils/
│       ├── change_detector.py
│       ├── threat_detector.py
│       ├── mac_vendor.py
│       └── device_icons.py
├── templates/            # Jinja2 HTML templates
├── static/               # Static assets
├── tests/                # Test suite
├── docs/                 # Documentation (MkDocs)
└── data/                 # SQLite database
```

## Adding New Features

### Adding an API Endpoint

1. Add the route in `app/main.py`
2. Add Pydantic models for request/response
3. Add tests in `tests/`
4. Update API documentation

### Adding a Template

1. Create the template in `templates/`
2. Extend `base.html`
3. Add the route in `app/main.py`
4. Update navigation if needed

### Adding a Database Model

1. Add the model in `app/models.py`
2. Create a migration (or reinitialize DB in dev)
3. Update related code
4. Add tests

## Testing

### Test Structure

```python
# tests/test_example.py
import pytest
from app.module import function_to_test

class TestFeature:
    def test_basic_functionality(self):
        result = function_to_test()
        assert result == expected

    def test_edge_case(self):
        with pytest.raises(ValueError):
            function_to_test(invalid_input)
```

### Writing Good Tests

- Test both success and failure cases
- Use descriptive test names
- Keep tests independent
- Mock external dependencies

## Documentation

### Updating Documentation

Documentation uses MkDocs with Material theme:

```bash
# Install MkDocs
pip install mkdocs-material mkdocs-minify-plugin

# Serve locally
mkdocs serve

# Build
mkdocs build
```

### Documentation Style

- Use clear, concise language
- Include code examples
- Add screenshots for UI features
- Keep the navigation organized

## Getting Help

- **Questions**: Open a GitHub Discussion
- **Bugs**: Open a GitHub Issue
- **Security**: Email privately (see SECURITY.md)

## Code of Conduct

Be respectful and constructive. We're all here to make Argus better!

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

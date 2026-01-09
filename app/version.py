"""Version management for Argus"""

import os
import subprocess
from functools import lru_cache
from datetime import datetime


# Default version for development
DEFAULT_VERSION = "dev"


@lru_cache(maxsize=1)
def get_version() -> str:
    """
    Get the application version.

    Priority:
    1. ARGUS_VERSION environment variable (set by Docker build)
    2. VERSION file in project root
    3. Git tag (for development)
    4. Default to "dev"
    """
    # Check environment variable first (set by Docker/CI)
    version = os.environ.get("ARGUS_VERSION")
    if version:
        return version.strip()

    # Check VERSION file
    version_file = os.path.join(os.path.dirname(__file__), "..", "VERSION")
    if os.path.exists(version_file):
        try:
            with open(version_file, "r") as f:
                version = f.read().strip()
                if version:
                    return version
        except Exception:
            pass

    # Try to get version from git
    try:
        # Get the latest tag
        result = subprocess.run(
            ["git", "describe", "--tags", "--always"],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=os.path.dirname(__file__)
        )
        if result.returncode == 0:
            git_version = result.stdout.strip()
            if git_version:
                return git_version
    except Exception:
        pass

    return DEFAULT_VERSION


@lru_cache(maxsize=1)
def get_build_info() -> dict:
    """
    Get detailed build information.

    Returns dict with:
    - version: The version string
    - build_date: When the build was created (if available)
    - commit: Git commit SHA (if available)
    - branch: Git branch (if available)
    """
    info = {
        "version": get_version(),
        "build_date": os.environ.get("ARGUS_BUILD_DATE"),
        "commit": os.environ.get("ARGUS_COMMIT"),
        "branch": os.environ.get("ARGUS_BRANCH"),
    }

    # Try to get git info for development builds
    if not info["commit"]:
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                capture_output=True,
                text=True,
                timeout=5,
                cwd=os.path.dirname(__file__)
            )
            if result.returncode == 0:
                info["commit"] = result.stdout.strip()
        except Exception:
            pass

    if not info["branch"]:
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True,
                text=True,
                timeout=5,
                cwd=os.path.dirname(__file__)
            )
            if result.returncode == 0:
                info["branch"] = result.stdout.strip()
        except Exception:
            pass

    if not info["build_date"]:
        info["build_date"] = datetime.utcnow().strftime("%Y-%m-%d")

    # Remove None values
    return {k: v for k, v in info.items() if v is not None}


# Module-level version string for easy import
__version__ = get_version()

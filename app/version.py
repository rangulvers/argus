"""Version management for Argus"""

import os
import subprocess
from functools import lru_cache
from datetime import datetime


# Default version for development
DEFAULT_VERSION = "dev"


def _read_version_file(filepath: str) -> dict:
    """Read version info from a .version file"""
    info = {}
    if os.path.exists(filepath):
        try:
            with open(filepath, "r") as f:
                for line in f:
                    if "=" in line:
                        key, value = line.strip().split("=", 1)
                        if value:
                            info[key] = value
        except Exception:
            pass
    return info


@lru_cache(maxsize=1)
def get_version() -> str:
    """
    Get the application version.

    Priority:
    1. ARGUS_VERSION environment variable (set by Docker/CI)
    2. .version file (generated during Docker build)
    3. VERSION file in project root
    4. Git tag (for local development)
    5. Default to "dev"
    """
    # Check environment variable first (set by Docker/CI)
    version = os.environ.get("ARGUS_VERSION")
    if version and version.strip():
        return version.strip()

    # Check .version file (generated during Docker build)
    version_file = os.path.join(os.path.dirname(__file__), "..", ".version")
    version_info = _read_version_file(version_file)
    if version_info.get("ARGUS_VERSION"):
        return version_info["ARGUS_VERSION"]

    # Check VERSION file in project root
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
    # Start with environment variables
    info = {
        "version": get_version(),
        "build_date": os.environ.get("ARGUS_BUILD_DATE"),
        "commit": os.environ.get("ARGUS_COMMIT"),
        "branch": os.environ.get("ARGUS_BRANCH"),
    }

    # Try to read from .version file (generated during Docker build)
    version_file = os.path.join(os.path.dirname(__file__), "..", ".version")
    file_info = _read_version_file(version_file)
    if not info["build_date"] and file_info.get("ARGUS_BUILD_DATE"):
        info["build_date"] = file_info["ARGUS_BUILD_DATE"]
    if not info["commit"] and file_info.get("ARGUS_COMMIT"):
        info["commit"] = file_info["ARGUS_COMMIT"]
    if not info["branch"] and file_info.get("ARGUS_BRANCH"):
        info["branch"] = file_info["ARGUS_BRANCH"]

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

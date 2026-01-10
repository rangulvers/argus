"""Update checker for Argus - checks GitHub releases for new versions"""

import logging
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from functools import lru_cache
import httpx

from app.version import get_version

logger = logging.getLogger(__name__)

# GitHub repository info
GITHUB_OWNER = "rangulvers"
GITHUB_REPO = "argus"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest"

# Cache duration
CACHE_DURATION = timedelta(hours=1)


class UpdateChecker:
    """Checks for updates from GitHub releases"""

    def __init__(self):
        self._last_check: Optional[datetime] = None
        self._cached_result: Optional[Dict[str, Any]] = None

    def _parse_version(self, version_str: str) -> tuple:
        """Parse version string into comparable tuple.

        Handles various formats:
        - v1.2.3 or 1.2.3 -> (1, 2, 3)
        - v0.0.4-18-g59de3fa (git describe) -> (0, 0, 4)
        - 2026.01.09-abc1234 (CalVer from CI) -> (0, 0, 0) treated as dev
        - dev -> (0, 0, 0)
        """
        import re

        # Remove 'v' prefix if present
        version_str = version_str.lstrip('v')

        # Handle plain dev
        if version_str == 'dev':
            return (0, 0, 0)

        # Detect CalVer format: YYYY.MM.DD-hash (year > 2000 in first position)
        calver_match = re.match(r'^(20\d{2})\.(\d{2})\.(\d{2})', version_str)
        if calver_match:
            # CalVer builds are dev builds - always show update available for releases
            return (0, 0, 0)

        # Try to extract semver pattern (handles v1.2.3-extra)
        # This captures the base version from git describe like "0.0.4-18-g59de3fa"
        semver_match = re.match(r'^(\d+)\.(\d+)\.(\d+)', version_str)
        if semver_match:
            return (int(semver_match.group(1)),
                    int(semver_match.group(2)),
                    int(semver_match.group(3)))

        # Other formats - treat as dev build
        return (0, 0, 0)

    def _is_newer_version(self, remote: str, local: str) -> bool:
        """Check if remote version is newer than local"""
        remote_parts = self._parse_version(remote)
        local_parts = self._parse_version(local)
        return remote_parts > local_parts

    async def check_for_updates(self, force: bool = False) -> Dict[str, Any]:
        """
        Check GitHub for new releases.

        Args:
            force: Force check even if cache is valid

        Returns:
            Dict with update information
        """
        current_version = get_version()

        # Return cached result if still valid
        if not force and self._cached_result and self._last_check:
            if datetime.utcnow() - self._last_check < CACHE_DURATION:
                return self._cached_result

        result = {
            "current_version": current_version,
            "latest_version": None,
            "update_available": False,
            "release_url": None,
            "release_notes": None,
            "published_at": None,
            "checked_at": datetime.utcnow().isoformat(),
            "error": None
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    GITHUB_API_URL,
                    headers={
                        "Accept": "application/vnd.github.v3+json",
                        "User-Agent": f"Argus/{current_version}"
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    latest_version = data.get("tag_name", "").lstrip('v')

                    result["latest_version"] = latest_version
                    result["release_url"] = data.get("html_url")
                    result["release_notes"] = data.get("body", "")[:500]  # Truncate notes
                    result["published_at"] = data.get("published_at")
                    result["update_available"] = self._is_newer_version(
                        latest_version, current_version
                    )

                    logger.info(
                        f"Update check complete. Current: {current_version}, "
                        f"Latest: {latest_version}, Update available: {result['update_available']}"
                    )

                elif response.status_code == 404:
                    result["error"] = "No releases found"
                    logger.warning("No GitHub releases found for Argus")

                elif response.status_code == 403:
                    result["error"] = "GitHub API rate limit exceeded"
                    logger.warning("GitHub API rate limit exceeded")

                else:
                    result["error"] = f"GitHub API error: {response.status_code}"
                    logger.error(f"GitHub API returned status {response.status_code}")

        except httpx.TimeoutException:
            result["error"] = "Request timed out"
            logger.error("Update check timed out")

        except httpx.RequestError as e:
            result["error"] = f"Network error: {str(e)}"
            logger.error(f"Update check network error: {e}")

        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
            logger.error(f"Update check error: {e}")

        # Cache the result
        self._cached_result = result
        self._last_check = datetime.utcnow()

        return result

    def get_cached_result(self) -> Optional[Dict[str, Any]]:
        """Get the cached update check result without making a request"""
        return self._cached_result


# Global instance
_update_checker: Optional[UpdateChecker] = None


def get_update_checker() -> UpdateChecker:
    """Get or create the global update checker instance"""
    global _update_checker
    if _update_checker is None:
        _update_checker = UpdateChecker()
    return _update_checker

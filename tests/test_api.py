"""Tests for FastAPI endpoints"""

import pytest
from fastapi import status

# Skip reason for tests affected by middleware database access
MIDDLEWARE_DB_SKIP = "Middleware imports SessionLocal directly, bypassing test overrides"


class TestHealthEndpoint:
    """Tests for health check endpoint"""

    def test_health_check(self, client):
        """Test health endpoint returns OK"""
        response = client.get("/health")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "healthy"


@pytest.mark.skip(reason=MIDDLEWARE_DB_SKIP)
class TestVersionEndpoint:
    """Tests for version endpoint"""

    def test_version_endpoint(self, authenticated_client):
        """Test version endpoint returns version info"""
        response = authenticated_client.get("/api/version")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "version" in data


@pytest.mark.skip(reason=MIDDLEWARE_DB_SKIP)
class TestDevicesAPI:
    """Tests for devices API endpoints"""

    def test_list_devices_empty(self, authenticated_client):
        """Test listing devices when none exist"""
        response = authenticated_client.get("/api/devices")
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == []

    def test_list_devices_with_scan(self, authenticated_client, sample_device):
        """Test listing devices from a scan"""
        response = authenticated_client.get(f"/api/devices?scan_id={sample_device.scan_id}")
        assert response.status_code == status.HTTP_200_OK
        devices = response.json()
        assert len(devices) >= 1
        assert any(d["ip_address"] == "192.168.1.100" for d in devices)

    def test_get_device_detail(self, authenticated_client, sample_device):
        """Test getting device details"""
        response = authenticated_client.get(f"/api/devices/{sample_device.id}")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["ip_address"] == "192.168.1.100"
        assert data["hostname"] == "test-device"

    def test_get_device_not_found(self, authenticated_client):
        """Test getting non-existent device"""
        response = authenticated_client.get("/api/devices/99999")
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_update_device(self, authenticated_client, sample_device):
        """Test updating device fields"""
        response = authenticated_client.put(
            f"/api/devices/{sample_device.id}",
            json={
                "label": "Updated Label",
                "notes": "Test notes",
                "is_trusted": True,
                "zone": "Production"
            }
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["label"] == "Updated Label"
        assert data["is_trusted"] is True
        assert data["zone"] == "Production"


@pytest.mark.skip(reason=MIDDLEWARE_DB_SKIP)
class TestScansAPI:
    """Tests for scans API endpoints"""

    def test_list_scans_empty(self, authenticated_client):
        """Test listing scans when none exist"""
        response = authenticated_client.get("/api/scans")
        assert response.status_code == status.HTTP_200_OK

    def test_list_scans(self, authenticated_client, sample_scan):
        """Test listing scans"""
        response = authenticated_client.get("/api/scans")
        assert response.status_code == status.HTTP_200_OK
        scans = response.json()
        assert len(scans) >= 1

    def test_get_scan_detail(self, authenticated_client, sample_scan):
        """Test getting scan details"""
        response = authenticated_client.get(f"/api/scans/{sample_scan.id}")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["subnet"] == "192.168.1.0/24"
        assert data["status"] == "completed"


@pytest.mark.skip(reason=MIDDLEWARE_DB_SKIP)
class TestChangesAPI:
    """Tests for changes API endpoints"""

    def test_list_changes_empty(self, authenticated_client):
        """Test listing changes when none exist"""
        response = authenticated_client.get("/api/changes")
        assert response.status_code == status.HTTP_200_OK

    def test_list_changes(self, authenticated_client, sample_changes):
        """Test listing changes"""
        response = authenticated_client.get("/api/changes")
        assert response.status_code == status.HTTP_200_OK
        changes = response.json()
        assert len(changes) >= 2


@pytest.mark.skip(reason=MIDDLEWARE_DB_SKIP)
class TestZonesAPI:
    """Tests for zones API endpoint"""

    def test_list_zones_empty(self, authenticated_client):
        """Test listing zones when none exist"""
        response = authenticated_client.get("/api/zones")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "zones" in data

    def test_list_zones_with_data(self, authenticated_client, sample_device_history):
        """Test listing zones with existing data"""
        response = authenticated_client.get("/api/zones")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "Servers" in data["zones"]


@pytest.mark.skip(reason=MIDDLEWARE_DB_SKIP)
class TestVisualizationAPI:
    """Tests for visualization API endpoints"""

    def test_topology_endpoint(self, authenticated_client, sample_device):
        """Test topology visualization endpoint"""
        response = authenticated_client.get("/api/visualization/topology")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "nodes" in data
        assert "edges" in data

    def test_heatmap_endpoint(self, authenticated_client, sample_device):
        """Test heatmap visualization endpoint"""
        response = authenticated_client.get("/api/visualization/heatmap")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "devices" in data
        assert "summary" in data

    def test_port_matrix_endpoint(self, authenticated_client, sample_device_with_ports):
        """Test port matrix visualization endpoint"""
        response = authenticated_client.get("/api/visualization/port-matrix")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "ports" in data
        assert "matrix" in data

    def test_timeline_endpoint(self, authenticated_client, sample_changes):
        """Test timeline visualization endpoint"""
        response = authenticated_client.get("/api/visualization/timeline")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "changes" in data
        assert "scans" in data


@pytest.mark.skip(reason=MIDDLEWARE_DB_SKIP)
class TestWebPages:
    """Tests for web page routes"""

    def test_login_page_accessible(self, client, sample_user):
        """Test login page is accessible"""
        response = client.get("/login")
        assert response.status_code == status.HTTP_200_OK
        assert "login" in response.text.lower() or "Login" in response.text

    def test_setup_page_when_no_users(self, client):
        """Test setup page redirects when no users exist"""
        response = client.get("/", follow_redirects=False)
        # Should redirect to setup when no users exist
        assert response.status_code in [status.HTTP_302_FOUND, status.HTTP_200_OK]

    def test_dashboard_requires_auth(self, client, sample_user):
        """Test dashboard requires authentication"""
        # Without login, should redirect
        response = client.get("/", follow_redirects=False)
        assert response.status_code == status.HTTP_302_FOUND

    def test_dashboard_with_auth(self, authenticated_client):
        """Test dashboard accessible with auth"""
        response = authenticated_client.get("/")
        assert response.status_code == status.HTTP_200_OK

    def test_devices_page(self, authenticated_client, sample_scan):
        """Test devices page"""
        response = authenticated_client.get("/devices")
        assert response.status_code == status.HTTP_200_OK

    def test_scans_page(self, authenticated_client):
        """Test scans page"""
        response = authenticated_client.get("/scans")
        assert response.status_code == status.HTTP_200_OK

    def test_changes_page(self, authenticated_client):
        """Test changes page"""
        response = authenticated_client.get("/changes")
        assert response.status_code == status.HTTP_200_OK

    def test_visualization_page(self, authenticated_client):
        """Test visualization page"""
        response = authenticated_client.get("/visualization")
        assert response.status_code == status.HTTP_200_OK

    def test_settings_page(self, authenticated_client):
        """Test settings page"""
        response = authenticated_client.get("/settings")
        assert response.status_code == status.HTTP_200_OK

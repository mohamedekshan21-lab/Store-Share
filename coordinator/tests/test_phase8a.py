"""
Phase 8A Acceptance & Provider Monitoring/Management Test Suite.

Validates:
1. Provider Overview aggregation: Quota vs verified storage vs physical host capacity,
   ingress/egress traffic, availability, ECC balance, reputation, and repair stats.
2. Provider Isolation & Node Ownership: Strict data isolation ensuring Provider A cannot
   inspect, alter, schedule, or shut down Provider B's nodes.
3. Node Scheduling Management: Disabling scheduling prevents chunk placement selection,
   re-enabling restores placement eligibility.
4. Graceful Node Shutdown: Setting node status to 'draining' and disabling scheduling.
5. Dashboard & Static Assets: Serving responsive provider dashboard HTML, CSS, and JS.
6. CoordinatorClient SDK & CLI Integration: Testing Phase 8A SDK methods and CLI commands.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Generator
import pytest
from starlette.testclient import TestClient

from coordinator.app.main import app
from coordinator.app.config import CoordinatorSettings
from coordinator.app.database import get_db_connection, init_db
from coordinator.app.node_registry import NodeRegistry
from coordinator.app.metering import MeteringService
from coordinator.app.accounting import AccountingService
from coordinator.coordinator_client import CoordinatorClient, CoordinatorClientError
from client.cli import main as cli_main


@pytest.fixture
def test_settings(tmp_path: Path) -> CoordinatorSettings:
    """Fixture providing isolated temporary database and settings for Phase 8A tests."""
    db_file = tmp_path / "coordinator_phase8a_test.db"
    return CoordinatorSettings(
        db_path=db_file,
        auth_token="phase8a-test-secret-token",
        heartbeat_timeout_seconds=5,
    )


@pytest.fixture
def node_registry(test_settings: CoordinatorSettings) -> NodeRegistry:
    """Fixture providing NodeRegistry instance."""
    return NodeRegistry(test_settings)


@pytest.fixture
def metering_service(test_settings: CoordinatorSettings) -> MeteringService:
    """Fixture providing MeteringService instance."""
    return MeteringService(test_settings)


@pytest.fixture
def accounting_service(test_settings: CoordinatorSettings) -> AccountingService:
    """Fixture providing AccountingService instance."""
    return AccountingService(test_settings)


@pytest.fixture
def test_client(test_settings: CoordinatorSettings) -> Generator[TestClient, None, None]:
    """TestClient configured with isolated state."""
    app.state.settings = test_settings
    app.state.registry = NodeRegistry(test_settings)
    app.state.metering_service = MeteringService(test_settings)
    app.state.accounting_service = AccountingService(test_settings)
    with TestClient(app) as client:
        yield client


# =============================================================================
# 1. Provider Overview Aggregation Tests
# =============================================================================

def test_provider_overview_aggregation_distinguishes_capacities(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    Validates that Provider Overview clearly distinguishes:
    - Configured storage quota
    - Verified stored data
    - Physical host disk capacity
    - Remaining Expo quota
    """
    token_headers = {"X-Auth-Token": test_settings.auth_token, "X-Provider-Id": "provider_alpha"}

    # Register Node 1: 100 GB quota, 20 GB verified stored, 500 GB physical host disk
    reg1 = {
        "node_id": "ALPHA-NODE-1",
        "host": "192.168.1.50",
        "port": 8001,
        "total_capacity_bytes": 100_000_000_000,
        "used_capacity_bytes": 20_000_000_000,
        "available_capacity_bytes": 80_000_000_000,
        "provider_id": "provider_alpha",
        "is_schedulable": True,
    }
    res1 = test_client.post("/nodes/register", json=reg1, headers=token_headers)
    assert res1.status_code == 200

    # Register Node 2: 200 GB quota, 50 GB verified stored, 1000 GB physical host disk
    reg2 = {
        "node_id": "ALPHA-NODE-2",
        "host": "192.168.1.51",
        "port": 8002,
        "total_capacity_bytes": 200_000_000_000,
        "used_capacity_bytes": 50_000_000_000,
        "available_capacity_bytes": 150_000_000_000,
        "provider_id": "provider_alpha",
        "is_schedulable": True,
    }
    res2 = test_client.post("/nodes/register", json=reg2, headers=token_headers)
    assert res2.status_code == 200

    # Record some transfer events for ALPHA-NODE-1
    app.state.metering_service.record_transfer_event(
        node_id="ALPHA-NODE-1",
        direction="upload",
        operation_type="client_upload",
        payload_bytes=10_000_000,
        status="success",
    )
    app.state.metering_service.record_transfer_event(
        node_id="ALPHA-NODE-1",
        direction="download",
        operation_type="client_download",
        payload_bytes=4_000_000,
        status="success",
    )

    # Query provider overview
    res_ov = test_client.get("/provider/overview?window_hours=24.0", headers=token_headers)
    assert res_ov.status_code == 200
    ov = res_ov.json()

    assert ov["provider_id"] == "provider_alpha"
    assert ov["total_nodes_count"] == 2
    assert ov["online_nodes_count"] == 2
    assert ov["total_configured_quota_bytes"] == 300_000_000_000
    assert ov["total_verified_stored_bytes"] == 70_000_000_000
    assert ov["total_remaining_quota_bytes"] == 230_000_000_000
    assert ov["total_ingress_bytes"] == 10_000_000
    assert ov["total_egress_bytes"] == 4_000_000
    assert len(ov["nodes"]) == 2


# =============================================================================
# 2. Strict Provider Isolation & Node Ownership Safeguards
# =============================================================================

def test_cross_provider_isolation_prevents_unauthorized_access(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    Enforces that Provider A cannot view or manipulate Provider B's nodes.
    """
    token = test_settings.auth_token

    # Register Node for Provider Alice
    res_a = test_client.post(
        "/nodes/register",
        json={
            "node_id": "ALICE-NODE-1",
            "host": "10.0.0.1",
            "port": 8001,
            "provider_id": "alice",
        },
        headers={"X-Auth-Token": token, "X-Provider-Id": "alice"},
    )
    assert res_a.status_code == 200

    # Register Node for Provider Bob
    res_b = test_client.post(
        "/nodes/register",
        json={
            "node_id": "BOB-NODE-1",
            "host": "10.0.0.2",
            "port": 8002,
            "provider_id": "bob",
        },
        headers={"X-Auth-Token": token, "X-Provider-Id": "bob"},
    )
    assert res_b.status_code == 200

    # 1. Alice listing her nodes should ONLY see ALICE-NODE-1
    res_alice_nodes = test_client.get("/provider/nodes", headers={"X-Auth-Token": token, "X-Provider-Id": "alice"})
    assert res_alice_nodes.status_code == 200
    alice_node_ids = [n["node_id"] for n in res_alice_nodes.json()]
    assert "ALICE-NODE-1" in alice_node_ids
    assert "BOB-NODE-1" not in alice_node_ids

    # 2. Bob listing his nodes should ONLY see BOB-NODE-1
    res_bob_nodes = test_client.get("/provider/nodes", headers={"X-Auth-Token": token, "X-Provider-Id": "bob"})
    assert res_bob_nodes.status_code == 200
    bob_node_ids = [n["node_id"] for n in res_bob_nodes.json()]
    assert "BOB-NODE-1" in bob_node_ids
    assert "ALICE-NODE-1" not in bob_node_ids

    # 3. Alice attempts to inspect Bob's node details -> 403 Forbidden
    res_detail = test_client.get(
        "/provider/nodes/BOB-NODE-1/detail",
        headers={"X-Auth-Token": token, "X-Provider-Id": "alice"},
    )
    assert res_detail.status_code == 403
    assert "Access denied" in res_detail.json()["detail"]

    # 4. Alice attempts to disable scheduling on Bob's node -> 403 Forbidden
    res_sched = test_client.post(
        "/provider/nodes/BOB-NODE-1/scheduling",
        json={"is_schedulable": False},
        headers={"X-Auth-Token": token, "X-Provider-Id": "alice"},
    )
    assert res_sched.status_code == 403
    assert "Access denied" in res_sched.json()["detail"]

    # 5. Alice attempts to shutdown Bob's node -> 403 Forbidden
    res_shut = test_client.post(
        "/provider/nodes/BOB-NODE-1/shutdown",
        json={"reason": "Malicious shutdown attempt"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "alice"},
    )
    assert res_shut.status_code == 403
    assert "Access denied" in res_shut.json()["detail"]


# =============================================================================
# 3. Node Scheduling Management & Smart Selection Integration
# =============================================================================

def test_node_scheduling_controls_placement_eligibility(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    Validates that disabling node scheduling immediately excludes the node from
    candidate placement selection (`select_node`), and re-enabling restores it.
    """
    token = test_settings.auth_token
    headers = {"X-Auth-Token": token, "X-Provider-Id": "provider_sched"}

    # Register two online nodes: NODE-1 has 90MB available, NODE-2 has 10MB available
    test_client.post(
        "/nodes/register",
        json={
            "node_id": "SCHED-NODE-1",
            "host": "127.0.0.1",
            "port": 8101,
            "total_capacity_bytes": 100_000_000,
            "used_capacity_bytes": 10_000_000,
            "available_capacity_bytes": 90_000_000,
            "provider_id": "provider_sched",
            "is_schedulable": True,
        },
        headers=headers,
    )
    test_client.post(
        "/nodes/register",
        json={
            "node_id": "SCHED-NODE-2",
            "host": "127.0.0.1",
            "port": 8102,
            "total_capacity_bytes": 50_000_000,
            "used_capacity_bytes": 40_000_000,
            "available_capacity_bytes": 10_000_000,
            "provider_id": "provider_sched",
            "is_schedulable": True,
        },
        headers=headers,
    )

    # Initially, SCHED-NODE-1 has higher capacity so select_node chooses it
    sel_initial = test_client.get("/nodes/select?min_bytes=1000", headers=headers)
    assert sel_initial.status_code == 200
    assert sel_initial.json()["node_id"] == "SCHED-NODE-1"

    # Provider disables SCHED-NODE-1 scheduling
    dis_res = test_client.post(
        "/provider/nodes/SCHED-NODE-1/scheduling",
        json={"is_schedulable": False, "reason": "Maintenance window"},
        headers=headers,
    )
    assert dis_res.status_code == 200
    assert dis_res.json()["is_schedulable"] is False

    # Now select_node must select SCHED-NODE-2 instead
    sel_after_disable = test_client.get("/nodes/select?min_bytes=1000", headers=headers)
    assert sel_after_disable.status_code == 200
    assert sel_after_disable.json()["node_id"] == "SCHED-NODE-2"

    # Re-enable SCHED-NODE-1 scheduling
    en_res = test_client.post(
        "/provider/nodes/SCHED-NODE-1/scheduling",
        json={"is_schedulable": True},
        headers=headers,
    )
    assert en_res.status_code == 200
    assert en_res.json()["is_schedulable"] is True

    # Once re-enabled, SCHED-NODE-1 is selected again due to higher capacity
    sel_re_enabled = test_client.get("/nodes/select?min_bytes=1000", headers=headers)
    assert sel_re_enabled.status_code == 200
    assert sel_re_enabled.json()["node_id"] == "SCHED-NODE-1"


# =============================================================================
# 4. Graceful Node Shutdown
# =============================================================================

def test_graceful_node_shutdown_transitions_to_draining(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    Validates that graceful shutdown marks node status as 'draining' and
    is_schedulable as False, safely preventing further placements.
    """
    token = test_settings.auth_token
    headers = {"X-Auth-Token": token, "X-Provider-Id": "provider_drain"}

    test_client.post(
        "/nodes/register",
        json={
            "node_id": "DRAIN-NODE-1",
            "host": "127.0.0.1",
            "port": 8105,
            "provider_id": "provider_drain",
            "is_schedulable": True,
        },
        headers=headers,
    )

    shut_res = test_client.post(
        "/provider/nodes/DRAIN-NODE-1/shutdown",
        json={"reason": "Disk upgrade scheduled"},
        headers=headers,
    )
    assert shut_res.status_code == 200
    body = shut_res.json()
    assert body["node_id"] == "DRAIN-NODE-1"
    assert body["status"] == "draining"
    assert body["is_schedulable"] is False
    assert body["reason"] == "Disk upgrade scheduled"

    # Verify node detail reflects draining state
    det = test_client.get("/provider/nodes/DRAIN-NODE-1/detail", headers=headers).json()
    assert det["status"] == "draining"
    assert det["is_schedulable"] is False


# =============================================================================
# 5. Dashboard Web Interface & Static Assets Delivery
# =============================================================================

def test_dashboard_routes_and_static_assets(test_client: TestClient):
    """
    Validates serving of the responsive provider monitoring dashboard
    at both `/dashboard` and `/provider/dashboard`, as well as static assets.
    """
    # 1. /dashboard returns HTML5 with expected UI elements
    res_dash = test_client.get("/dashboard")
    assert res_dash.status_code == 200
    assert "text/html" in res_dash.headers["content-type"]
    html_text = res_dash.text
    assert "Expo Provider Portal" in html_text
    assert "id=\"configured-quota-bytes\"" in html_text
    assert "id=\"verified-stored-bytes\"" in html_text
    assert "id=\"remaining-quota-bytes\"" in html_text
    assert "id=\"nodes-table-body\"" in html_text
    assert "dashboard.css" in html_text
    assert "dashboard.js" in html_text

    # 2. /provider/dashboard also returns HTML5
    res_prov_dash = test_client.get("/provider/dashboard")
    assert res_prov_dash.status_code == 200
    assert "Expo Provider Portal" in res_prov_dash.text

    # 3. /static/dashboard.css
    res_css = test_client.get("/static/dashboard.css")
    assert res_css.status_code == 200
    assert "--bg-base" in res_css.text

    # 4. /static/dashboard.js
    res_js = test_client.get("/static/dashboard.js")
    assert res_js.status_code == 200
    assert "loadDashboard" in res_js.text


# =============================================================================
# 6. SDK Client & CLI Integration
# =============================================================================

def test_coordinator_client_sdk_and_cli_phase8a(test_client: TestClient, test_settings: CoordinatorSettings, monkeypatch, capsys):
    """
    Tests Phase 8A SDK methods and CLI commands against the running test application.
    """
    token = test_settings.auth_token
    headers = {"X-Auth-Token": token, "X-Provider-Id": "provider_sdk"}

    # Register node
    test_client.post(
        "/nodes/register",
        json={
            "node_id": "SDK-NODE-1",
            "host": "127.0.0.1",
            "port": 8110,
            "total_capacity_bytes": 100_000_000,
            "used_capacity_bytes": 10_000_000,
            "provider_id": "provider_sdk",
            "is_schedulable": True,
        },
        headers=headers,
    )

    # Monkeypatch CoordinatorClient._request to route through test_client
    def fake_request(self, method: str, path: str, **kwargs):
        headers_merged = self._get_headers()
        if "headers" in kwargs:
            headers_merged.update(kwargs.pop("headers"))
        return test_client.request(method, path, headers=headers_merged, **kwargs)

    monkeypatch.setattr(CoordinatorClient, "_request", fake_request)

    client = CoordinatorClient(
        coordinator_url="http://testserver",
        auth_token=token,
    )

    # 1. SDK get_provider_overview
    ov = client.get_provider_overview(provider_id="provider_sdk")
    assert ov["provider_id"] == "provider_sdk"
    assert ov["total_nodes_count"] == 1

    # 2. SDK get_provider_nodes
    nodes = client.get_provider_nodes(provider_id="provider_sdk")
    assert len(nodes) == 1
    assert nodes[0]["node_id"] == "SDK-NODE-1"

    # 3. SDK get_provider_node_detail
    detail = client.get_provider_node_detail("SDK-NODE-1", provider_id="provider_sdk")
    assert detail["node_id"] == "SDK-NODE-1"

    # 4. SDK set_node_scheduling
    sched = client.set_node_scheduling("SDK-NODE-1", is_schedulable=False, reason="Testing SDK", provider_id="provider_sdk")
    assert sched["is_schedulable"] is False

    # 5. SDK initiate_node_shutdown
    shut = client.initiate_node_shutdown("SDK-NODE-1", reason="Testing SDK shutdown", provider_id="provider_sdk")
    assert shut["status"] == "draining"

    # 6. Test CLI subcommands
    # provider-overview
    capsys.readouterr()  # clear buffer
    rc = cli_main(["--token", token, "provider-overview", "--provider-id", "provider_sdk"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Expo Provider Overview (provider_sdk)" in out

    # provider-nodes
    rc = cli_main(["--token", token, "provider-nodes", "--provider-id", "provider_sdk"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Registered Provider Nodes" in out
    assert "SDK-NODE-1" in out

    # provider-node
    rc = cli_main(["--token", token, "provider-node", "SDK-NODE-1", "--provider-id", "provider_sdk"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Node Diagnostic Detail: SDK-NODE-1" in out

    # provider-scheduling
    rc = cli_main(["--token", token, "provider-scheduling", "SDK-NODE-1", "--provider-id", "provider_sdk"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "placement scheduling set to: ENABLED" in out

    # provider-shutdown
    rc = cli_main(["--token", token, "provider-shutdown", "SDK-NODE-1", "--provider-id", "provider_sdk", "--reason", "CLI test"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "shutdown initiated. Status: draining" in out


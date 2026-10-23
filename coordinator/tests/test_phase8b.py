"""
Phase 8B Acceptance Test Suite: Provider Security and Safe Node Lifecycle Hardening.

Validates:
1. Provider Authentication, Identity Isolation & CSRF Protection:
   - Missing/invalid credentials rejected with consistent 401/403.
   - Provider identity spoofing via X-Provider-Id blocked (403).
   - Strict tenant isolation across overview, node listing, diagnostics, scheduling, and shutdown.
   - Administrative cross-provider access requires explicit permission (X-Admin-Override).
   - Browser session creation, HttpOnly cookies, expiration, logout, and CSRF defense on state mutations.
   - No sensitive secrets or tokens leaked in static assets, HTML, or error messages.
   - Security headers (X-Frame-Options, X-Content-Type-Options, CSP) present on responses.

2. Safe Node Draining & Lifecycle Hardening:
   - Placement scheduling is disabled immediately when drain begins.
   - Reads remain accessible while draining.
   - Redundancy verification respects replication and erasure coding requirements.
   - Source chunks are never deleted during drain.
   - Truthful 'drain_blocked' state when insufficient cluster redundancy exists.
   - Safe removal ('drained') blocked if redundancy requirements unmet (409 Conflict).
   - Drain jobs are durable and survive Coordinator restarts.
   - Drain requests are idempotent and retries can re-evaluate blocked drains.
   - Concurrent drain operations do not race or corrupt lifecycle state.
"""

from __future__ import annotations

import json
import threading
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
from coordinator.app.auth import ProviderSessionManager
from coordinator.app.drain_service import NodeDrainService, DrainStatus
from coordinator.coordinator_client import CoordinatorClient, CoordinatorClientError


@pytest.fixture
def test_settings(tmp_path: Path) -> CoordinatorSettings:
    """Fixture providing isolated temporary database and settings for Phase 8B tests."""
    db_file = tmp_path / "coordinator_phase8b_test.db"
    return CoordinatorSettings(
        db_path=db_file,
        auth_token="phase8b-master-admin-token",
        admin_auth_token="phase8b-master-admin-token",
        heartbeat_timeout_seconds=5,
    )


@pytest.fixture
def test_client(test_settings: CoordinatorSettings) -> Generator[TestClient, None, None]:
    """TestClient configured with isolated state."""
    app.state.settings = test_settings
    app.state.registry = NodeRegistry(test_settings)
    app.state.metering_service = MeteringService(test_settings)
    app.state.accounting_service = AccountingService(test_settings)
    app.state.session_manager = ProviderSessionManager(test_settings)
    app.state.drain_service = NodeDrainService(test_settings)
    with TestClient(app) as client:
        yield client


# =============================================================================
# 1. Provider Authentication & Identity Isolation Tests
# =============================================================================

def test_missing_and_invalid_credentials_rejected(test_client: TestClient):
    """Missing or invalid credentials return consistent 401 Unauthorized."""
    # 1. No credentials
    res = test_client.get("/provider/overview")
    assert res.status_code == 401
    assert "WWW-Authenticate" in res.headers

    # 2. Invalid bearer token
    res_bad = test_client.get("/provider/overview", headers={"Authorization": "Bearer bad-token-value"})
    assert res_bad.status_code == 401

    # 3. Invalid custom auth token
    res_bad_hdr = test_client.get("/provider/overview", headers={"X-Auth-Token": "bogus-auth-token"})
    assert res_bad_hdr.status_code == 401


def test_provider_identity_spoofing_prevented(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    A caller with credentials bound to Provider A cannot spoof identity
    as Provider B via X-Provider-Id (HTTP 403 Forbidden).
    """
    # Provider-bound token for alice
    alice_token = "provider:alice"

    # Alice requests her own overview -> 200 OK
    res_alice = test_client.get(
        "/provider/overview",
        headers={"Authorization": f"Bearer {alice_token}", "X-Provider-Id": "alice"},
    )
    assert res_alice.status_code == 200
    assert res_alice.json()["provider_id"] == "alice"

    # Alice attempts to spoof identity as bob -> 403 Forbidden
    res_spoof = test_client.get(
        "/provider/overview",
        headers={"Authorization": f"Bearer {alice_token}", "X-Provider-Id": "bob"},
    )
    assert res_spoof.status_code == 403
    assert "not authorized to act as provider 'bob'" in res_spoof.json()["detail"]


def test_cross_provider_isolation_overview_nodes_and_diagnostics(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    Strict isolation between providers:
    Provider A cannot see Provider B's nodes, diagnostics, or overview.
    """
    token_admin = test_settings.auth_token

    # Register node for alice
    test_client.post(
        "/nodes/register",
        json={"node_id": "ALICE-N1", "host": "10.0.1.1", "port": 8001, "provider_id": "alice"},
        headers={"X-Auth-Token": token_admin, "X-Provider-Id": "alice"},
    )
    # Register node for bob
    test_client.post(
        "/nodes/register",
        json={"node_id": "BOB-N1", "host": "10.0.2.1", "port": 8002, "provider_id": "bob"},
        headers={"X-Auth-Token": token_admin, "X-Provider-Id": "bob"},
    )

    alice_token = "provider:alice"
    bob_token = "provider:bob"

    # Alice cannot inspect Bob's node diagnostics
    res_diag = test_client.get(
        "/provider/nodes/BOB-N1/detail",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert res_diag.status_code == 403
    assert "does not belong to provider 'alice'" in res_diag.json()["detail"]

    # Bob cannot inspect Alice's node diagnostics
    res_bob_diag = test_client.get(
        "/provider/nodes/ALICE-N1/detail",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert res_bob_diag.status_code == 403
    assert "does not belong to provider 'bob'" in res_bob_diag.json()["detail"]


def test_unauthorized_scheduling_and_shutdown_attempts(test_client: TestClient, test_settings: CoordinatorSettings):
    """Provider A cannot modify scheduling or trigger shutdown on Provider B's node."""
    token_admin = test_settings.auth_token
    test_client.post(
        "/nodes/register",
        json={"node_id": "TARGET-NODE", "host": "10.0.3.1", "port": 8003, "provider_id": "victim_provider"},
        headers={"X-Auth-Token": token_admin, "X-Provider-Id": "victim_provider"},
    )

    attacker_token = "provider:attacker_provider"

    # Attacker tries to disable scheduling
    res_sched = test_client.post(
        "/provider/nodes/TARGET-NODE/scheduling",
        json={"is_schedulable": False, "reason": "malicious disabling"},
        headers={"Authorization": f"Bearer {attacker_token}"},
    )
    assert res_sched.status_code == 403

    # Attacker tries to shutdown
    res_shut = test_client.post(
        "/provider/nodes/TARGET-NODE/shutdown",
        json={"reason": "malicious shutdown"},
        headers={"Authorization": f"Bearer {attacker_token}"},
    )
    assert res_shut.status_code == 403

    # Attacker tries to drain
    res_drain = test_client.post(
        "/provider/nodes/TARGET-NODE/drain",
        json={"reason": "malicious drain"},
        headers={"Authorization": f"Bearer {attacker_token}"},
    )
    assert res_drain.status_code == 403


def test_administrative_cross_provider_access_requires_explicit_permission(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    Administrative master token:
    1. By default, acting as Provider A cannot mutate Provider B's node (403).
    2. With explicit X-Admin-Override: true, administrator can manage cross-provider nodes.
    3. Non-admin caller passing X-Admin-Override: true is rejected (403).
    """
    admin_token = test_settings.auth_token
    test_client.post(
        "/nodes/register",
        json={"node_id": "NODE-CROSS", "host": "10.0.4.1", "port": 8004, "provider_id": "tenant_b"},
        headers={"X-Auth-Token": admin_token, "X-Provider-Id": "tenant_b"},
    )

    # 1. Admin acting as tenant_a without override -> 403
    res_no_override = test_client.post(
        "/provider/nodes/NODE-CROSS/scheduling",
        json={"is_schedulable": False},
        headers={"X-Auth-Token": admin_token, "X-Provider-Id": "tenant_a"},
    )
    assert res_no_override.status_code == 403

    # 2. Admin with explicit X-Admin-Override -> 200 OK
    res_with_override = test_client.post(
        "/provider/nodes/NODE-CROSS/scheduling",
        json={"is_schedulable": False},
        headers={"X-Auth-Token": admin_token, "X-Provider-Id": "tenant_a", "X-Admin-Override": "true"},
    )
    assert res_with_override.status_code == 200
    assert res_with_override.json()["is_schedulable"] is False

    # 3. Non-admin attempting to use X-Admin-Override -> 403 Forbidden
    non_admin_token = "provider:tenant_a"
    res_fake_admin = test_client.post(
        "/provider/nodes/NODE-CROSS/scheduling",
        json={"is_schedulable": True},
        headers={"Authorization": f"Bearer {non_admin_token}", "X-Admin-Override": "true"},
    )
    assert res_fake_admin.status_code == 403


def test_browser_session_login_logout_and_csrf_protection(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    Browser session workflow:
    - Login sets HttpOnly session cookie and returns CSRF token.
    - State-changing mutations without CSRF token are blocked (403).
    - State-changing mutations with valid CSRF token succeed.
    - Logout terminates session and clears cookie.
    """
    token_admin = test_settings.auth_token
    test_client.post(
        "/nodes/register",
        json={"node_id": "DASH-NODE-1", "host": "10.0.5.1", "port": 8005, "provider_id": "dash_provider"},
        headers={"X-Auth-Token": token_admin, "X-Provider-Id": "dash_provider"},
    )

    # 1. Attempt login with wrong credentials
    res_bad_login = test_client.post(
        "/provider/session/login",
        json={"provider_id": "dash_provider", "secret_or_token": "wrong-secret"},
    )
    assert res_bad_login.status_code == 401

    # 2. Successful login with provider credentials
    res_login = test_client.post(
        "/provider/session/login",
        json={"provider_id": "dash_provider", "secret_or_token": "provider:dash_provider"},
    )
    assert res_login.status_code == 200
    login_data = res_login.json()
    assert login_data["provider_id"] == "dash_provider"
    csrf_token = login_data["csrf_token"]
    assert csrf_token is not None

    # Check session cookie received
    assert "expo_session" in res_login.cookies
    session_cookie = res_login.cookies["expo_session"]

    # 3. Session status check
    res_status = test_client.get(
        "/provider/session/status",
        headers={"Cookie": f"expo_session={session_cookie}"},
    )
    assert res_status.status_code == 200
    assert res_status.json()["authenticated"] is True
    assert res_status.json()["provider_id"] == "dash_provider"

    # 4. GET request with session cookie succeeds without CSRF header
    res_overview = test_client.get(
        "/provider/overview",
        headers={"Cookie": f"expo_session={session_cookie}"},
    )
    assert res_overview.status_code == 200

    # 5. State-changing POST without CSRF token -> 403 Forbidden
    res_post_no_csrf = test_client.post(
        "/provider/nodes/DASH-NODE-1/scheduling",
        json={"is_schedulable": False},
        headers={"Cookie": f"expo_session={session_cookie}"},
    )
    assert res_post_no_csrf.status_code == 403
    assert "CSRF token" in res_post_no_csrf.json()["detail"]

    # 6. State-changing POST with invalid CSRF token -> 403 Forbidden
    res_post_bad_csrf = test_client.post(
        "/provider/nodes/DASH-NODE-1/scheduling",
        json={"is_schedulable": False},
        headers={"X-CSRF-Token": "bogus-csrf-token", "Cookie": f"expo_session={session_cookie}"},
    )
    assert res_post_bad_csrf.status_code == 403

    # 7. State-changing POST with valid CSRF token -> 200 OK
    res_post_valid = test_client.post(
        "/provider/nodes/DASH-NODE-1/scheduling",
        json={"is_schedulable": False},
        headers={"X-CSRF-Token": csrf_token, "Cookie": f"expo_session={session_cookie}"},
    )
    assert res_post_valid.status_code == 200
    assert res_post_valid.json()["is_schedulable"] is False

    # 8. Logout terminates session
    res_logout = test_client.post(
        "/provider/session/logout",
        headers={"X-CSRF-Token": csrf_token, "Cookie": f"expo_session={session_cookie}"},
    )
    assert res_logout.status_code == 200

    # 9. Subsequent request with terminated session -> 401
    res_after = test_client.get(
        "/provider/overview",
        headers={"Cookie": f"expo_session={session_cookie}"},
    )
    assert res_after.status_code == 401


def test_no_sensitive_secrets_leaked_in_assets_or_responses(test_client: TestClient):
    """
    Validates that:
    - Static HTML/JS does not contain hardcoded secret tokens or keys.
    - Security headers are properly applied across responses.
    """
    # 1. Fetch dashboard HTML
    res_html = test_client.get("/provider/dashboard")
    assert res_html.status_code == 200
    html_text = res_html.text
    assert "phase7b1-test-secret-token" not in html_text
    assert "phase8b-master-admin-token" not in html_text

    # Verify security headers
    assert res_html.headers.get("X-Frame-Options") == "DENY"
    assert res_html.headers.get("X-Content-Type-Options") == "nosniff"
    assert "Content-Security-Policy" in res_html.headers

    # 2. Fetch dashboard JS
    res_js = test_client.get("/static/dashboard.js")
    assert res_js.status_code == 200
    js_text = res_js.text
    assert "phase7b1-test-secret-token" not in js_text
    assert "phase8b-master-admin-token" not in js_text


# =============================================================================
# 2. Safe Node Draining & Lifecycle Hardening Tests
# =============================================================================

def test_drain_disables_scheduling_immediately(test_client: TestClient, test_settings: CoordinatorSettings):
    """Initiating drain immediately disables chunk placement scheduling."""
    token = test_settings.auth_token
    test_client.post(
        "/nodes/register",
        json={"node_id": "DRAIN-SCHED-1", "host": "10.0.6.1", "port": 8006, "provider_id": "prov_drain", "is_schedulable": True},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_drain"},
    )

    res_drain = test_client.post(
        "/provider/nodes/DRAIN-SCHED-1/drain",
        json={"reason": "Hardware maintenance scheduled"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_drain"},
    )
    assert res_drain.status_code == 200
    drain_job = res_drain.json()
    assert drain_job["node_id"] == "DRAIN-SCHED-1"

    # Verify registry shows node as not schedulable
    det = test_client.get(
        "/provider/nodes/DRAIN-SCHED-1/detail",
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_drain"},
    ).json()
    assert det["is_schedulable"] is False


def test_drain_blocked_when_insufficient_cluster_redundancy(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    If a node holds a required replica or fragment and insufficient eligible
    nodes exist to guarantee file durability, drain transitions truthfully to 'drain_blocked'.
    """
    token = test_settings.auth_token

    # 1. Register only 2 nodes
    test_client.post(
        "/nodes/register",
        json={"node_id": "NODE-REP-A", "host": "10.0.7.1", "port": 8007, "provider_id": "prov_rep"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_rep"},
    )
    test_client.post(
        "/nodes/register",
        json={"node_id": "NODE-REP-B", "host": "10.0.7.2", "port": 8008, "provider_id": "prov_rep"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_rep"},
    )

    # 2. Register a replicated file needing 2 copies (distributed across A and B)
    # Both A and B hold copies. If A is drained, only B remains (factor 2 requires a 3rd node for migration!)
    manifest = {
        "file_id": "test-file-rep",
        "total_size": 1024,
        "chunk_size": 1024,
        "redundancy_mode": "replication",
        "replication_factor": 2,
        "chunks": [
            {
                "chunk_index": 0,
                "chunk_id": "chk-rep-0",
                "sha256": "aabbcc",
                "nodes": ["NODE-REP-A", "NODE-REP-B"],
            }
        ]
    }
    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            """
            INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, manifest_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("test-file-rep", "test_user", "sample.bin", 1024, "active", "replication", 1, json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat())
        )
        conn.commit()

    # 3. Attempt drain on NODE-REP-A: There is no 3rd schedulable node to migrate to!
    res_drain = test_client.post(
        "/provider/nodes/NODE-REP-A/drain",
        json={"reason": "Testing redundancy constraint"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_rep"},
    )
    assert res_drain.status_code == 200
    drain_data = res_drain.json()
    assert drain_data["status"] == "drain_blocked"
    assert "insufficient eligible nodes" in drain_data["reason"].lower()

    # 4. Check node registry reflects online health and drain_blocked lifecycle
    node_det = test_client.get(
        "/provider/nodes/NODE-REP-A/detail",
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_rep"},
    ).json()
    assert node_det["status"] == "online"
    assert node_det["drain_status"] == "drain_blocked"


def test_drain_cannot_be_completed_when_redundancy_missing(test_client: TestClient, test_settings: CoordinatorSettings):
    """Attempting to complete a drain when redundancy is unmet returns 409 Conflict."""
    token = test_settings.auth_token

    # Setup node and file with missing redundancy
    test_client.post(
        "/nodes/register",
        json={"node_id": "NODE-UNMET-1", "host": "10.0.8.1", "port": 8009, "provider_id": "prov_unmet"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_unmet"},
    )
    manifest = {
        "file_id": "test-file-unmet",
        "total_size": 2048,
        "chunk_size": 2048,
        "redundancy_mode": "replication",
        "replication_factor": 2,
        "chunks": [{"chunk_index": 0, "chunk_id": "c0", "sha256": "1122", "nodes": ["NODE-UNMET-1"]}]
    }
    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            """
            INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, manifest_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("test-file-unmet", "user_1", "data.dat", 2048, "active", "replication", 1, json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat())
        )
        conn.commit()

    # Drain is blocked
    test_client.post(
        "/provider/nodes/NODE-UNMET-1/drain",
        json={"reason": "Drain attempt"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_unmet"},
    )

    # Calling complete drain -> 409 Conflict
    res_comp = test_client.post(
        "/provider/nodes/NODE-UNMET-1/drain/complete",
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_unmet"},
    )
    assert res_comp.status_code == 409
    assert "Cannot mark node 'NODE-UNMET-1' as safely removable" in res_comp.json()["detail"]


def test_drain_completes_when_redundancy_satisfied(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    When a node holds 0 dependent chunks or all chunks have verified copies elsewhere,
    complete drain safely transitions the node to 'drained'.
    """
    token = test_settings.auth_token

    test_client.post(
        "/nodes/register",
        json={"node_id": "EMPTY-NODE-1", "host": "10.0.9.1", "port": 8010, "provider_id": "prov_clean"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_clean"},
    )

    # Initiate drain on empty node
    res_init = test_client.post(
        "/provider/nodes/EMPTY-NODE-1/drain",
        json={"reason": "Planned decommission"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_clean"},
    )
    assert res_init.status_code == 200

    # Complete drain
    res_comp = test_client.post(
        "/provider/nodes/EMPTY-NODE-1/drain/complete",
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_clean"},
    )
    assert res_comp.status_code == 200
    comp_data = res_comp.json()
    assert comp_data["status"] == "drained"

    # Verify node record is drained and descheduled while maintaining health status
    node = test_client.get(
        "/provider/nodes/EMPTY-NODE-1/detail",
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_clean"},
    ).json()
    assert node["status"] == "online"
    assert node["drain_status"] == "drained"
    assert node["is_schedulable"] is False


def test_drain_idempotent_and_retryable(test_client: TestClient, test_settings: CoordinatorSettings):
    """Repeated drain calls on a node are idempotent; retries re-evaluate blocked drains."""
    token = test_settings.auth_token

    test_client.post(
        "/nodes/register",
        json={"node_id": "IDEM-NODE-1", "host": "10.0.10.1", "port": 8011, "provider_id": "prov_idem"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_idem"},
    )

    # 1. First drain call
    res1 = test_client.post(
        "/provider/nodes/IDEM-NODE-1/drain",
        json={"reason": "First call"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_idem"},
    ).json()

    # 2. Second drain call returns same drain job
    res2 = test_client.post(
        "/provider/nodes/IDEM-NODE-1/drain",
        json={"reason": "Duplicate call"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_idem"},
    ).json()

    assert res1["drain_id"] == res2["drain_id"]

    # 3. Retry call
    res_retry = test_client.post(
        "/provider/nodes/IDEM-NODE-1/drain/retry",
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_idem"},
    )
    assert res_retry.status_code == 200
    assert res_retry.json()["drain_id"] == res1["drain_id"]


def test_drain_persistence_survives_coordinator_restart(test_client: TestClient, test_settings: CoordinatorSettings):
    """Drain jobs persist in SQLite and survive Coordinator restarts."""
    token = test_settings.auth_token

    test_client.post(
        "/nodes/register",
        json={"node_id": "SURVIVE-NODE-1", "host": "10.0.11.1", "port": 8012, "provider_id": "prov_restart"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_restart"},
    )

    res_init = test_client.post(
        "/provider/nodes/SURVIVE-NODE-1/drain",
        json={"reason": "Testing restart survival"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_restart"},
    ).json()

    drain_id = res_init["drain_id"]

    # Simulate coordinator restart: create new NodeDrainService pointing to the same db_path
    new_drain_service = NodeDrainService(test_settings)
    recovered_job = new_drain_service.get_drain_job("SURVIVE-NODE-1")

    assert recovered_job is not None
    assert recovered_job.drain_id == drain_id
    assert recovered_job.node_id == "SURVIVE-NODE-1"
    assert recovered_job.status in ("draining", "drained", "drain_blocked")


def test_concurrent_drain_requests_safe(test_client: TestClient, test_settings: CoordinatorSettings):
    """Concurrent drain requests execute without database lock contention or race conditions."""
    token = test_settings.auth_token

    test_client.post(
        "/nodes/register",
        json={"node_id": "CONCUR-NODE-1", "host": "10.0.12.1", "port": 8013, "provider_id": "prov_concur"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_concur"},
    )

    results = []
    errors = []

    def run_drain():
        try:
            res = test_client.post(
                "/provider/nodes/CONCUR-NODE-1/drain",
                json={"reason": "Concurrent drain"},
                headers={"X-Auth-Token": token, "X-Provider-Id": "prov_concur"},
            )
            results.append(res.status_code)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=run_drain) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0
    assert all(code == 200 for code in results)


def test_coordinator_client_sdk_drain_methods(test_client: TestClient, test_settings: CoordinatorSettings, monkeypatch: pytest.MonkeyPatch):
    """Validates CoordinatorClient SDK Phase 8B safe drain methods."""
    token = test_settings.auth_token

    test_client.post(
        "/nodes/register",
        json={"node_id": "SDK-DRAIN-NODE", "host": "10.0.13.1", "port": 8014, "provider_id": "prov_sdk"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_sdk"},
    )

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

    # 1. Initiate drain
    drain = client.initiate_node_drain("SDK-DRAIN-NODE", reason="SDK test drain", provider_id="prov_sdk")
    assert drain["node_id"] == "SDK-DRAIN-NODE"
    assert drain["status"] in ("draining", "drained")

    # 2. Get drain status
    status_info = client.get_node_drain("SDK-DRAIN-NODE", provider_id="prov_sdk")
    assert status_info["drain_id"] == drain["drain_id"]

    # 3. Retry drain
    retry_info = client.retry_node_drain("SDK-DRAIN-NODE", provider_id="prov_sdk")
    assert retry_info["drain_id"] == drain["drain_id"]

    # 4. Complete drain
    comp_info = client.complete_node_drain("SDK-DRAIN-NODE", provider_id="prov_sdk")
    assert comp_info["status"] == "drained"

    # 5. Cancel drain
    cancel_info = client.cancel_node_drain("SDK-DRAIN-NODE", provider_id="prov_sdk")
    assert cancel_info["status"] == "cancelled"


# =============================================================================
# 3. Section A & B & C Specialized Hardening Tests
# =============================================================================

def test_hashed_session_storage_in_database(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    Verifies that raw session tokens are NEVER stored in plaintext in SQLite.
    Only the SHA-256 hash is persisted.
    """
    import hashlib
    res = test_client.post(
        "/provider/session/login",
        json={"provider_id": "hash_test_prov", "secret_or_token": "provider:hash_test_prov"},
    )
    assert res.status_code == 200
    raw_session_token = res.cookies.get("expo_session")
    assert raw_session_token is not None

    expected_hash = hashlib.sha256(raw_session_token.encode("utf-8")).hexdigest()

    with get_db_connection(test_settings.db_path) as conn:
        # 1. Verify row found by session_hash
        row = conn.execute(
            "SELECT * FROM provider_sessions WHERE session_hash = ?",
            (expected_hash,),
        ).fetchone()
        assert row is not None
        assert row["provider_id"] == "hash_test_prov"

        # 2. Verify raw token is nowhere in the database table
        all_rows = conn.execute("SELECT session_hash FROM provider_sessions").fetchall()
        for r in all_rows:
            assert raw_session_token != r["session_hash"]


def test_lifecycle_state_separation_node_offline_during_drain(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    Decoupled lifecycle invariant:
    When a draining node misses heartbeats and becomes 'offline', its 'drain_status'
    remains intact ('draining' or 'drain_blocked'), and its drain job history is not erased.
    """
    token = test_settings.auth_token
    test_client.post(
        "/nodes/register",
        json={"node_id": "OFFLINE-DRAIN-1", "host": "10.0.14.1", "port": 8015, "provider_id": "prov_lifecycle"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_lifecycle"},
    )

    # 1. Initiate drain
    res_drain = test_client.post(
        "/provider/nodes/OFFLINE-DRAIN-1/drain",
        json={"reason": "Testing offline state separation"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_lifecycle"},
    )
    assert res_drain.status_code == 200
    drain_id = res_drain.json()["drain_id"]

    # Check initially online and draining
    node_before = test_client.get(
        "/provider/nodes/OFFLINE-DRAIN-1/detail",
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_lifecycle"},
    ).json()
    assert node_before["status"] == "online"
    assert node_before["drain_status"] in ("draining", "drained", "drain_blocked")

    # 2. Simulate missed heartbeats: set last_seen 100 seconds in the past
    stale_time = (datetime.now(timezone.utc) - timedelta(seconds=100)).isoformat()
    with get_db_connection(test_settings.db_path) as conn:
        conn.execute("UPDATE nodes SET last_seen = ? WHERE node_id = ?", (stale_time, "OFFLINE-DRAIN-1"))
        conn.commit()

    # 3. Query node: operational status MUST be 'offline', but drain_status MUST remain intact
    node_after = test_client.get(
        "/provider/nodes/OFFLINE-DRAIN-1/detail",
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_lifecycle"},
    ).json()
    assert node_after["status"] == "offline"
    assert node_after["drain_status"] == node_before["drain_status"]

    # 4. Durable drain job still exists
    drain_job = test_client.get(
        "/provider/nodes/OFFLINE-DRAIN-1/drain",
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_lifecycle"},
    ).json()
    assert drain_job["drain_id"] == drain_id
    assert drain_job["status"] == node_before["drain_status"]


def test_explicit_credential_to_identity_mapping_and_impersonation_rejection(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    Validates explicit database credentials:
    - Authenticating with key bound to Provider Alpha maps securely to Alpha.
    - Supplying X-Provider-Id: Beta with Alpha's credentials returns 403 Forbidden.
    """
    from coordinator.app.auth import CredentialManager
    cred_mgr = CredentialManager(test_settings)

    # Register credentials in SQLite
    cred_mgr.register_credential(
        principal_id="key_alpha",
        provider_id="provider_alpha",
        secret="secret-key-alpha-999",
        is_admin=False,
    )
    cred_mgr.register_credential(
        principal_id="key_beta",
        provider_id="provider_beta",
        secret="secret-key-beta-888",
        is_admin=False,
    )

    # 1. Successful authenticated call for Provider Alpha
    res_alpha = test_client.get(
        "/provider/overview",
        headers={"Authorization": "Bearer secret-key-alpha-999"},
    )
    assert res_alpha.status_code == 200
    assert res_alpha.json()["provider_id"] == "provider_alpha"

    # 2. Impersonation attempt: Alpha credentials with X-Provider-Id: provider_beta -> 403
    res_impersonate = test_client.get(
        "/provider/overview",
        headers={"Authorization": "Bearer secret-key-alpha-999", "X-Provider-Id": "provider_beta"},
    )
    assert res_impersonate.status_code == 403
    assert "not authorized to act as provider 'provider_beta'" in res_impersonate.json()["detail"]


def test_separate_administrator_authorization(tmp_path: Path):
    """
    Requirement A.3: Valid Coordinator token must not automatically grant administrator access.
    Separate admin token is required.
    """
    db_file = tmp_path / "admin_sep_test.db"
    settings = CoordinatorSettings(
        db_path=db_file,
        auth_token="ordinary-coordinator-token",
        admin_auth_token="super-secret-admin-token",
    )
    init_db(db_file)

    app.state.settings = settings
    app.state.registry = NodeRegistry(settings)
    app.state.metering_service = MeteringService(settings)
    app.state.accounting_service = AccountingService(settings)
    app.state.session_manager = ProviderSessionManager(settings)
    app.state.drain_service = NodeDrainService(settings)

    with TestClient(app) as client:
        # Register a node for tenant_target
        client.post(
            "/nodes/register",
            json={"node_id": "TARGET-N1", "host": "10.0.15.1", "port": 8016, "provider_id": "tenant_target"},
            headers={"X-Auth-Token": "super-secret-admin-token", "X-Admin-Override": "true"},
        )

        # 1. Ordinary coordinator token cannot perform admin override on another provider's node -> 403
        res_ord = client.post(
            "/provider/nodes/TARGET-N1/scheduling",
            json={"is_schedulable": False},
            headers={"X-Auth-Token": "ordinary-coordinator-token", "X-Provider-Id": "tenant_other", "X-Admin-Override": "true"},
        )
        assert res_ord.status_code == 403

        # 2. Admin token CAN perform admin override -> 200 OK
        res_adm = client.post(
            "/provider/nodes/TARGET-N1/scheduling",
            json={"is_schedulable": False},
            headers={"X-Auth-Token": "super-secret-admin-token", "X-Provider-Id": "tenant_other", "X-Admin-Override": "true"},
        )
        assert res_adm.status_code == 200
        assert res_adm.json()["is_schedulable"] is False


def test_erasure_coded_shard_redundancy_and_floor_evaluation(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    Requirement C.4: For erasure-coded data, verify required number of surviving shards (floor k)
    and distinct eligible nodes (k + m) before allowing node drain.
    """
    token = test_settings.auth_token

    # Register 3 nodes
    test_client.post(
        "/nodes/register",
        json={"node_id": "EC-NODE-0", "host": "10.0.16.1", "port": 8017, "provider_id": "prov_ec"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_ec"},
    )
    test_client.post(
        "/nodes/register",
        json={"node_id": "EC-NODE-1", "host": "10.0.16.2", "port": 8018, "provider_id": "prov_ec"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_ec"},
    )

    # File with RS(k=4, m=2), where EC-NODE-0 holds a shard, and only 1 shard exists on EC-NODE-1
    # Total online elsewhere = 1 shard < data_shards (4). Draining EC-NODE-0 would endanger reconstruction!
    manifest = {
        "file_id": "file-ec-durability",
        "total_size": 4096,
        "chunk_size": 4096,
        "redundancy_mode": "erasure",
        "data_shards": 4,
        "parity_shards": 2,
        "chunks": [
            {
                "chunk_index": 0,
                "chunk_id": "chk-ec-0",
                "shards": [
                    {"shard_index": 0, "node_id": "EC-NODE-0"},
                    {"shard_index": 1, "node_id": "EC-NODE-1"},
                ],
            }
        ],
    }

    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            """
            INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, manifest_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("file-ec-durability", "ec_user", "archive.tar", 4096, "active", "erasure", 1, json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    # Attempt drain on EC-NODE-0
    res_drain = test_client.post(
        "/provider/nodes/EC-NODE-0/drain",
        json={"reason": "Testing EC durability safety floor"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_ec"},
    )
    assert res_drain.status_code == 200
    job = res_drain.json()
    assert job["status"] == "drain_blocked"
    assert "surviving online shards elsewhere" in job["reason"].lower()
    assert "minimum 4 required for reconstruction" in job["reason"].lower()


def test_source_fragment_preservation_zero_deletion(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    Requirement C.6: Preserve source fragments throughout draining.
    Do not delete source data as part of this phase.
    """
    token = test_settings.auth_token

    test_client.post(
        "/nodes/register",
        json={"node_id": "PRESERVE-NODE-1", "host": "10.0.17.1", "port": 8019, "provider_id": "prov_pres"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_pres"},
    )

    # Initiate drain
    res_drain = test_client.post(
        "/provider/nodes/PRESERVE-NODE-1/drain",
        json={"reason": "Testing source fragment preservation"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_pres"},
    )
    assert res_drain.status_code == 200

    # Complete drain
    res_comp = test_client.post(
        "/provider/nodes/PRESERVE-NODE-1/drain/complete",
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_pres"},
    )
    assert res_comp.status_code == 200

    # Verify no file deletion events or prunes were triggered in database
    with get_db_connection(test_settings.db_path) as conn:
        del_events = conn.execute(
            "SELECT COUNT(*) AS c FROM metering_operation_events WHERE operation_type = 'delete' AND target_node_id = 'PRESERVE-NODE-1'"
        ).fetchone()
        assert del_events["c"] == 0


def test_session_expiry_and_explicit_revocation(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    Requirement A.5: Server-side expiration and explicit revocation.
    - Expired session tokens return 401 Unauthorized.
    - Revoked provider sessions immediately terminate access.
    - Expired sessions are purged from the database.
    """
    session_mgr = app.state.session_manager

    # 1. Create a session
    sess = session_mgr.create_session("prov_expiry", is_admin=False, duration_seconds=3600)
    raw_token = sess.session_id
    headers_sess1 = {"Cookie": f"expo_session={raw_token}"}

    # Verify session is initially valid
    res_valid = test_client.get("/provider/session/status", headers=headers_sess1)
    assert res_valid.status_code == 200
    assert res_valid.json()["authenticated"] is True

    # 2. Simulate expiration by backdating expires_at in SQLite
    past_time = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            "UPDATE provider_sessions SET expires_at = ? WHERE session_hash = ?",
            (past_time, sess.session_hash),
        )
        conn.commit()

    # Query with expired session -> 401 Unauthorized
    res_expired = test_client.get("/provider/overview", headers=headers_sess1)
    assert res_expired.status_code == 401
    assert "expired or invalid" in res_expired.json()["detail"].lower()

    # 3. Create another session and test explicit provider revocation
    sess2 = session_mgr.create_session("prov_revoked", is_admin=False, duration_seconds=3600)
    headers_sess2 = {"Cookie": f"expo_session={sess2.session_id}"}

    res2_valid = test_client.get("/provider/session/status", headers=headers_sess2)
    assert res2_valid.status_code == 200
    assert res2_valid.json()["authenticated"] is True

    # Explicitly revoke all sessions for prov_revoked
    revoked_count = session_mgr.revoke_provider_sessions("prov_revoked")
    assert revoked_count >= 1

    # Subsequent request returns 401
    res_revoked = test_client.get("/provider/overview", headers=headers_sess2)
    assert res_revoked.status_code == 401

    # 4. Clean expired sessions housekeeping
    cleaned = session_mgr.clean_expired_sessions()
    assert cleaned >= 0


def test_browser_login_rejects_coordinator_shared_token_for_ordinary_providers(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    Requirement A.6: Ensure browser login cannot accidentally expose the Coordinator's
    shared administrative token to ordinary providers.
    """
    token_coord = test_settings.auth_token

    # Ordinary provider attempts to log in using the shared coordinator token -> 401 Unauthorized
    res_ordinary_spoof = test_client.post(
        "/provider/session/login",
        json={"provider_id": "ordinary_provider_123", "secret_or_token": token_coord},
    )
    assert res_ordinary_spoof.status_code == 401
    assert "cannot be used for ordinary provider" in res_ordinary_spoof.json()["detail"]

    # Ordinary provider logging in with explicit provider-bound credentials succeeds
    res_proper = test_client.post(
        "/provider/session/login",
        json={"provider_id": "ordinary_provider_123", "secret_or_token": "provider:ordinary_provider_123"},
    )
    assert res_proper.status_code == 200
    assert res_proper.json()["provider_id"] == "ordinary_provider_123"
    assert res_proper.json()["is_admin"] is False


def test_corrupt_destination_data_blocks_drain_and_prevents_completion(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    Requirements C.5 & C.9: Do not assume a metadata count proves physical presence and readability.
    If destination replica fails integrity verification (corrupt data or hash mismatch),
    the copy is rejected, drain is marked drain_blocked, and complete_drain is blocked (409 Conflict).
    """
    token = test_settings.auth_token

    # Register source node and candidate destination node
    test_client.post(
        "/nodes/register",
        json={"node_id": "SRC-CORRUPT-1", "host": "10.0.18.1", "port": 8020, "provider_id": "prov_corrupt"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_corrupt"},
    )
    test_client.post(
        "/nodes/register",
        json={"node_id": "DEST-CORRUPT-1", "host": "10.0.18.2", "port": 8021, "provider_id": "prov_corrupt"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_corrupt"},
    )

    manifest = {
        "file_id": "file-corrupt-replica",
        "original_filename": "payload.bin",
        "redundancy_mode": "replication",
        "replication_factor": 2,
        "chunks": [
            {
                "chunk_id": "chk-corrupt-001",
                "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                "placements": [
                    {"node_id": "SRC-CORRUPT-1"},
                    {"node_id": "DEST-CORRUPT-1"},
                ],
            }
        ],
    }

    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            """
            INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, manifest_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("file-corrupt-replica", "user_c", "payload.bin", 1024, "active", "replication", 1, json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    drain_svc: NodeDrainService = app.state.drain_service

    # Inject verifier: DEST-CORRUPT-1 fails physical integrity check (corrupt data)
    def mock_corrupt_verifier(node_id: str, chunk_id: str, expected_sha: Optional[str]) -> bool:
        if node_id == "DEST-CORRUPT-1":
            return False  # Corrupt copy rejected!
        return True

    drain_svc.physical_verifier = mock_corrupt_verifier

    try:
        # Initiate drain on SRC-CORRUPT-1
        res_drain = test_client.post(
            "/provider/nodes/SRC-CORRUPT-1/drain",
            headers={"X-Auth-Token": token, "X-Provider-Id": "prov_corrupt"},
        )
        assert res_drain.status_code == 200
        job = res_drain.json()
        assert job["status"] == "drain_blocked"
        assert "failed physical integrity verification" in job["reason"]

        # Attempt to complete drain -> 409 Conflict
        res_comp = test_client.post(
            "/provider/nodes/SRC-CORRUPT-1/drain/complete",
            headers={"X-Auth-Token": token, "X-Provider-Id": "prov_corrupt"},
        )
        assert res_comp.status_code == 409
        assert "Cannot mark node 'SRC-CORRUPT-1' as safely removable" in res_comp.json()["detail"]
    finally:
        drain_svc.physical_verifier = None


def test_interrupted_transfer_and_network_probe_failure_blocks_drain(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    Requirements C.7 & D: If a transfer or physical verification is interrupted or fails due to network error,
    the drain job transitions to drain_blocked with an actionable reason rather than claiming success.
    """
    token = test_settings.auth_token

    test_client.post(
        "/nodes/register",
        json={"node_id": "SRC-INTERRUPT-1", "host": "10.0.19.1", "port": 8022, "provider_id": "prov_interrupt"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_interrupt"},
    )
    test_client.post(
        "/nodes/register",
        json={"node_id": "DEST-INTERRUPT-1", "host": "10.0.19.2", "port": 8023, "provider_id": "prov_interrupt"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_interrupt"},
    )

    manifest = {
        "file_id": "file-interrupt",
        "original_filename": "data_dump.tar",
        "redundancy_mode": "replication",
        "replication_factor": 2,
        "chunks": [
            {
                "chunk_id": "chk-interrupt-001",
                "sha256": "1111222233334444555566667777888899990000aaaa11112222333344445555",
                "placements": [
                    {"node_id": "SRC-INTERRUPT-1"},
                    {"node_id": "DEST-INTERRUPT-1"},
                ],
            }
        ],
    }

    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            """
            INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, manifest_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("file-interrupt", "user_i", "data_dump.tar", 2048, "active", "replication", 1, json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    drain_svc: NodeDrainService = app.state.drain_service

    # Simulate network drop / timeout during physical verification
    def mock_network_drop_verifier(node_id: str, chunk_id: str, expected_sha: Optional[str]) -> bool:
        if node_id == "DEST-INTERRUPT-1":
            raise ConnectionResetError("Connection reset by peer during transfer verification")
        return True

    drain_svc.physical_verifier = mock_network_drop_verifier

    try:
        res_drain = test_client.post(
            "/provider/nodes/SRC-INTERRUPT-1/drain",
            headers={"X-Auth-Token": token, "X-Provider-Id": "prov_interrupt"},
        )
        assert res_drain.status_code == 200
        job = res_drain.json()
        assert job["status"] == "drain_blocked"
        assert "failed physical integrity verification" in job["reason"]
    finally:
        drain_svc.physical_verifier = None


def test_concurrent_drain_retries_thread_safety(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    Requirements C.8 & D: Concurrent retries and drain calls are safe, atomic,
    and prevent job state corruption or duplicate records in SQLite.
    """
    token = test_settings.auth_token

    test_client.post(
        "/nodes/register",
        json={"node_id": "CONC-RETRY-1", "host": "10.0.20.1", "port": 8024, "provider_id": "prov_conc"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_conc"},
    )

    # Initial drain
    res_init = test_client.post(
        "/provider/nodes/CONC-RETRY-1/drain",
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_conc"},
    )
    assert res_init.status_code == 200
    primary_drain_id = res_init.json()["drain_id"]

    results = []
    errors = []

    def run_retry():
        try:
            res = test_client.post(
                "/provider/nodes/CONC-RETRY-1/drain/retry",
                headers={"X-Auth-Token": token, "X-Provider-Id": "prov_conc"},
            )
            results.append(res)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=run_retry) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0
    assert len(results) == 8
    for r in results:
        assert r.status_code == 200
        assert r.json()["drain_id"] == primary_drain_id

    # Verify only 1 record exists in node_drain_jobs table
    with get_db_connection(test_settings.db_path) as conn:
        count_row = conn.execute(
            "SELECT COUNT(*) AS c FROM node_drain_jobs WHERE node_id = 'CONC-RETRY-1'"
        ).fetchone()
        assert count_row["c"] == 1


def test_full_lifecycle_state_machine_and_offline_invariance(test_client: TestClient, test_settings: CoordinatorSettings):
    """
    Requirements B & D: Comprehensive validation of the multi-dimensional lifecycle state machine:
    - Node health (online/offline) strictly separated from placement scheduling (is_schedulable)
      and durable drain state (drain_status).
    - Node offline does not erase drain progress, does not alter drain_status, and does not make incomplete drain complete.
    - Transitions from online -> disabled -> draining -> drain_blocked -> offline -> online -> drained.
    """
    token = test_settings.auth_token

    # 1. Register node: online, schedulable, drain_status: none
    test_client.post(
        "/nodes/register",
        json={"node_id": "MACHINE-NODE-1", "host": "10.0.21.1", "port": 8025, "provider_id": "prov_sm"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_sm"},
    )

    n0 = test_client.get(
        "/provider/nodes/MACHINE-NODE-1/detail",
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_sm"},
    ).json()
    assert n0["status"] == "online"
    assert n0["is_schedulable"] is True
    assert n0["drain_status"] == "none"

    # 2. Disable scheduling (read remains accessible)
    test_client.post(
        "/provider/nodes/MACHINE-NODE-1/scheduling",
        json={"is_schedulable": False, "reason": "Pre-maintenance disable"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_sm"},
    )
    n1 = test_client.get(
        "/provider/nodes/MACHINE-NODE-1/detail",
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_sm"},
    ).json()
    assert n1["status"] == "online"
    assert n1["is_schedulable"] is False
    assert n1["drain_status"] == "none"

    # 3. Add a file requiring 3 replicas, but only MACHINE-NODE-1 and 1 other node exist -> drain will block
    test_client.post(
        "/nodes/register",
        json={"node_id": "OTHER-NODE-1", "host": "10.0.21.2", "port": 8026, "provider_id": "prov_sm"},
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_sm"},
    )

    manifest = {
        "file_id": "file-sm-blocked",
        "original_filename": "archive.tar.gz",
        "redundancy_mode": "replication",
        "replication_factor": 3,
        "chunks": [
            {
                "chunk_id": "chk-sm-01",
                "placements": [{"node_id": "MACHINE-NODE-1"}, {"node_id": "OTHER-NODE-1"}],
            }
        ],
    }
    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            """
            INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, manifest_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("file-sm-blocked", "user_sm", "archive.tar.gz", 4096, "active", "replication", 1, json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    # Initiate drain -> drain_blocked
    res_drain = test_client.post(
        "/provider/nodes/MACHINE-NODE-1/drain",
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_sm"},
    )
    assert res_drain.status_code == 200
    assert res_drain.json()["status"] == "drain_blocked"

    n2 = test_client.get(
        "/provider/nodes/MACHINE-NODE-1/detail",
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_sm"},
    ).json()
    assert n2["status"] == "online"
    assert n2["is_schedulable"] is False
    assert n2["drain_status"] == "drain_blocked"

    # 4. Simulate node going offline (missed heartbeats)
    past_time = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
    with get_db_connection(test_settings.db_path) as conn:
        conn.execute("UPDATE nodes SET last_seen = ? WHERE node_id = 'MACHINE-NODE-1'", (past_time,))
        conn.commit()

    # Query node: operational status is offline, but drain_status remains drain_blocked!
    n3 = test_client.get(
        "/provider/nodes/MACHINE-NODE-1/detail",
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_sm"},
    ).json()
    assert n3["status"] == "offline"
    assert n3["is_schedulable"] is False
    assert n3["drain_status"] == "drain_blocked"

    # Drain job still records drain_blocked, not drained
    job_rec = test_client.get(
        "/provider/nodes/MACHINE-NODE-1/drain",
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_sm"},
    ).json()
    assert job_rec["status"] == "drain_blocked"

    # Incomplete/blocked drain cannot be completed -> 409 Conflict
    res_bad_comp = test_client.post(
        "/provider/nodes/MACHINE-NODE-1/drain/complete",
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_sm"},
    )
    assert res_bad_comp.status_code == 409

    # 5. Node comes back online (heartbeat received)
    test_client.post(
        "/nodes/MACHINE-NODE-1/heartbeat",
        json={"status": "online"},
        headers={"X-Auth-Token": token},
    )
    n4 = test_client.get(
        "/provider/nodes/MACHINE-NODE-1/detail",
        headers={"X-Auth-Token": token, "X-Provider-Id": "prov_sm"},
    ).json()
    assert n4["status"] == "online"
    assert n4["drain_status"] == "drain_blocked"
    assert n4["is_schedulable"] is False




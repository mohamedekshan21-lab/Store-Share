"""
Phase 10C: Provider Onboarding, Node Health Validation, Probation Lifecycle, and Reliability-Gated Placement Tests.

Automated verification covering:
1. Provider onboarding terms acceptance and capability activation.
2. Unauthenticated and unonboarded node registration rejection (fail-closed).
3. Provider spoofing prevention (isolated registrations and node operations).
4. Suspended provider node exclusion from registration and placement.
5. Newly registered node begins in non-serving state ('registered') and cannot be placed.
6. Heartbeat alone never promotes registered or probation nodes.
7. Storage node health validation engine end-to-end sandbox write/read/checksum/cleanup.
8. Failed validation transitions node to unhealthy and prevents placement.
9. Validation artifact cleanup failure detection (fail-visible).
10. Probation capacity cap enforcement during placement selection.
11. Probation observation duration, health check count, and reliability promotion to online.
12. Stale heartbeat marks node offline and excludes from placement.
13. Coordinator restart durability (preserving lifecycle states, scores, and probation metrics).
14. Deterministic reliability scoring algorithm and confidence metrics.
"""

from __future__ import annotations

import io
import json
import time
import uuid
import pytest
from pathlib import Path
from fastapi import status
from fastapi.testclient import TestClient

from coordinator.app.main import app, get_settings
from coordinator.app.config import CoordinatorSettings
from coordinator.app.database import init_db, get_db_connection
from coordinator.app.node_registry import NodeRegistry
from coordinator.app.node_validation import NodeValidator, compute_reliability_score
from coordinator.app.auth import AccountManager, hash_password
from coordinator.app.capability import issue_upload_capability, issue_download_capability, issue_delete_capability
from storage_node.app.config import Settings as StorageSettings
from storage_node.app.main import app as storage_app


@pytest.fixture
def p10c_env(tmp_path: Path):
    """Provides isolated test database and settings for Phase 10C tests."""
    db_file = tmp_path / "coordinator_phase10c_test.db"
    settings = CoordinatorSettings(
        db_path=db_file,
        auth_token="p10c-coord-token",
        admin_auth_token="p10c-admin-token",
        capability_secret="p10c-shared-capability-secret-key-32bytes!",
        environment="development",
        heartbeat_timeout_seconds=2,
        probation_min_duration_seconds=2,
        probation_min_health_checks=2,
        probation_max_bytes=10_000_000,
        disk_safety_buffer_bytes=1000,
        reliability_min_score=0.4,
    )
    init_db(settings.db_path)
    return settings


@pytest.fixture
def client(p10c_env: CoordinatorSettings):
    """Configures TestClient with overridden settings and clean app state."""
    app.state.settings = p10c_env
    app.dependency_overrides[get_settings] = lambda: p10c_env
    for attr in ("account_manager", "registry", "catalog", "session_manager", "credential_manager", "metering_service", "drain_service"):
        if hasattr(app.state, attr):
            try:
                delattr(app.state, attr)
            except Exception:
                pass

    app.state.registry = NodeRegistry(p10c_env)

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()
    for attr in ("settings", "account_manager", "registry", "catalog", "session_manager", "credential_manager", "metering_service", "drain_service"):
        if hasattr(app.state, attr):
            try:
                delattr(app.state, attr)
            except Exception:
                pass


@pytest.fixture
def storage_node_client(tmp_path: Path, p10c_env: CoordinatorSettings):
    """Provides a real Storage Node TestClient instance bound to the shared capability secret."""
    storage_root = tmp_path / "storage_sandbox_node"
    storage_root.mkdir(parents=True, exist_ok=True)
    st_settings = StorageSettings(
        node_id="NODE-VAL-TARGET-1",
        storage_root=storage_root,
        storage_quota_gb=1.0,
        capability_secret=p10c_env.capability_secret,
        auth_token="storage-internal-token",
        environment="development",
    )
    from storage_node.app.storage_manager import StorageManager
    from storage_node.app.main import get_manager, get_app_settings
    manager = StorageManager(st_settings)
    storage_app.dependency_overrides[get_manager] = lambda: manager
    storage_app.dependency_overrides[get_app_settings] = lambda: st_settings
    storage_app.state.settings = st_settings
    storage_app.state.storage_manager = manager
    with TestClient(storage_app) as sc:
        yield sc
    storage_app.dependency_overrides.clear()


def create_and_login_account(client: TestClient, email: str, password: str = "SecurePass123!") -> tuple[str, str]:
    """Helper to register an account and establish a session. Returns (account_id, session_token)."""
    reg_res = client.post("/auth/register", json={"email": email, "password": password})
    assert reg_res.status_code == 201
    account_id = reg_res.json()["account_id"]

    login_res = client.post("/auth/login", json={"email": email, "password": password})
    assert login_res.status_code == 200
    session_token = login_res.json()["token"]
    return account_id, session_token


# =============================================================================
# 1. Provider Onboarding & Terms Acceptance
# =============================================================================

def test_1_provider_onboarding_requires_terms_acceptance_and_active_account(client: TestClient, p10c_env: CoordinatorSettings):
    """Validates that onboarding requires explicit terms agreement, records consent, and activates provider status."""
    acc_id, token = create_and_login_account(client, "provider_onboard_1@expo.com")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Reject without accept_terms
    res_reject = client.post(
        "/provider/onboard",
        json={"accept_terms": False, "terms_version": "1.0"},
        headers=headers,
    )
    assert res_reject.status_code == 400
    assert "terms and conditions must be explicitly accepted" in res_reject.json()["detail"].lower()

    # 2. Accept terms successfully
    res_ok = client.post(
        "/provider/onboard",
        json={"accept_terms": True, "terms_version": "1.0"},
        headers=headers,
    )
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["is_verified"] is True
    assert data["status"] == "active"
    assert data["terms_version"] == "1.0"
    assert data["account_id"] == acc_id
    provider_id = data["provider_id"]

    # 3. Query onboarding status
    res_status = client.get("/provider/onboarding", headers=headers)
    assert res_status.status_code == 200
    st_data = res_status.json()
    assert st_data["provider_id"] == provider_id
    assert st_data["is_verified"] is True

    # 4. Verify account capabilities updated with 'provider'
    with get_db_connection(p10c_env.db_path) as conn:
        row = conn.execute("SELECT capabilities FROM accounts WHERE account_id = ?", (acc_id,)).fetchone()
        caps = json.loads(row["capabilities"])
        assert "provider" in caps


# =============================================================================
# 2. Unauthenticated and Unonboarded Registration Rejection
# =============================================================================

def test_2_unauthenticated_or_unonboarded_node_registration_fails_closed(client: TestClient, p10c_env: CoordinatorSettings):
    """Validates fail-closed security: unauthenticated requests and un-onboarded consumers cannot register nodes."""
    # 1. Consumer registers but does NOT onboard as a provider
    consumer_id, consumer_token = create_and_login_account(client, "pure_consumer@expo.com")
    consumer_headers = {"Authorization": f"Bearer {consumer_token}"}

    # Consumer attempting to register a node must be rejected
    res_unonboarded = client.post(
        "/nodes/register",
        json={"node_id": "NODE-CONSUMER-ILLEGAL", "host": "127.0.0.1", "port": 8080, "total_capacity_bytes": 100_000_000},
        headers=consumer_headers,
    )
    assert res_unonboarded.status_code == 403
    assert "provider onboarding" in res_unonboarded.json()["detail"].lower()

    # 2. Production fail-closed: missing authentication in production environment
    p10c_env.environment = "production"
    client.cookies.clear()
    res_anon_prod = client.post(
        "/nodes/register",
        json={"node_id": "NODE-ANON-PROD", "host": "127.0.0.1", "port": 8081, "total_capacity_bytes": 100_000_000},
    )
    assert res_anon_prod.status_code == 401
    p10c_env.environment = "development"


# =============================================================================
# 3. Provider Spoofing Prevention
# =============================================================================

def test_3_provider_spoofing_prevented_in_registration_and_node_operations(client: TestClient, p10c_env: CoordinatorSettings):
    """Validates that authenticated providers cannot spoof other provider identities or access other provider nodes."""
    # Onboard Alice
    alice_acc, alice_token = create_and_login_account(client, "alice_prov@expo.com")
    alice_headers = {"Authorization": f"Bearer {alice_token}"}
    onb_alice = client.post("/provider/onboard", json={"accept_terms": True}, headers=alice_headers).json()
    alice_prov_id = onb_alice["provider_id"]

    # Onboard Bob
    bob_acc, bob_token = create_and_login_account(client, "bob_prov@expo.com")
    bob_headers = {"Authorization": f"Bearer {bob_token}"}
    onb_bob = client.post("/provider/onboard", json={"accept_terms": True}, headers=bob_headers).json()
    bob_prov_id = onb_bob["provider_id"]

    # Alice attempts to register a node with Bob's provider_id -> 403 Forbidden
    res_spoof = client.post(
        "/nodes/register",
        json={
            "node_id": "NODE-ALICE-SPOOF",
            "host": "127.0.0.1",
            "port": 8082,
            "total_capacity_bytes": 100_000_000,
            "provider_id": bob_prov_id,
        },
        headers=alice_headers,
    )
    assert res_spoof.status_code == 403
    assert "cannot register node for another provider" in res_spoof.json()["detail"].lower()

    # Alice registers her legitimate node
    res_alice_node = client.post(
        "/nodes/register",
        json={
            "node_id": "NODE-ALICE-LEGIT",
            "host": "127.0.0.1",
            "port": 8083,
            "total_capacity_bytes": 100_000_000,
            "provider_id": alice_prov_id,
        },
        headers=alice_headers,
    )
    assert res_alice_node.status_code == 200

    # Bob attempts to trigger validation or view validation history for Alice's node -> 403 Forbidden
    res_bob_val = client.post("/provider/nodes/NODE-ALICE-LEGIT/validate", headers=bob_headers)
    assert res_bob_val.status_code == 403

    res_bob_hist = client.get("/provider/nodes/NODE-ALICE-LEGIT/validation", headers=bob_headers)
    assert res_bob_hist.status_code == 403

    res_bob_prob = client.get("/provider/nodes/NODE-ALICE-LEGIT/probation", headers=bob_headers)
    assert res_bob_prob.status_code == 403


# =============================================================================
# 4. Suspended Provider Account Rejection & Placement Exclusion
# =============================================================================

def test_4_suspended_provider_nodes_cannot_register_or_be_scheduled(client: TestClient, p10c_env: CoordinatorSettings):
    """Validates that suspended or disabled provider accounts cannot register nodes and their nodes cannot be placed."""
    charlie_acc, charlie_token = create_and_login_account(client, "charlie_susp@expo.com")
    charlie_headers = {"Authorization": f"Bearer {charlie_token}"}
    onb_res = client.post("/provider/onboard", json={"accept_terms": True}, headers=charlie_headers).json()
    charlie_prov_id = onb_res["provider_id"]

    # Charlie registers a node
    res_reg = client.post(
        "/nodes/register",
        json={
            "node_id": "NODE-CHARLIE-ACTIVE",
            "host": "127.0.0.1",
            "port": 8084,
            "total_capacity_bytes": 100_000_000,
            "lifecycle_state": "online",
            "status": "online",
        },
        headers=charlie_headers,
    )
    assert res_reg.status_code == 200

    # Suspend Charlie's account in database
    with get_db_connection(p10c_env.db_path) as conn:
        conn.execute("UPDATE accounts SET status = 'suspended' WHERE account_id = ?", (charlie_acc,))
        conn.commit()

    # Charlie tries to register another node -> 403 Forbidden
    res_blocked_reg = client.post(
        "/nodes/register",
        json={
            "node_id": "NODE-CHARLIE-BLOCKED",
            "host": "127.0.0.1",
            "port": 8085,
            "total_capacity_bytes": 100_000_000,
        },
        headers=charlie_headers,
    )
    assert res_blocked_reg.status_code in (401, 403)

    # Placement selection must exclude NODE-CHARLIE-ACTIVE because provider is suspended
    selected = app.state.registry.select_node(required_bytes=1000)
    assert selected is None or selected.node_id != "NODE-CHARLIE-ACTIVE"


# =============================================================================
# 5. Newly Registered Node Begins in 'registered' & Cannot Receive Placement
# =============================================================================

def test_5_newly_registered_node_begins_in_registered_and_not_placed(client: TestClient, p10c_env: CoordinatorSettings):
    """Validates that newly registered nodes begin in 'registered' and are non-serving until validated."""
    acc_id, token = create_and_login_account(client, "provider_dave@expo.com")
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/provider/onboard", json={"accept_terms": True}, headers=headers)

    res_reg = client.post(
        "/nodes/register",
        json={
            "node_id": "NODE-DAVE-FRESH",
            "host": "127.0.0.1",
            "port": 8086,
            "total_capacity_bytes": 50_000_000,
        },
        headers=headers,
    )
    assert res_reg.status_code == 200
    data = res_reg.json()
    assert data["lifecycle_state"] == "registered"
    assert data["status"] == "registered"

    # Placement selection cannot pick this node
    sel_res = client.get("/nodes/select?required_bytes=1000")
    # Should be 404 since no online nodes exist
    assert sel_res.status_code == 404


# =============================================================================
# 6. Raw Heartbeat Does Not Promote Node
# =============================================================================

def test_6_heartbeat_alone_does_not_promote_node(client: TestClient, p10c_env: CoordinatorSettings):
    """Validates that sending heartbeats updates last_seen but NEVER promotes an unvalidated node."""
    acc_id, token = create_and_login_account(client, "provider_frank@expo.com")
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/provider/onboard", json={"accept_terms": True}, headers=headers)

    client.post(
        "/nodes/register",
        json={
            "node_id": "NODE-FRANK-HEARTBEAT",
            "host": "127.0.0.1",
            "port": 8087,
            "total_capacity_bytes": 50_000_000,
        },
        headers=headers,
    )

    coord_headers = {"X-Auth-Token": p10c_env.auth_token}

    # Storage Node sends heartbeat claiming status='online'
    res_hb = client.post(
        "/nodes/NODE-FRANK-HEARTBEAT/heartbeat",
        json={"status": "online"},
        headers=coord_headers,
    )
    assert res_hb.status_code == 200
    data = res_hb.json()
    # Must remain in 'registered' non-serving state
    assert data["lifecycle_state"] == "registered"
    assert data["status"] == "registered"

    # Node remains excluded from placement
    sel_res = client.get("/nodes/select?required_bytes=1000")
    assert sel_res.status_code == 404


# =============================================================================
# 7. End-to-End Health Validation Engine & Probation Transition
# =============================================================================

def test_7_storage_node_validation_end_to_end_and_transition_to_probation(
    client: TestClient,
    storage_node_client: TestClient,
    p10c_env: CoordinatorSettings,
):
    """Validates execution of all 6 health checks against a storage node, transitioning it to probation."""
    acc_id, token = create_and_login_account(client, "provider_val@expo.com")
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/provider/onboard", json={"accept_terms": True}, headers=headers)

    node_id = "NODE-VAL-TARGET-1"
    client.post(
        "/nodes/register",
        json={
            "node_id": node_id,
            "host": "127.0.0.1",
            "port": 8088,
            "total_capacity_bytes": 50_000_000,
        },
        headers=headers,
    )

    validator = NodeValidator(p10c_env)
    val_result = validator.validate_node(node_id=node_id, custom_client=storage_node_client)

    assert val_result.overall_status == "success"
    assert len(val_result.checks) == 6
    check_names = {c.name for c in val_result.checks}
    assert check_names == {
        "identity_and_liveness",
        "disk_and_quota",
        "authorized_write",
        "authorized_read_and_checksum",
        "unauthorized_rejection",
        "artifact_cleanup",
    }
    for c in val_result.checks:
        assert c.passed is True, f"Check '{c.name}' failed: {c.message}"

    assert val_result.resulting_lifecycle_state == "probation"
    assert val_result.reliability_score > 0.0

    # Node in registry is now in 'probation' with status 'online'
    node = app.state.registry.get_node(node_id)
    assert node.lifecycle_state == "probation"
    assert node.status == "online"
    assert node.health_check_success_count == 1
    assert node.consecutive_failures == 0

    # Validation history is recorded in database
    hist_res = client.get(f"/provider/nodes/{node_id}/validation", headers=headers)
    assert hist_res.status_code == 200
    hist = hist_res.json()
    assert hist["count"] == 1
    assert hist["probation_status"]["lifecycle_state"] == "probation"


# =============================================================================
# 8. Failed Validation Transitions Node to Unhealthy
# =============================================================================

def test_8_failed_validation_marks_node_unhealthy(
    client: TestClient,
    storage_node_client: TestClient,
    p10c_env: CoordinatorSettings,
):
    """Validates that failure in disk or connectivity checks transitions node to unhealthy."""
    acc_id, token = create_and_login_account(client, "provider_fail@expo.com")
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/provider/onboard", json={"accept_terms": True}, headers=headers)

    node_id = "NODE-FAIL-TARGET-1"
    client.post(
        "/nodes/register",
        json={
            "node_id": node_id,
            "host": "127.0.0.1",
            "port": 8089,
            "total_capacity_bytes": 50_000_000,
        },
        headers=headers,
    )

    validator = NodeValidator(p10c_env)
    # Simulate disk failure
    val_result = validator.validate_node(
        node_id=node_id,
        simulate_disk_failure=True,
        custom_client=storage_node_client,
    )
    assert val_result.overall_status == "failed"
    assert val_result.resulting_lifecycle_state == "unhealthy"

    node = app.state.registry.get_node(node_id)
    assert node.lifecycle_state == "unhealthy"
    assert node.status == "unhealthy"
    assert node.is_schedulable is False

    # Node cannot be placed
    sel = app.state.registry.select_node(required_bytes=1000)
    assert sel is None or sel.node_id != node_id


# =============================================================================
# 9. Validation Cleanup Failure Detection
# =============================================================================

def test_9_validation_cleanup_failure_detection(
    client: TestClient,
    storage_node_client: TestClient,
    p10c_env: CoordinatorSettings,
):
    """Validates that failure to clean up validation test artifacts is visibly reported and prevents healthy status."""
    acc_id, token = create_and_login_account(client, "provider_clean@expo.com")
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/provider/onboard", json={"accept_terms": True}, headers=headers)

    node_id = "NODE-CLEAN-FAIL-1"
    client.post(
        "/nodes/register",
        json={
            "node_id": node_id,
            "host": "127.0.0.1",
            "port": 8090,
            "total_capacity_bytes": 50_000_000,
        },
        headers=headers,
    )

    validator = NodeValidator(p10c_env)
    val_result = validator.validate_node(
        node_id=node_id,
        simulate_cleanup_failure=True,
        custom_client=storage_node_client,
    )
    assert val_result.overall_status == "cleanup_failed"
    assert val_result.resulting_lifecycle_state == "unhealthy"
    assert "cleanup failed" in val_result.failure_reason.lower()

    node = app.state.registry.get_node(node_id)
    assert node.lifecycle_state == "unhealthy"
    assert node.last_health_check_status == "cleanup_failed"


# =============================================================================
# 10. Probation Capacity Limits Enforced During Placement
# =============================================================================

def test_10_probation_capacity_limits_enforced(client: TestClient, p10c_env: CoordinatorSettings):
    """Validates that probation nodes cannot receive chunk allocations exceeding probation_max_bytes."""
    p10c_env.probation_max_bytes = 10_000_000  # 10 MB limit
    p10c_env.disk_safety_buffer_bytes = 0

    acc_id, token = create_and_login_account(client, "provider_cap@expo.com")
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/provider/onboard", json={"accept_terms": True}, headers=headers)

    # Register node directly into probation
    node_id = "NODE-PROB-CAP-1"
    client.post(
        "/nodes/register",
        json={
            "node_id": node_id,
            "host": "127.0.0.1",
            "port": 8091,
            "total_capacity_bytes": 100_000_000,
            "lifecycle_state": "probation",
            "status": "online",
        },
        headers=headers,
    )

    # Current placed bytes = 8 MB
    app.state.registry.record_probation_placement(node_id, placed_bytes=8_000_000)

    # Allocation of 1 MB (total 9 MB <= 10 MB) -> allowed
    selected = app.state.registry.select_node(required_bytes=1_000_000)
    assert selected is not None
    assert selected.node_id == node_id

    # Place the 1 MB (total placed = 9 MB)
    app.state.registry.record_probation_placement(node_id, placed_bytes=1_000_000)

    # Allocation of 2 MB (9 MB + 2 MB = 11 MB > 10 MB limit) -> rejected!
    selected_over = app.state.registry.select_node(required_bytes=2_000_000)
    assert selected_over is None


# =============================================================================
# 11. Probation Progression & Promotion to Online
# =============================================================================

def test_11_probation_progression_window_and_promotion_to_online(
    client: TestClient,
    storage_node_client: TestClient,
    p10c_env: CoordinatorSettings,
):
    """Validates that a node is promoted from probation to online only after satisfying duration, check count, and reliability."""
    p10c_env.probation_min_duration_seconds = 2
    p10c_env.probation_min_health_checks = 2
    p10c_env.reliability_min_score = 0.4

    acc_id, token = create_and_login_account(client, "provider_prom@expo.com")
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/provider/onboard", json={"accept_terms": True}, headers=headers)

    node_id = "NODE-VAL-TARGET-1"  # Matches storage_node_client node_id
    client.post(
        "/nodes/register",
        json={
            "node_id": node_id,
            "host": "127.0.0.1",
            "port": 8092,
            "total_capacity_bytes": 100_000_000,
        },
        headers=headers,
    )

    validator = NodeValidator(p10c_env)

    # Check 1: Transitions from registered to probation
    r1 = validator.validate_node(node_id=node_id, custom_client=storage_node_client)
    assert r1.resulting_lifecycle_state == "probation"
    node = app.state.registry.get_node(node_id)
    assert node.lifecycle_state == "probation"
    assert node.health_check_success_count == 1
    assert node.promoted_at is None

    # Wait for the probation observation duration (2 seconds)
    time.sleep(2.1)

    # Check 2: 2nd check with >= 2s duration elapsed satisfies all promotion criteria -> promoted to 'online'!
    r2 = validator.validate_node(node_id=node_id, custom_client=storage_node_client)
    assert r2.resulting_lifecycle_state == "online"

    node_promoted = app.state.registry.get_node(node_id)
    assert node_promoted.lifecycle_state == "online"
    assert node_promoted.promoted_at is not None
    assert node_promoted.health_check_success_count == 2
    assert node_promoted.reliability_score >= 0.4


# =============================================================================
# 12. Stale Heartbeat Offline Detection & Placement Exclusion
# =============================================================================

def test_12_stale_heartbeat_marks_node_offline_and_blocks_placement(client: TestClient, p10c_env: CoordinatorSettings):
    """Validates that a node whose heartbeat has expired is evaluated as offline and excluded from placement."""
    p10c_env.heartbeat_timeout_seconds = 1
    p10c_env.disk_safety_buffer_bytes = 0

    acc_id, token = create_and_login_account(client, "provider_stale@expo.com")
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/provider/onboard", json={"accept_terms": True}, headers=headers)

    node_id = "NODE-STALE-TARGET-1"
    client.post(
        "/nodes/register",
        json={
            "node_id": node_id,
            "host": "127.0.0.1",
            "port": 8093,
            "total_capacity_bytes": 100_000_000,
            "lifecycle_state": "online",
            "status": "online",
        },
        headers=headers,
    )

    # Node is online initially
    sel1 = app.state.registry.select_node(required_bytes=1000)
    assert sel1 is not None and sel1.node_id == node_id

    # Wait for timeout to expire
    time.sleep(1.2)

    # Status evaluated as offline
    node_rec = app.state.registry.get_node(node_id)
    assert node_rec.status == "offline"

    # Excluded from placement
    sel2 = app.state.registry.select_node(required_bytes=1000)
    assert sel2 is None


# =============================================================================
# 13. Coordinator Restart Preserves Lifecycle and Metrics
# =============================================================================

def test_13_coordinator_restart_preserves_probation_and_reliability(client: TestClient, p10c_env: CoordinatorSettings):
    """Validates that Coordinator restarts preserve all Phase 10C durable lifecycle states, scores, and metrics."""
    acc_id, token = create_and_login_account(client, "provider_restart@expo.com")
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/provider/onboard", json={"accept_terms": True}, headers=headers)

    node_id = "NODE-RESTART-PERSIST-1"
    client.post(
        "/nodes/register",
        json={
            "node_id": node_id,
            "host": "127.0.0.1",
            "port": 8094,
            "total_capacity_bytes": 100_000_000,
            "lifecycle_state": "probation",
            "status": "online",
        },
        headers=headers,
    )

    app.state.registry.record_probation_placement(node_id, placed_bytes=3_500_000)
    with get_db_connection(p10c_env.db_path) as conn:
        conn.execute(
            """
            UPDATE nodes
            SET health_check_success_count = 5,
                health_check_fail_count = 1,
                consecutive_failures = 0,
                reliability_score = 0.88,
                probation_started_at = '2026-10-15T12:00:00+00:00'
            WHERE node_id = ?
            """,
            (node_id,),
        )
        conn.commit()

    # Simulate restart by instantiating a completely fresh NodeRegistry instance
    fresh_registry = NodeRegistry(p10c_env)
    recovered_node = fresh_registry.get_node(node_id)

    assert recovered_node is not None
    assert recovered_node.lifecycle_state == "probation"
    assert recovered_node.probation_placed_bytes == 3_500_000
    assert recovered_node.health_check_success_count == 5
    assert recovered_node.health_check_fail_count == 1
    assert recovered_node.reliability_score == 0.88
    assert recovered_node.probation_started_at == "2026-10-15T12:00:00+00:00"


# =============================================================================
# 14. Deterministic Reliability Scoring Algorithm
# =============================================================================

def test_14_reliability_scoring_algorithm_edge_cases():
    """Validates the reliability scoring function across varied check distributions and confidence tiers."""
    # 0 checks -> insufficient data
    score, conf, suff = compute_reliability_score(0, 0, 0, None)
    assert score == 0.0
    assert conf == 0.0
    assert suff == "insufficient_data"

    # Perfect checks with fresh heartbeat
    import datetime
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    score_p, conf_p, suff_p = compute_reliability_score(
        success_count=5,
        fail_count=0,
        consecutive_failures=0,
        last_seen_iso=now_iso,
        heartbeat_timeout_seconds=30,
    )
    assert score_p >= 0.95
    assert conf_p == 1.0
    assert suff_p == "sufficient"

    # Failure penalty
    score_f, _, _ = compute_reliability_score(
        success_count=3,
        fail_count=3,
        consecutive_failures=3,
        last_seen_iso=now_iso,
        heartbeat_timeout_seconds=30,
    )
    assert score_f < score_p


# =============================================================================
# 15. Repeated and Concurrent Onboarding Idempotency
# =============================================================================

def test_15_repeated_and_concurrent_onboarding_idempotency(client: TestClient, p10c_env: CoordinatorSettings):
    """Validates that repeated and concurrent onboarding requests are safely idempotent."""
    acc_id, token = create_and_login_account(client, "idempotent_prov@expo.com")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Repeated onboarding calls with same or updated terms version
    r1 = client.post("/provider/onboard", json={"accept_terms": True, "terms_version": "1.0"}, headers=headers)
    assert r1.status_code == 200
    prov_id = r1.json()["provider_id"]

    r2 = client.post("/provider/onboard", json={"accept_terms": True, "terms_version": "1.1"}, headers=headers)
    assert r2.status_code == 200
    data2 = r2.json()
    assert data2["provider_id"] == prov_id
    assert data2["terms_version"] == "1.1"

    # 2. Concurrent onboarding requests
    from concurrent.futures import ThreadPoolExecutor
    def do_onboard(v):
        return client.post("/provider/onboard", json={"accept_terms": True, "terms_version": f"2.{v}"}, headers=headers).status_code

    with ThreadPoolExecutor(max_workers=3) as ex:
        results = list(ex.map(do_onboard, [1, 2, 3]))

    assert all(code == 200 for code in results)

    # Status check confirms active and single verified record
    res_st = client.get("/provider/onboarding", headers=headers)
    assert res_st.status_code == 200
    assert res_st.json()["is_verified"] is True


# =============================================================================
# 16. Validation Failure and Subsequent Recovery
# =============================================================================

def test_16_validation_failure_and_subsequent_recovery(
    client: TestClient,
    storage_node_client: TestClient,
    p10c_env: CoordinatorSettings,
):
    """Validates that a node that fails validation transitions to unhealthy, and subsequent successful validation recovers it to probation."""
    acc_id, token = create_and_login_account(client, "recovery_prov@expo.com")
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/provider/onboard", json={"accept_terms": True}, headers=headers)

    node_id = "NODE-VAL-TARGET-1"
    client.post(
        "/nodes/register",
        json={"node_id": node_id, "host": "127.0.0.1", "port": 8095, "total_capacity_bytes": 100_000_000},
        headers=headers,
    )

    validator = NodeValidator(p10c_env)

    # Step 1: Simulate disk failure during validation
    val1 = validator.validate_node(node_id=node_id, simulate_disk_failure=True, custom_client=storage_node_client)
    assert val1.overall_status == "failed"
    assert val1.resulting_lifecycle_state == "unhealthy"

    node1 = app.state.registry.get_node(node_id)
    assert node1.lifecycle_state == "unhealthy"
    assert node1.is_schedulable is False

    # Placement must exclude unhealthy node
    assert app.state.registry.select_node(required_bytes=1000) is None

    # Step 2: Node resolves issue and re-validates successfully -> recovers to probation
    val2 = validator.validate_node(node_id=node_id, custom_client=storage_node_client)
    assert val2.overall_status == "success"
    assert val2.resulting_lifecycle_state == "probation"

    node2 = app.state.registry.get_node(node_id)
    assert node2.lifecycle_state == "probation"
    assert node2.is_schedulable is True
    assert node2.status == "online"

    # Now eligible for placement within probation limits
    sel = app.state.registry.select_node(required_bytes=1000)
    assert sel is not None and sel.node_id == node_id


# =============================================================================
# 17. Placement Excludes All Ineligible Node States
# =============================================================================

def test_17_placement_comprehensive_exclusion_ineligible_nodes(client: TestClient, p10c_env: CoordinatorSettings):
    """Validates that node placement strictly excludes offline, unhealthy, unvalidated, disabled, and draining nodes."""
    acc_id, token = create_and_login_account(client, "filter_prov@expo.com")
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/provider/onboard", json={"accept_terms": True}, headers=headers)

    # Register 5 test nodes in various ineligible states
    ineligible_configs = [
        ("NODE-INELIG-1", "registered", "registered", True, "none"),   # unvalidated
        ("NODE-INELIG-2", "unhealthy", "unhealthy", False, "none"),    # unhealthy
        ("NODE-INELIG-3", "online", "online", False, "none"),          # disabled scheduling
        ("NODE-INELIG-4", "online", "online", True, "draining"),       # currently draining
        ("NODE-INELIG-5", "online", "offline", True, "none"),          # offline
    ]

    for nid, l_state, st, sched, drain in ineligible_configs:
        client.post(
            "/nodes/register",
            json={
                "node_id": nid,
                "host": "127.0.0.1",
                "port": 9000,
                "total_capacity_bytes": 100_000_000,
                "lifecycle_state": l_state,
                "status": st,
            },
            headers=headers,
        )
        with get_db_connection(p10c_env.db_path) as conn:
            conn.execute(
                "UPDATE nodes SET lifecycle_state = ?, status = ?, is_schedulable = ?, drain_status = ? WHERE node_id = ?",
                (l_state, st, 1 if sched else 0, drain, nid)
            )
            conn.commit()

    # None of the 5 nodes can be placed
    for _ in range(5):
        selected = app.state.registry.select_node(required_bytes=1000)
        assert selected is None, f"Expected no eligible node, but got: {selected.node_id if selected else None}"


# =============================================================================
# 18. Cross-Provider State Mutation and Identity Claim Prevention
# =============================================================================

def test_18_cross_provider_state_mutation_rejection(client: TestClient, p10c_env: CoordinatorSettings):
    """Validates that a provider cannot modify scheduling, drain, or validation state of another provider's node."""
    # Provider Alpha
    _, alpha_token = create_and_login_account(client, "alpha_prov@expo.com")
    alpha_headers = {"Authorization": f"Bearer {alpha_token}"}
    client.post("/provider/onboard", json={"accept_terms": True}, headers=alpha_headers)

    # Provider Beta
    _, beta_token = create_and_login_account(client, "beta_prov@expo.com")
    beta_headers = {"Authorization": f"Bearer {beta_token}"}
    client.post("/provider/onboard", json={"accept_terms": True}, headers=beta_headers)

    # Alpha registers Node Alpha
    alpha_node = "NODE-ALPHA-EXCLUSIVE"
    r_reg = client.post(
        "/nodes/register",
        json={"node_id": alpha_node, "host": "127.0.0.1", "port": 8096, "total_capacity_bytes": 100_000_000},
        headers=alpha_headers,
    )
    assert r_reg.status_code == 200

    # Beta attempts to disable Alpha's scheduling -> 403 Forbidden
    r_sched = client.post(f"/provider/nodes/{alpha_node}/scheduling", json={"is_schedulable": False}, headers=beta_headers)
    assert r_sched.status_code == 403

    # Beta attempts to initiate drain on Alpha's node -> 403 Forbidden
    r_drain = client.post(f"/provider/nodes/{alpha_node}/drain", json={"reason": "malicious drain"}, headers=beta_headers)
    assert r_drain.status_code == 403

    # Beta attempts to trigger validation on Alpha's node -> 403 Forbidden
    r_val = client.post(f"/provider/nodes/{alpha_node}/validate", headers=beta_headers)
    assert r_val.status_code == 403

    # Beta attempts to claim Alpha's node ID during registration -> 403 Forbidden
    r_claim = client.post(
        "/nodes/register",
        json={"node_id": alpha_node, "host": "127.0.0.1", "port": 8097, "total_capacity_bytes": 50_000_000},
        headers=beta_headers,
    )
    assert r_claim.status_code == 403


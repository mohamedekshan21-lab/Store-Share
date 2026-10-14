"""
Phase 7B Comprehensive Acceptance & Regression Test Suite.
Validates Expo Contribution Credits (ECC), Persistent Transactional Ledger,
Node Reputation & Trust Scoring (0-100), Anti-Abuse Trust Boundaries,
REST APIs, CoordinatorClient SDK, and CLI Commands.
"""

from __future__ import annotations

import json
import uuid
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
from coordinator.app.models import AccountingPolicyConfig
from coordinator.coordinator_client import CoordinatorClient
from client.cli import main as cli_main


@pytest.fixture
def test_settings(tmp_path: Path) -> CoordinatorSettings:
    """Fixture providing isolated temporary database and settings for Phase 7B tests."""
    db_file = tmp_path / "coordinator_phase7b_test.db"
    return CoordinatorSettings(
        db_path=db_file,
        auth_token="phase7b-test-secret-token",
        heartbeat_timeout_seconds=5,
    )


@pytest.fixture
def accounting_service(test_settings: CoordinatorSettings) -> AccountingService:
    """Fixture providing AccountingService instance."""
    return AccountingService(test_settings)


@pytest.fixture
def metering_service(test_settings: CoordinatorSettings) -> MeteringService:
    """Fixture providing MeteringService instance."""
    return MeteringService(test_settings)


@pytest.fixture
def node_registry(test_settings: CoordinatorSettings) -> NodeRegistry:
    """Fixture providing NodeRegistry instance."""
    return NodeRegistry(test_settings)


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
# 1. Database Schema and Migrations
# =============================================================================

def test_phase7b_database_schema_and_indexes(test_settings: CoordinatorSettings):
    """Verifies that all Phase 7B tables and indexes are initialized properly."""
    init_db(test_settings.db_path)
    with get_db_connection(test_settings.db_path) as conn:
        tables = [r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        assert "credit_ledger_entries" in tables
        assert "credit_balances" in tables
        assert "node_reputation_records" in tables
        assert "accounting_audit_logs" in tables

        indices = [r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()]
        assert "idx_cle_node_ts" in indices
        assert "idx_cle_idem" in indices
        assert "idx_rep_node_calc" in indices
        assert "idx_audit_target" in indices


# =============================================================================
# 2. Accounting Policy Versioning & Audit Trail
# =============================================================================

def test_accounting_policy_defaults_and_version(accounting_service: AccountingService):
    """Verifies default policy weights and version."""
    policy = accounting_service.get_policy()
    assert policy.policy_version == "7B-v1.0"
    assert policy.storage_weight_per_gb_day == 1.0
    assert policy.upload_weight_per_gb == 1.0
    assert policy.download_weight_per_gb == 1.5
    assert policy.repair_op_weight == 2.0
    assert policy.availability_weight == 0.40


def test_accounting_policy_update_and_audit_logging(accounting_service: AccountingService):
    """Updating policy parameters creates an auditable record in accounting_audit_logs."""
    new_policy = AccountingPolicyConfig(
        policy_version="7B-v2.0",
        storage_weight_per_gb_day=2.0,
        upload_weight_per_gb=1.2,
        download_weight_per_gb=1.8,
        repair_op_weight=3.0,
    )
    updated = accounting_service.update_policy(new_policy, actor="admin_alice")
    assert updated.policy_version == "7B-v2.0"
    assert updated.storage_weight_per_gb_day == 2.0

    # Verify audit log in SQLite
    with get_db_connection(accounting_service.db_path) as conn:
        log = conn.execute(
            "SELECT * FROM accounting_audit_logs WHERE action_type = 'policy_change' ORDER BY timestamp DESC"
        ).fetchone()
        assert log is not None
        assert log["target_id"] == "7B-v2.0"
        assert log["actor"] == "admin_alice"
        details = json.loads(log["details_json"])
        assert details["new"]["policy_version"] == "7B-v2.0"


# =============================================================================
# 3. Persistent Credit Ledger and Reversals
# =============================================================================

def test_ledger_record_and_idempotency(accounting_service: AccountingService, node_registry: NodeRegistry):
    """Recording ledger entries updates the balance table and is strictly idempotent."""
    node_id = "NODE-IDEM-1"
    node_registry.register_node(node_id, "127.0.0.1", 9101, total_capacity_bytes=10_000_000)

    entry1 = accounting_service.record_ledger_entry(
        node_id=node_id,
        category="storage",
        credit_delta=10.5,
        idempotency_key="test-idem-key-1",
        reason="Initial storage points",
    )
    assert entry1.credit_delta == 10.5
    assert entry1.node_id == node_id

    # Re-recording with identical idempotency key returns the exact same entry without double credit
    entry2 = accounting_service.record_ledger_entry(
        node_id=node_id,
        category="storage",
        credit_delta=10.5,
        idempotency_key="test-idem-key-1",
        reason="Duplicate call",
    )
    assert entry2.entry_id == entry1.entry_id

    bal = accounting_service.get_node_balance(node_id)
    assert bal.total_credits == 10.5
    assert bal.lifetime_earned == 10.5
    assert bal.lifetime_reversed == 0.0


def test_explicit_credit_reversal_compensating_entry(accounting_service: AccountingService, node_registry: NodeRegistry):
    """Reversing a ledger entry creates a compensating entry and updates balances without overwriting history."""
    node_id = "NODE-REV-1"
    node_registry.register_node(node_id, "127.0.0.1", 9102, total_capacity_bytes=10_000_000)

    orig = accounting_service.record_ledger_entry(
        node_id=node_id,
        category="repair",
        credit_delta=5.0,
        idempotency_key="test-award-repair-1",
        reason="Erroneous repair bonus",
    )

    bal_before = accounting_service.get_node_balance(node_id)
    assert bal_before.total_credits == 5.0

    # Reverse entry
    rev_entry = accounting_service.reverse_ledger_entry(
        entry_id=orig.entry_id,
        reason="Admin correction for duplicate claim",
        actor="admin_bob",
    )
    assert rev_entry.category == "reversal"
    assert rev_entry.credit_delta == -5.0
    assert rev_entry.reversal_ref == orig.entry_id

    bal_after = accounting_service.get_node_balance(node_id)
    assert bal_after.total_credits == 0.0
    assert bal_after.lifetime_earned == 5.0
    assert bal_after.lifetime_reversed == 5.0

    # Attempting to reverse an already reversed entry raises ValueError
    with pytest.raises(ValueError, match="already been reversed"):
        accounting_service.reverse_ledger_entry(orig.entry_id, reason="Second reversal attempt")

    # Attempting to reverse a reversal entry raises ValueError
    with pytest.raises(ValueError, match="Cannot reverse an existing reversal"):
        accounting_service.reverse_ledger_entry(rev_entry.entry_id, reason="Reversing a reversal")


def test_balance_reconciliation(accounting_service: AccountingService, node_registry: NodeRegistry):
    """reconcile_balance reconciles balance table directly against the ledger sum."""
    node_id = "NODE-RECON-1"
    node_registry.register_node(node_id, "127.0.0.1", 9103, total_capacity_bytes=10_000_000)

    accounting_service.record_ledger_entry(node_id, "storage", 10.0, "k1", "Storage 1")
    accounting_service.record_ledger_entry(node_id, "transfer_upload", 4.0, "k2", "Upload 1")
    accounting_service.record_ledger_entry(node_id, "transfer_download", 2.0, "k3", "Download 1")

    # Manually tamper with the balance table to simulate drift
    with get_db_connection(accounting_service.db_path) as conn:
        conn.execute("UPDATE credit_balances SET total_credits = 999.0 WHERE node_id = ?", (node_id,))
        conn.commit()

    # Reconcile restores ground truth (10 + 4 + 2 = 16.0)
    reconciled = accounting_service.reconcile_balance(node_id)
    assert reconciled.total_credits == 16.0


# =============================================================================
# 4. Storage Contribution Accounting (Time & Verified Bytes)
# =============================================================================

def test_storage_contribution_strictly_verified_not_quota(
    accounting_service: AccountingService,
    metering_service: MeteringService,
    node_registry: NodeRegistry,
):
    """
    Unused provider quota earns ZERO credits. Only verified bytes stored in active
    manifests generate storage points.
    """
    node_id = "NODE-STORAGE-VERIFIED"
    # Node offers 100 GB quota
    node_registry.register_node(node_id, "127.0.0.1", 9104, total_capacity_bytes=100 * (1024 ** 3))

    # Without any files stored, award_storage_credits generates no credit
    res1 = accounting_service.award_storage_credits(node_id, window_hours=24.0)
    assert res1 is None

    # Now register a verified active file in the catalog holding 1 GB on this node
    manifest = {
        "chunks": [
            {
                "chunk_id": "c-store-1",
                "size_bytes": 1024 ** 3,  # 1 GB
                "placements": [{"node_id": node_id, "chunk_id": "c-store-1"}],
            }
        ]
    }
    with get_db_connection(metering_service.db_path) as conn:
        conn.execute(
            """
            INSERT INTO files (
                file_id, owner_id, original_filename, original_size,
                status, redundancy_mode, manifest_version, manifest_json,
                created_at, updated_at
            ) VALUES ('f-store', 'owner1', 'test.dat', 1073741824, 'active', 'replication', 2, ?, ?, ?)
            """,
            (json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    # Create heartbeat observations to establish 100% availability
    accounting_service.settings.heartbeat_timeout_seconds = 10000
    accounting_service.metering_service.settings.heartbeat_timeout_seconds = 10000
    metering_service.settings.heartbeat_timeout_seconds = 10000
    now = datetime.now(timezone.utc)
    for h in range(5):
        metering_service.record_heartbeat_observation(
            node_id=node_id,
            reported_status="online",
            observed_at=(now - timedelta(hours=h * 2)).isoformat(),
        )

    # Award storage credits for 24h: 1 GB * 24h = 1 GB-day * 1.0 weight = 1.0 ECC
    entry = accounting_service.award_storage_credits(node_id, window_hours=24.0)
    assert entry is not None
    assert entry.category == "storage"
    assert pytest.approx(entry.credit_delta, rel=1e-2) == 1.0


# =============================================================================
# 5. Bandwidth Transfers & Operation Accounting
# =============================================================================

def test_transfer_credit_differentiation_and_failed_exclusion(
    accounting_service: AccountingService,
    metering_service: MeteringService,
    node_registry: NodeRegistry,
):
    """
    Ingress (upload) and egress (download) use differentiated weights.
    Failed transfers earn 0 credits.
    """
    node_id = "NODE-TX-WEIGHTS"
    node_registry.register_node(node_id, "127.0.0.1", 9105, total_capacity_bytes=50_000_000)

    # 1 GB Upload (weight 1.0)
    up_evt = metering_service.record_transfer_event(
        node_id=node_id,
        direction="upload",
        operation_type="client_upload",
        payload_bytes=1024 ** 3,
        status="success",
        idempotency_key="tx-up-1gb",
    )
    up_credit = accounting_service.award_transfer_credits(up_evt.event_id)
    assert up_credit is not None
    assert up_credit.category == "transfer_upload"
    assert pytest.approx(up_credit.credit_delta, rel=1e-2) == 1.0

    # 1 GB Download (weight 1.5)
    down_evt = metering_service.record_transfer_event(
        node_id=node_id,
        direction="download",
        operation_type="client_download",
        payload_bytes=1024 ** 3,
        status="success",
        idempotency_key="tx-down-1gb",
    )
    down_credit = accounting_service.award_transfer_credits(down_evt.event_id)
    assert down_credit is not None
    assert down_credit.category == "transfer_download"
    assert pytest.approx(down_credit.credit_delta, rel=1e-2) == 1.5

    # Failed transfer -> 0 credits
    failed_evt = metering_service.record_transfer_event(
        node_id=node_id,
        direction="download",
        operation_type="client_download",
        payload_bytes=1024 ** 3,
        status="failed",
        idempotency_key="tx-fail-1gb",
    )
    failed_credit = accounting_service.award_transfer_credits(failed_evt.event_id)
    assert failed_credit is None


def test_replication_and_repair_credit_awarding(
    accounting_service: AccountingService,
    metering_service: MeteringService,
    node_registry: NodeRegistry,
):
    """Replication and self-healing repair earn configured base and byte bonuses."""
    node_a = "NODE-REC-A"
    node_b = "NODE-REC-B"
    node_registry.register_node(node_a, "127.0.0.1", 9106, total_capacity_bytes=50_000_000)
    node_registry.register_node(node_b, "127.0.0.1", 9107, total_capacity_bytes=50_000_000)

    # Replication: base 0.5 + bytes
    rep_op = metering_service.record_operation_event(
        operation_type="replication",
        source_node_id=node_a,
        target_node_id=node_b,
        payload_bytes=1024 ** 3,
        status="completed",
        idempotency_key="rep-op-1",
    )
    rep_credit = accounting_service.award_operation_credits(rep_op.operation_id)
    assert rep_credit is not None
    assert rep_credit.category == "replication"
    # 0.5 base + 0.5 for 1GB = 1.0 ECC
    assert pytest.approx(rep_credit.credit_delta, rel=1e-2) == 1.0

    # Repair: base 2.0 + bytes
    repair_op = metering_service.record_operation_event(
        operation_type="repair",
        source_node_id=node_a,
        target_node_id=node_b,
        payload_bytes=1024 ** 3,
        status="completed",
        idempotency_key="repair-op-1",
    )
    repair_credit = accounting_service.award_operation_credits(repair_op.operation_id)
    assert repair_credit is not None
    assert repair_credit.category == "repair"
    # 2.0 base + 1.0 for 1GB = 3.0 ECC
    assert pytest.approx(repair_credit.credit_delta, rel=1e-2) == 3.0


# =============================================================================
# 6. Node Reputation and Trust Scoring (0 to 100)
# =============================================================================

def test_node_reputation_perfect_history(
    accounting_service: AccountingService,
    metering_service: MeteringService,
    node_registry: NodeRegistry,
):
    """A node with consistent heartbeats, 100% successful transfers, and operations earns 100 score."""
    node_id = "NODE-REP-PERFECT"
    node_registry.register_node(node_id, "127.0.0.1", 9108, total_capacity_bytes=50_000_000)

    now = datetime.now(timezone.utc)
    accounting_service.settings.heartbeat_timeout_seconds = 10000
    accounting_service.metering_service.settings.heartbeat_timeout_seconds = 10000
    metering_service.settings.heartbeat_timeout_seconds = 10000
    for i in range(12):
        metering_service.record_heartbeat_observation(
            node_id=node_id,
            reported_status="online",
            observed_at=(now - timedelta(hours=i * 2)).isoformat(),
        )

    for i in range(6):
        metering_service.record_transfer_event(
            node_id=node_id,
            direction="upload",
            operation_type="client_upload",
            payload_bytes=1000,
            status="success",
            idempotency_key=f"rep-tx-{i}",
        )

    for i in range(3):
        metering_service.record_operation_event(
            operation_type="repair",
            source_node_id="SOURCE-NODE",
            target_node_id=node_id,
            payload_bytes=5000,
            status="completed",
            idempotency_key=f"rep-op-{i}",
        )

    rep = accounting_service.calculate_node_reputation(node_id, window_hours=24.0)
    assert rep.reputation_score == 100.0
    assert rep.availability_score == 100.0
    assert rep.integrity_score == 100.0
    assert rep.recovery_score == 100.0
    assert rep.confidence_indicator >= 0.8
    assert rep.data_sufficiency_status == "sufficient"


def test_node_reputation_penalized_for_failures(
    accounting_service: AccountingService,
    metering_service: MeteringService,
    node_registry: NodeRegistry,
):
    """Transfer failures and offline intervals reduce reputation scores objectively."""
    node_id = "NODE-REP-FLAKY"
    node_registry.register_node(node_id, "127.0.0.1", 9109, total_capacity_bytes=50_000_000)

    # 5 successful, 5 failed transfers -> 50% integrity
    for i in range(5):
        metering_service.record_transfer_event(
            node_id=node_id,
            direction="upload",
            operation_type="client_upload",
            payload_bytes=1000,
            status="success",
            idempotency_key=f"rep-flaky-succ-{i}",
        )
    for i in range(5):
        metering_service.record_transfer_event(
            node_id=node_id,
            direction="upload",
            operation_type="client_upload",
            payload_bytes=1000,
            status="failed",
            idempotency_key=f"rep-flaky-fail-{i}",
        )

    rep = accounting_service.calculate_node_reputation(node_id, window_hours=24.0)
    assert rep.integrity_score == 50.0
    # Score must be lower than 100
    assert rep.reputation_score < 100.0
    assert rep.reputation_score >= 0.0


def test_new_node_low_confidence_indicator(
    accounting_service: AccountingService,
    node_registry: NodeRegistry,
):
    """A newly registered node without history receives an 'insufficient' confidence indicator."""
    node_id = "NODE-REP-NEWBIE"
    node_registry.register_node(node_id, "127.0.0.1", 9110, total_capacity_bytes=50_000_000)

    rep = accounting_service.calculate_node_reputation(node_id, window_hours=24.0)
    assert rep.confidence_indicator < 0.3
    assert rep.data_sufficiency_status == "insufficient"


# =============================================================================
# 7. Anti-Abuse Trust Boundaries & Authentication
# =============================================================================

def test_negative_payload_bytes_rejected(test_client: TestClient):
    """Negative payload bytes in transfer and operation submissions are rejected with 400 Bad Request."""
    res_tx = test_client.post(
        "/metering/transfers",
        json={
            "node_id": "FAKE-NODE",
            "direction": "upload",
            "operation_type": "client_upload",
            "payload_bytes": -5000,
        },
    )
    assert res_tx.status_code == 400

    res_op = test_client.post(
        "/metering/operations",
        json={
            "operation_type": "repair",
            "target_node_id": "FAKE-NODE",
            "payload_bytes": -100,
        },
    )
    assert res_op.status_code == 400


def test_administrative_endpoints_require_coordinator_auth(test_client: TestClient):
    """Policy updates and credit reversals require valid coordinator authentication."""
    # 1. Update policy without auth -> 401
    res_no_auth = test_client.put(
        "/accounting/policy",
        json={"policy_version": "HACKED", "storage_weight_per_gb_day": 999.0},
    )
    assert res_no_auth.status_code == 401

    # With valid auth -> 200
    res_auth = test_client.put(
        "/accounting/policy",
        json={"policy_version": "7B-v1.1", "storage_weight_per_gb_day": 1.5},
        headers={"X-Auth-Token": "phase7b-test-secret-token"},
    )
    assert res_auth.status_code == 200
    assert res_auth.json()["policy_version"] == "7B-v1.1"

    # 2. Reverse credit without auth -> 401
    rev_no_auth = test_client.post(
        "/accounting/credits/reverse",
        json={"entry_id": "cle-fake", "reason": "unauthorized attempt"},
    )
    assert rev_no_auth.status_code == 401


# =============================================================================
# 8. REST API Endpoints & Pagination
# =============================================================================

def test_api_credits_endpoints_and_pagination(
    test_client: TestClient,
    accounting_service: AccountingService,
    node_registry: NodeRegistry,
):
    """Tests GET /credits/nodes/{node_id}/balance, /ledger (paginated), and /summary."""
    node_id = "API-CRED-NODE"
    node_registry.register_node(node_id, "127.0.0.1", 9111, total_capacity_bytes=50_000_000)

    # Seed 5 ledger entries
    for i in range(5):
        accounting_service.record_ledger_entry(
            node_id=node_id,
            category="storage",
            credit_delta=2.0,
            idempotency_key=f"api-seed-{i}",
            reason=f"Seed entry {i}",
        )

    # 1. Balance endpoint
    bal_res = test_client.get(f"/credits/nodes/{node_id}/balance")
    assert bal_res.status_code == 200
    bal_data = bal_res.json()
    assert bal_data["total_credits"] == 10.0

    # 2. Ledger pagination: limit 2, offset 0
    page1 = test_client.get(f"/credits/nodes/{node_id}/ledger?limit=2&offset=0")
    assert page1.status_code == 200
    p1_data = page1.json()
    assert p1_data["count"] == 2
    assert p1_data["total_credits_in_page"] == 4.0

    # Offset 2
    page2 = test_client.get(f"/credits/nodes/{node_id}/ledger?limit=2&offset=2")
    assert page2.status_code == 200
    p2_data = page2.json()
    assert p2_data["count"] == 2

    # 3. Summary endpoint
    summ_res = test_client.get(f"/credits/nodes/{node_id}/summary")
    assert summ_res.status_code == 200
    s_data = summ_res.json()
    assert s_data["current_balance"] == 10.0
    assert s_data["storage_credits"] == 10.0
    assert s_data["entry_count"] == 5


def test_api_reputation_and_cluster_summary(
    test_client: TestClient,
    node_registry: NodeRegistry,
):
    """Tests /reputation/nodes/{node_id}, /reputation/nodes, and /accounting/cluster/summary."""
    node_registry.register_node("API-REP-1", "127.0.0.1", 9112, total_capacity_bytes=10_000_000)
    node_registry.register_node("API-REP-2", "127.0.0.1", 9113, total_capacity_bytes=20_000_000)

    # Get single node reputation
    res1 = test_client.get("/reputation/nodes/API-REP-1")
    assert res1.status_code == 200
    assert "reputation_score" in res1.json()

    # List all reputations
    res_list = test_client.get("/reputation/nodes")
    assert res_list.status_code == 200
    assert res_list.json()["count"] >= 2

    # Cluster accounting summary
    res_cluster = test_client.get("/accounting/cluster/summary")
    assert res_cluster.status_code == 200
    c_data = res_cluster.json()
    assert c_data["total_nodes_evaluated"] >= 2
    assert "average_reputation_score" in c_data


# =============================================================================
# 9. CoordinatorClient SDK & CLI Execution
# =============================================================================

def test_coordinator_client_phase7b_sdk(
    test_client: TestClient,
    node_registry: NodeRegistry,
    accounting_service: AccountingService,
):
    """Verifies that CoordinatorClient Phase 7B methods interface properly with endpoints."""
    node_id = "SDK-7B-NODE"
    node_registry.register_node(node_id, "127.0.0.1", 9114, total_capacity_bytes=30_000_000)

    accounting_service.record_ledger_entry(node_id, "storage", 12.0, "sdk-k1", "SDK storage award")

    client = CoordinatorClient(
        coordinator_url="http://testserver",
        auth_token="phase7b-test-secret-token",
    )
    # Bridge transport to Starlette TestClient with auth headers
    client._request = lambda method, path, **kwargs: test_client.request(
        method, path, headers=client._get_headers(), **kwargs
    )

    bal = client.get_credit_balance(node_id)
    assert bal["total_credits"] == 12.0

    ledger = client.get_credit_ledger(node_id, limit=10)
    assert ledger["count"] >= 1

    summary = client.get_credit_summary(node_id)
    assert summary["current_balance"] == 12.0

    rep = client.get_node_reputation(node_id)
    assert "reputation_score" in rep

    policy = client.get_accounting_policy()
    assert "policy_version" in policy

    cluster = client.get_accounting_cluster_summary()
    assert "net_cluster_credits" in cluster


def test_cli_phase7b_commands(
    monkeypatch: pytest.MonkeyPatch,
    test_client: TestClient,
    node_registry: NodeRegistry,
    accounting_service: AccountingService,
    capsys: pytest.CaptureFixture,
):
    """Tests CLI commands: credits-balance, credits-ledger, reputation-show, accounting-summary."""
    node_id = "CLI-7B-NODE"
    node_registry.register_node(node_id, "127.0.0.1", 9115, total_capacity_bytes=25_000_000)
    accounting_service.record_ledger_entry(node_id, "storage", 15.0, "cli-k1", "CLI storage award")

    # Patch CoordinatorClient._request in CLI to route to test_client
    orig_init = CoordinatorClient.__init__

    def patched_init(self, coordinator_url="http://127.0.0.1:9000", **kwargs):
        orig_init(self, coordinator_url="http://testserver", auth_token="phase7b-test-secret-token", **kwargs)
        self._request = lambda method, path, **kw: test_client.request(
            method, path, headers=self._get_headers(), **kw
        )

    monkeypatch.setattr(CoordinatorClient, "__init__", patched_init)

    # 1. credits-balance
    code = cli_main(["credits-balance", node_id])
    assert code == 0
    out = capsys.readouterr().out
    assert "Expo Contribution Credits (ECC)" in out
    assert "15.0000 ECC" in out

    # 2. credits-ledger
    code = cli_main(["credits-ledger", node_id, "--limit", "10"])
    assert code == 0
    out = capsys.readouterr().out
    assert "Contribution Credit Ledger" in out

    # 3. credits-summary
    code = cli_main(["credits-summary", node_id])
    assert code == 0
    out = capsys.readouterr().out
    assert "Categorized Contribution Summary" in out

    # 4. reputation-show
    code = cli_main(["reputation-show", node_id])
    assert code == 0
    out = capsys.readouterr().out
    assert "Node Reputation & Trust Score" in out

    # 5. accounting-policy
    code = cli_main(["accounting-policy"])
    assert code == 0
    out = capsys.readouterr().out
    assert "Active Expo Accounting & Reputation Policy" in out

    # 6. accounting-summary
    code = cli_main(["accounting-summary"])
    assert code == 0
    out = capsys.readouterr().out
    assert "Cluster Contribution Accounting Summary" in out

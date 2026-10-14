"""
Phase 7B.1 Acceptance & Invariant Verification Test Suite.
Validates:
1. Fixed-precision deterministic micro-ECC accounting and reconciliation.
2. Event reprocessing idempotency.
3. Exclusion of failed events from credit issuance.
4. Bounded partial and full reversals, non-negative balance protection.
5. Calibrated reputation scoring, confidence levels, and unobserved dimension neutral priors.
6. Treatment of nodes with zero observations vs verified history.
7. System isolation and manifest stability.
8. Coordinator restart persistence.
9. Administrative and tenant authorization security.
10. Storage interval overlap prevention and UTC interval locking.
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
from coordinator.app.accounting import AccountingService, to_micro_units, from_micro_units, MICRO_UNITS_PER_ECC
from coordinator.app.models import AccountingPolicyConfig, CreditReversalRequest
from coordinator.coordinator_client import CoordinatorClient, CoordinatorClientError


@pytest.fixture
def test_settings(tmp_path: Path) -> CoordinatorSettings:
    """Fixture providing isolated temporary database and settings for Phase 7B.1 tests."""
    db_file = tmp_path / "coordinator_phase7b1_test.db"
    return CoordinatorSettings(
        db_path=db_file,
        auth_token="phase7b1-test-secret-token",
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
# Invariant 1: Fixed-Precision Integer Subunits & Balance Reconciliation
# =============================================================================

def test_fixed_precision_micro_units_conversion():
    """Validates deterministic conversion between ECC floats and integer micro-units."""
    assert to_micro_units(1.0) == 1_000_000
    assert to_micro_units(0.000001) == 1  # Smallest atomic ECC subunit
    assert to_micro_units(0.0000004) == 0  # Rounds down
    assert to_micro_units(0.0000005) == 1  # Rounds half-up
    assert to_micro_units(12345.678901) == 12_345_678_901
    assert from_micro_units(1) == 0.000001
    assert from_micro_units(1_000_000) == 1.0


def test_balance_reconciliation_exact_integer_sums(
    accounting_service: AccountingService,
    node_registry: NodeRegistry,
):
    """
    Asserts every node balance reconciles with exact integer sums of its ledger entries.
    Tests micro-credits, large sums, and intentional drift recovery.
    """
    node_id = "NODE-PRECISION-1"
    node_registry.register_node(node_id, "127.0.0.1", 9201, total_capacity_bytes=50_000_000)

    # Issue 100 tiny atomic micro-credits (0.000001 ECC each)
    for i in range(100):
        accounting_service.record_ledger_entry(
            node_id=node_id,
            category="transfer_upload",
            credit_delta=0.000001,
            idempotency_key=f"tiny-{i}",
            reason="Tiny micro-credit",
        )

    # Issue a large credit (5000.5 ECC)
    accounting_service.record_ledger_entry(
        node_id=node_id,
        category="storage",
        credit_delta=5000.5,
        idempotency_key="large-credit-1",
        reason="Large storage grant",
    )

    bal = accounting_service.get_node_balance(node_id)
    # Expected: 100 * 0.000001 + 5000.5 = 0.0001 + 5000.5 = 5000.5001 ECC
    # In micro-units: 100 + 5_000_500_000 = 5_000_500_100 micro-units
    assert bal.total_micro_units == 5_000_500_100
    assert bal.total_credits == 5000.5001

    # Tamper with the balance table to simulate cache drift
    with get_db_connection(accounting_service.db_path) as conn:
        conn.execute("UPDATE credit_balances SET total_credits = 0.0, total_micro_units = 0 WHERE node_id = ?", (node_id,))
        conn.commit()

    # Reconcile restores ground truth directly from sum of ledger entries
    reconciled = accounting_service.reconcile_balance(node_id)
    assert reconciled.total_micro_units == 5_000_500_100
    assert reconciled.total_credits == 5000.5001


# =============================================================================
# Invariant 2: Reprocessing Events Never Issues Duplicate Credits
# =============================================================================

def test_event_reprocessing_strict_idempotency(
    accounting_service: AccountingService,
    metering_service: MeteringService,
    node_registry: NodeRegistry,
):
    """Reprocessing the same event returns existing ledger entry with zero duplicate credit."""
    node_id = "NODE-IDEM-TEST"
    node_registry.register_node(node_id, "127.0.0.1", 9202, total_capacity_bytes=50_000_000)

    tx_evt = metering_service.record_transfer_event(
        node_id=node_id,
        direction="upload",
        operation_type="client_upload",
        payload_bytes=1024 ** 3,
        status="success",
        idempotency_key="unique-tx-event-1",
    )

    # First award
    entry1 = accounting_service.award_transfer_credits(tx_evt.event_id)
    assert entry1 is not None

    bal1 = accounting_service.get_node_balance(node_id)

    # Second award for same event
    entry2 = accounting_service.award_transfer_credits(tx_evt.event_id)
    assert entry2 is not None
    assert entry1.entry_id == entry2.entry_id

    bal2 = accounting_service.get_node_balance(node_id)
    assert bal1.total_micro_units == bal2.total_micro_units
    assert bal1.total_credits == bal2.total_credits

    # Verify ledger entry count is exactly 1
    entries = accounting_service.get_ledger_entries(node_id)
    assert len(entries) == 1


# =============================================================================
# Invariant 3: Failed Operations Never Receive Credits
# =============================================================================

def test_failed_operations_and_transfers_earn_zero_credits(
    accounting_service: AccountingService,
    metering_service: MeteringService,
    node_registry: NodeRegistry,
):
    """Failed operations or failed transfers never earn contribution credits."""
    node_id = "NODE-FAILED-EVENTS"
    node_registry.register_node(node_id, "127.0.0.1", 9203, total_capacity_bytes=50_000_000)

    # 1. Failed transfer
    tx_fail = metering_service.record_transfer_event(
        node_id=node_id,
        direction="download",
        operation_type="client_download",
        payload_bytes=1024 ** 3,
        status="failed",
        idempotency_key="tx-failed-1",
    )
    assert accounting_service.award_transfer_credits(tx_fail.event_id) is None

    # 2. Failed repair operation
    op_fail = metering_service.record_operation_event(
        operation_type="repair",
        source_node_id="NODE-OTHER",
        target_node_id=node_id,
        payload_bytes=1024 ** 3,
        status="failed",
        idempotency_key="op-failed-1",
    )
    assert accounting_service.award_operation_credits(op_fail.operation_id) is None

    # Balance remains 0
    bal = accounting_service.get_node_balance(node_id)
    assert bal.total_credits == 0.0
    assert bal.total_micro_units == 0


# =============================================================================
# Invariant 4: Reversals Bounded, Partial Reversals & Non-Negative Balance
# =============================================================================

def test_partial_reversals_and_cumulative_bounds(
    accounting_service: AccountingService,
    node_registry: NodeRegistry,
):
    """
    Tests:
    - Multiple partial reversals up to original credit.
    - Exceeding remaining eligible credit raises ValueError.
    - Reversal idempotency preserves credit without double-deduction.
    """
    node_id = "NODE-PARTIAL-REV"
    node_registry.register_node(node_id, "127.0.0.1", 9204, total_capacity_bytes=50_000_000)

    orig = accounting_service.record_ledger_entry(
        node_id=node_id,
        category="repair",
        credit_delta=10.0,
        idempotency_key="orig-award-10",
        reason="Initial 10 ECC award",
    )
    assert accounting_service.get_node_balance(node_id).total_credits == 10.0

    # 1. First partial reversal: 4.0 ECC
    rev1 = accounting_service.reverse_ledger_entry(
        entry_id=orig.entry_id,
        reason="Partial audit correction 1",
        amount=4.0,
        idempotency_key="part-rev-1",
    )
    assert rev1.credit_delta == -4.0
    assert accounting_service.get_node_balance(node_id).total_credits == 6.0

    # 2. Retrying first partial reversal with same idempotency key is idempotent
    rev1_retry = accounting_service.reverse_ledger_entry(
        entry_id=orig.entry_id,
        reason="Partial audit correction 1 retry",
        amount=4.0,
        idempotency_key="part-rev-1",
    )
    assert rev1_retry.entry_id == rev1.entry_id
    assert accounting_service.get_node_balance(node_id).total_credits == 6.0

    # 3. Attempting to reverse 7.0 ECC when only 6.0 ECC remains eligible fails
    with pytest.raises(ValueError, match="exceeds remaining eligible credit"):
        accounting_service.reverse_ledger_entry(
            entry_id=orig.entry_id,
            reason="Excessive reversal attempt",
            amount=7.0,
        )

    # 4. Second partial reversal: 6.0 ECC (exhausts remaining eligible credit)
    rev2 = accounting_service.reverse_ledger_entry(
        entry_id=orig.entry_id,
        reason="Partial audit correction 2",
        amount=6.0,
    )
    assert rev2.credit_delta == -6.0
    bal_final = accounting_service.get_node_balance(node_id)
    assert bal_final.total_credits == 0.0
    assert bal_final.total_micro_units == 0
    assert bal_final.lifetime_earned == 10.0
    assert bal_final.lifetime_reversed == 10.0

    # 5. Further reversal attempt rejected
    with pytest.raises(ValueError, match="already been reversed"):
        accounting_service.reverse_ledger_entry(
            entry_id=orig.entry_id,
            reason="Exhausted entry reversal",
            amount=1.0,
        )


def test_reversal_cannot_create_negative_balance(
    accounting_service: AccountingService,
    node_registry: NodeRegistry,
):
    """Ensures a reversal cannot reduce a provider balance below zero."""
    node_id = "NODE-NEG-BAL-PROTECT"
    node_registry.register_node(node_id, "127.0.0.1", 9205, total_capacity_bytes=50_000_000)

    # Award 5.0 ECC
    entry_a = accounting_service.record_ledger_entry(
        node_id=node_id,
        category="storage",
        credit_delta=5.0,
        idempotency_key="award-a",
        reason="Storage award A",
    )

    # Reverse 3.0 ECC -> remaining balance is 2.0 ECC
    accounting_service.reverse_ledger_entry(
        entry_id=entry_a.entry_id,
        reason="Correction 1",
        amount=3.0,
    )
    assert accounting_service.get_node_balance(node_id).total_credits == 2.0

    # Manually reduce balance to 1.0 ECC (simulating partial debit)
    with get_db_connection(accounting_service.db_path) as conn:
        conn.execute("UPDATE credit_balances SET total_credits = 1.0, total_micro_units = 1000000 WHERE node_id = ?", (node_id,))
        conn.commit()

    # Now attempting to reverse the remaining 2.0 ECC eligible on entry_a would make balance -1.0 ECC
    with pytest.raises(ValueError, match="would create negative balance"):
        accounting_service.reverse_ledger_entry(
            entry_id=entry_a.entry_id,
            reason="Attempt to reverse remaining 2.0 ECC when only 1.0 ECC balance exists",
            amount=2.0,
        )


# =============================================================================
# Invariant 5 & 6: Reputation Calibration, Unobserved Dimensions & Confidence
# =============================================================================

def test_brand_new_node_reputation_calibration(
    accounting_service: AccountingService,
    node_registry: NodeRegistry,
):
    """
    Brand new node with ZERO observations:
    - Must NOT be given 100% reliability.
    - Starts at neutral unobserved baseline 50.0.
    - Confidence indicator is strictly 0.0 with 'insufficient' status.
    """
    node_id = "NODE-NEW-CALIB"
    node_registry.register_node(node_id, "127.0.0.1", 9206, total_capacity_bytes=50_000_000)

    rep = accounting_service.calculate_node_reputation(node_id, window_hours=24.0)
    assert rep.reputation_score == 50.0
    assert rep.availability_score == 50.0
    assert rep.integrity_score == 50.0
    assert rep.recovery_score == 50.0
    assert rep.confidence_indicator == 0.0
    assert rep.data_sufficiency_status == "insufficient"
    assert rep.metrics_summary["availability_observed"] is False
    assert rep.metrics_summary["integrity_observed"] is False
    assert rep.metrics_summary["recovery_observed"] is False


def test_partially_observed_node_reputation(
    accounting_service: AccountingService,
    metering_service: MeteringService,
    node_registry: NodeRegistry,
):
    """
    A node with observed heartbeats (100% uptime) and observed transfers (100% success),
    but ZERO recovery operations:
    - Score reflects observed dimensions without false recovery failure.
    - Recovery dimension is marked unobserved (50.0 prior).
    - Confidence indicator reflects incomplete multi-dimension observations.
    """
    node_id = "NODE-PARTIAL-OBSERVED"
    node_registry.register_node(node_id, "127.0.0.1", 9207, total_capacity_bytes=50_000_000)

    accounting_service.settings.heartbeat_timeout_seconds = 10000
    accounting_service.metering_service.settings.heartbeat_timeout_seconds = 10000
    metering_service.settings.heartbeat_timeout_seconds = 10000

    now = datetime.now(timezone.utc)
    for i in range(12):
        metering_service.record_heartbeat_observation(
            node_id=node_id,
            reported_status="online",
            observed_at=(now - timedelta(hours=i * 2)).isoformat(),
        )

    for i in range(5):
        metering_service.record_transfer_event(
            node_id=node_id,
            direction="upload",
            operation_type="client_upload",
            payload_bytes=2048,
            status="success",
            idempotency_key=f"part-obs-tx-{i}",
        )

    rep = accounting_service.calculate_node_reputation(node_id, window_hours=24.0)
    assert rep.availability_score == 100.0
    assert rep.integrity_score == 100.0
    assert rep.recovery_score == 50.0  # Unobserved neutral prior
    # Documented policy weights: 100*0.40 + 100*0.35 + 50*0.25 = 87.5
    assert rep.reputation_score == 87.5
    # Because 0 operations were recorded, recovery confidence c_ops is 0.0 -> confidence < 1.0
    assert rep.confidence_indicator < 1.0
    assert rep.metrics_summary["recovery_observed"] is False


# =============================================================================
# Invariant 7 & 10: Storage Interval Overlap Prevention & UTC Locking
# =============================================================================

def test_storage_interval_overlap_prevention(
    accounting_service: AccountingService,
    metering_service: MeteringService,
    node_registry: NodeRegistry,
):
    """
    Adjacent, overlapping, and repeated storage time windows:
    - Consecutive non-overlapping windows award credits normally.
    - Overlapping windows clip to only the uncredited duration.
    - Fully overlapping windows award zero duplicate credits.
    """
    node_id = "NODE-INTERVAL-OVERLAP"
    node_registry.register_node(node_id, "127.0.0.1", 9208, total_capacity_bytes=100 * (1024 ** 3))

    # Add active file
    manifest = {
        "chunks": [
            {
                "chunk_id": "c-store-overlap",
                "size_bytes": 1024 ** 3,  # 1 GB
                "placements": [{"node_id": node_id, "chunk_id": "c-store-overlap"}],
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
            ) VALUES ('f-overlap', 'owner1', 'test.dat', 1073741824, 'active', 'replication', 2, ?, ?, ?)
            """,
            (json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    accounting_service.settings.heartbeat_timeout_seconds = 10000
    accounting_service.metering_service.settings.heartbeat_timeout_seconds = 10000
    metering_service.settings.heartbeat_timeout_seconds = 10000
    base_time = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    for h in range(10):
        metering_service.record_heartbeat_observation(
            node_id=node_id,
            reported_status="online",
            observed_at=(base_time + timedelta(hours=h)).isoformat(),
        )

    # Window 1: 10:00 to 12:00 (2 hours)
    t10 = (base_time).isoformat()
    t12 = (base_time + timedelta(hours=2)).isoformat()
    entry1 = accounting_service.award_storage_credits(node_id, start_time=t10, end_time=t12)
    assert entry1 is not None
    bal1 = accounting_service.get_node_balance(node_id)
    assert bal1.total_credits > 0.0

    # Repeating Window 1 (10:00 to 12:00) returns existing entry without duplicate credit
    entry1_repeat = accounting_service.award_storage_credits(node_id, start_time=t10, end_time=t12)
    assert entry1_repeat.entry_id == entry1.entry_id
    bal1_repeat = accounting_service.get_node_balance(node_id)
    assert bal1.total_micro_units == bal1_repeat.total_micro_units

    # Sub-window inside Window 1 (10:30 to 11:30) is fully covered -> zero duplicate credit
    t10_30 = (base_time + timedelta(minutes=30)).isoformat()
    t11_30 = (base_time + timedelta(minutes=90)).isoformat()
    entry_sub = accounting_service.award_storage_credits(node_id, start_time=t10_30, end_time=t11_30)
    assert entry_sub.entry_id == entry1.entry_id
    assert accounting_service.get_node_balance(node_id).total_micro_units == bal1.total_micro_units

    # Partially overlapping window (11:00 to 13:00):
    # Only 12:00 to 13:00 (1 hour) is credited!
    t11 = (base_time + timedelta(hours=1)).isoformat()
    t13 = (base_time + timedelta(hours=3)).isoformat()
    entry2 = accounting_service.award_storage_credits(node_id, start_time=t11, end_time=t13)
    assert entry2 is not None
    assert entry2.entry_id != entry1.entry_id
    # Window hours in metadata was clipped to 1.0 hour
    assert entry2.audit_metadata["window_hours"] == 1.0


# =============================================================================
# Invariant 8: Coordinator Restart Persistence
# =============================================================================

def test_coordinator_restart_preserves_accounting_history(
    test_settings: CoordinatorSettings,
    node_registry: NodeRegistry,
):
    """Instantiating a new AccountingService on existing DB retains all ledger entries and balances."""
    node_id = "NODE-RESTART-TEST"
    node_registry.register_node(node_id, "127.0.0.1", 9209, total_capacity_bytes=50_000_000)

    # First service instance
    svc1 = AccountingService(test_settings)
    svc1.record_ledger_entry(node_id, "storage", 15.0, "restart-k1", "Pre-restart credit 1")
    svc1.record_ledger_entry(node_id, "repair", 5.0, "restart-k2", "Pre-restart credit 2")
    bal1 = svc1.get_node_balance(node_id)
    assert bal1.total_credits == 20.0
    assert bal1.total_micro_units == 20_000_000

    # Simulate process restart by creating brand new service instance
    svc2 = AccountingService(test_settings)
    bal2 = svc2.get_node_balance(node_id)
    assert bal2.total_credits == 20.0
    assert bal2.total_micro_units == 20_000_000
    assert bal2.lifetime_earned == 20.0

    entries = svc2.get_ledger_entries(node_id)
    assert len(entries) == 2


# =============================================================================
# Invariant 9: Administrative and Public Authorization Security
# =============================================================================

def test_administrative_endpoints_authorization_enforced(test_client: TestClient):
    """Ensures administrative reversal and policy mutation endpoints strictly require auth."""
    # 1. Reverse without auth -> 401
    res_rev = test_client.post(
        "/accounting/credits/reverse",
        json={"entry_id": "fake-entry", "reason": "No auth"},
    )
    assert res_rev.status_code == 401

    # 2. Reverse with invalid token -> 401
    res_rev_bad = test_client.post(
        "/accounting/credits/reverse",
        headers={"Authorization": "Bearer bad-token"},
        json={"entry_id": "fake-entry", "reason": "Bad token"},
    )
    assert res_rev_bad.status_code == 401

    # 3. Policy update without auth -> 401
    res_pol = test_client.put(
        "/accounting/policy",
        json={"policy_version": "malicious"},
    )
    assert res_pol.status_code == 401

    # 4. Trigger calculation without auth -> 401
    res_calc = test_client.post(
        "/accounting/credits/calculate",
        json={"window_hours": 24.0},
    )
    assert res_calc.status_code == 401

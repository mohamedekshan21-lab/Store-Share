"""
Phase 7B.1: Hardened Contribution Credits (ECC), Calibrated Reputation, and Auditable Ledger Service.
Provides deterministic fixed-precision integer micro-units (1 ECC = 1,000,000 micro-units),
overlap-prevented storage intervals, robust partial reversals, zero-evidence calibrated reputation,
and transactional integrity.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, List, Optional, Tuple

from coordinator.app.config import CoordinatorSettings
from coordinator.app.database import get_db_connection, init_db
from coordinator.app.metering import MeteringService
from coordinator.app.models import (
    CreditLedgerEntryRecord,
    CreditBalanceRecord,
    CreditLedgerListResponse,
    NodeCreditSummary,
    AccountingPolicyConfig,
    NodeReputationRecord,
    NodeReputationListResponse,
    ClusterAccountingSummary,
)

logger = logging.getLogger("expo_accounting")

# Fixed precision: 1 ECC = 1,000,000 micro-units (smallest unit = 1 micro-ECC = 0.000001 ECC)
MICRO_UNITS_PER_ECC = 1_000_000


def to_micro_units(val: float | Decimal | int | str) -> int:
    """Converts an ECC credit amount to deterministic integer micro-units."""
    d = Decimal(str(val)) if not isinstance(val, Decimal) else val
    return int((d * Decimal(MICRO_UNITS_PER_ECC)).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def from_micro_units(micro: int) -> float:
    """Converts integer micro-units back to floating-point ECC."""
    d = Decimal(micro) / Decimal(MICRO_UNITS_PER_ECC)
    return float(d.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP))


class AccountingService:
    """Core accounting and reputation engine for Expo storage network."""

    def __init__(self, settings: CoordinatorSettings) -> None:
        self.settings = settings
        self.db_path = settings.db_path
        init_db(self.db_path)
        self.metering_service = MeteringService(settings)
        self._policy = AccountingPolicyConfig()

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _parse_iso(self, ts_str: str) -> datetime:
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)

    # -------------------------------------------------------------------------
    # 1. Versioned Accounting Policy
    # -------------------------------------------------------------------------

    def get_policy(self) -> AccountingPolicyConfig:
        """Returns the currently active accounting and scoring policy."""
        return self._policy

    def update_policy(
        self, new_policy: AccountingPolicyConfig, actor: str = "system"
    ) -> AccountingPolicyConfig:
        """
        Updates the active accounting policy and logs an auditable change record.
        """
        old_policy_dict = self._policy.model_dump()
        self._policy = new_policy

        audit_id = f"aud-{uuid.uuid4().hex[:12]}"
        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO accounting_audit_logs (
                    audit_id, action_type, target_id, actor, timestamp, details_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_id,
                    "policy_change",
                    new_policy.policy_version,
                    actor,
                    self._now_iso(),
                    json.dumps({"old": old_policy_dict, "new": new_policy.model_dump()}),
                ),
            )
            conn.commit()

        logger.info(f"Accounting policy updated to version {new_policy.policy_version} by {actor}")
        return self._policy

    # -------------------------------------------------------------------------
    # 2. Persistent Credit Ledger with Fixed Precision
    # -------------------------------------------------------------------------

    def record_ledger_entry(
        self,
        node_id: str,
        category: str,
        credit_delta: float,
        idempotency_key: str,
        reason: str,
        event_id: Optional[str] = None,
        audit_metadata: Optional[Dict[str, Any]] = None,
        reversal_ref: Optional[str] = None,
        policy_version: Optional[str] = None,
        timestamp: Optional[str] = None,
        window_start: Optional[str] = None,
        window_end: Optional[str] = None,
    ) -> CreditLedgerEntryRecord:
        """
        Records an auditable credit ledger entry in SQLite within an immediate transaction.
        Uses integer micro-units for deterministic precision and zero floating-point drift.
        Guarantees idempotency: reprocessing an existing idempotency_key returns the original entry.
        Never silently overwrites historical entries.
        """
        clean_cat = category.lower().strip()
        pol_ver = policy_version or self._policy.policy_version
        ts = timestamp or self._now_iso()
        idem_key = idempotency_key.strip()
        delta_micro = to_micro_units(credit_delta)
        delta_float = from_micro_units(delta_micro)
        meta_json = json.dumps(audit_metadata) if audit_metadata else None

        with get_db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                # Check for existing entry by idempotency key
                existing = conn.execute(
                    "SELECT * FROM credit_ledger_entries WHERE idempotency_key = ?",
                    (idem_key,),
                ).fetchone()

                if existing:
                    parsed_meta = None
                    if existing["audit_metadata"]:
                        try:
                            parsed_meta = json.loads(existing["audit_metadata"])
                        except Exception:
                            pass
                    return CreditLedgerEntryRecord(
                        entry_id=existing["entry_id"],
                        node_id=existing["node_id"],
                        category=existing["category"],
                        credit_delta=existing["credit_delta"],
                        credit_micro_units=existing["credit_micro_units"],
                        event_id=existing["event_id"],
                        policy_version=existing["policy_version"],
                        timestamp=existing["timestamp"],
                        idempotency_key=existing["idempotency_key"],
                        reason=existing["reason"],
                        audit_metadata=parsed_meta,
                        reversal_ref=existing["reversal_ref"],
                        window_start=existing["window_start"],
                        window_end=existing["window_end"],
                    )

                entry_id = f"cle-{uuid.uuid4().hex[:12]}"
                conn.execute(
                    """
                    INSERT INTO credit_ledger_entries (
                        entry_id, node_id, category, credit_delta, credit_micro_units, event_id,
                        policy_version, timestamp, idempotency_key, reason,
                        audit_metadata, reversal_ref, window_start, window_end
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry_id,
                        node_id,
                        clean_cat,
                        delta_float,
                        delta_micro,
                        event_id,
                        pol_ver,
                        ts,
                        idem_key,
                        reason,
                        meta_json,
                        reversal_ref,
                        window_start,
                        window_end,
                    ),
                )

                # Update or initialize credit balance row atomically using integer micro-units
                bal_row = conn.execute(
                    "SELECT * FROM credit_balances WHERE node_id = ?",
                    (node_id,),
                ).fetchone()

                if bal_row:
                    curr_micro = bal_row["total_micro_units"] if bal_row["total_micro_units"] is not None else to_micro_units(bal_row["total_credits"])
                    curr_earned_micro = bal_row["lifetime_earned_micro"] if bal_row["lifetime_earned_micro"] is not None else to_micro_units(bal_row["lifetime_earned"])
                    curr_rev_micro = bal_row["lifetime_reversed_micro"] if bal_row["lifetime_reversed_micro"] is not None else to_micro_units(bal_row["lifetime_reversed"])

                    new_micro = curr_micro + delta_micro
                    new_earned_micro = curr_earned_micro + (delta_micro if delta_micro > 0 else 0)
                    new_rev_micro = curr_rev_micro + (abs(delta_micro) if delta_micro < 0 else 0)

                    new_total = from_micro_units(new_micro)
                    new_earned = from_micro_units(new_earned_micro)
                    new_rev = from_micro_units(new_rev_micro)

                    conn.execute(
                        """
                        UPDATE credit_balances
                        SET total_credits = ?, total_micro_units = ?,
                            lifetime_earned = ?, lifetime_earned_micro = ?,
                            lifetime_reversed = ?, lifetime_reversed_micro = ?,
                            last_reconciled_at = ?
                        WHERE node_id = ?
                        """,
                        (new_total, new_micro, new_earned, new_earned_micro, new_rev, new_rev_micro, ts, node_id),
                    )
                else:
                    init_earned_micro = delta_micro if delta_micro > 0 else 0
                    init_rev_micro = abs(delta_micro) if delta_micro < 0 else 0
                    conn.execute(
                        """
                        INSERT INTO credit_balances (
                            node_id, total_credits, total_micro_units,
                            lifetime_earned, lifetime_earned_micro,
                            lifetime_reversed, lifetime_reversed_micro,
                            last_reconciled_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            node_id,
                            delta_float,
                            delta_micro,
                            from_micro_units(init_earned_micro),
                            init_earned_micro,
                            from_micro_units(init_rev_micro),
                            init_rev_micro,
                            ts,
                        ),
                    )

                conn.commit()
            except Exception:
                conn.rollback()
                raise

        return CreditLedgerEntryRecord(
            entry_id=entry_id,
            node_id=node_id,
            category=clean_cat,
            credit_delta=delta_float,
            credit_micro_units=delta_micro,
            event_id=event_id,
            policy_version=pol_ver,
            timestamp=ts,
            idempotency_key=idem_key,
            reason=reason,
            audit_metadata=audit_metadata,
            reversal_ref=reversal_ref,
            window_start=window_start,
            window_end=window_end,
        )

    def reverse_ledger_entry(
        self,
        entry_id: str,
        reason: str,
        actor: str = "admin",
        amount: Optional[float] = None,
        idempotency_key: Optional[str] = None,
    ) -> CreditLedgerEntryRecord:
        """
        Creates an explicit compensating reversal ledger entry.
        Supports full and partial reversals.
        Never alters or overwrites historical records.
        Guarantees:
        - Cannot reverse an existing reversal entry.
        - Cumulative reversals cannot exceed original credit amount.
        - Cannot create negative node credit balance.
        - Idempotent retries return existing reversal record without duplicate deductions.
        """
        with get_db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                orig = conn.execute(
                    "SELECT * FROM credit_ledger_entries WHERE entry_id = ?",
                    (entry_id,),
                ).fetchone()

                if not orig:
                    raise KeyError(f"Credit ledger entry '{entry_id}' not found.")

                if orig["category"] == "reversal" or orig["reversal_ref"] is not None:
                    raise ValueError(f"Cannot reverse an existing reversal entry '{entry_id}'.")

                orig_micro = orig["credit_micro_units"] if orig["credit_micro_units"] else to_micro_units(orig["credit_delta"])
                if orig_micro <= 0:
                    raise ValueError(f"Cannot reverse non-positive credit entry '{entry_id}'.")

                # Sum existing reversals for this entry
                rev_sum_row = conn.execute(
                    "SELECT COALESCE(SUM(credit_micro_units), 0) AS rev_micro FROM credit_ledger_entries WHERE reversal_ref = ?",
                    (entry_id,),
                ).fetchone()
                already_reversed_micro = abs(int(rev_sum_row["rev_micro"]))
                remaining_eligible_micro = orig_micro - already_reversed_micro

                # Determine requested reversal micro-units
                if amount is not None:
                    req_micro = to_micro_units(amount)
                    if req_micro <= 0:
                        raise ValueError(f"Reversal amount must be positive, got {amount}.")
                    reversal_micro = req_micro
                else:
                    reversal_micro = remaining_eligible_micro

                # 1. If an explicit idempotency key is provided, check if it was already executed
                if idempotency_key:
                    target_idem = idempotency_key.strip()
                    existing_idem = conn.execute(
                        "SELECT * FROM credit_ledger_entries WHERE idempotency_key = ?",
                        (target_idem,),
                    ).fetchone()
                    if existing_idem:
                        parsed_meta = None
                        if existing_idem["audit_metadata"]:
                            try:
                                parsed_meta = json.loads(existing_idem["audit_metadata"])
                            except Exception:
                                pass
                        return CreditLedgerEntryRecord(
                            entry_id=existing_idem["entry_id"],
                            node_id=existing_idem["node_id"],
                            category=existing_idem["category"],
                            credit_delta=existing_idem["credit_delta"],
                            credit_micro_units=existing_idem["credit_micro_units"],
                            event_id=existing_idem["event_id"],
                            policy_version=existing_idem["policy_version"],
                            timestamp=existing_idem["timestamp"],
                            idempotency_key=existing_idem["idempotency_key"],
                            reason=existing_idem["reason"],
                            audit_metadata=parsed_meta,
                            reversal_ref=existing_idem["reversal_ref"],
                            window_start=existing_idem["window_start"],
                            window_end=existing_idem["window_end"],
                        )
                else:
                    target_idem = f"rev:{entry_id}:{uuid.uuid4().hex[:8]}"

                # 2. Check remaining eligible credit
                if remaining_eligible_micro <= 0:
                    raise ValueError(f"Entry '{entry_id}' has already been reversed.")

                if reversal_micro > remaining_eligible_micro:
                    raise ValueError(
                        f"Requested reversal amount ({from_micro_units(reversal_micro)} ECC) exceeds "
                        f"remaining eligible credit ({from_micro_units(remaining_eligible_micro)} ECC)."
                    )

                # Verify current balance cannot become negative
                bal_row = conn.execute(
                    "SELECT * FROM credit_balances WHERE node_id = ?",
                    (orig["node_id"],),
                ).fetchone()
                current_micro = int(bal_row["total_micro_units"]) if bal_row and bal_row["total_micro_units"] is not None else 0

                if current_micro < reversal_micro:
                    raise ValueError(
                        f"Reversal of {from_micro_units(reversal_micro)} ECC would create negative balance "
                        f"(current balance: {from_micro_units(current_micro)} ECC)."
                    )

                rev_delta_float = -from_micro_units(reversal_micro)
                rev_reason = f"Reversal of {entry_id}: {reason}"
                meta = {
                    "reversed_entry_id": entry_id,
                    "actor": actor,
                    "orig_category": orig["category"],
                    "reversal_micro_units": reversal_micro,
                    "partial": (reversal_micro < orig_micro),
                }

                # Record reversal entry directly inside existing transaction
                reversal_entry_id = f"cle-{uuid.uuid4().hex[:12]}"
                ts = self._now_iso()
                conn.execute(
                    """
                    INSERT INTO credit_ledger_entries (
                        entry_id, node_id, category, credit_delta, credit_micro_units, event_id,
                        policy_version, timestamp, idempotency_key, reason,
                        audit_metadata, reversal_ref, window_start, window_end
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        reversal_entry_id,
                        orig["node_id"],
                        "reversal",
                        rev_delta_float,
                        -reversal_micro,
                        orig["event_id"],
                        self._policy.policy_version,
                        ts,
                        target_idem,
                        rev_reason,
                        json.dumps(meta),
                        entry_id,
                        None,
                        None,
                    ),
                )

                # Update balance atomically
                new_bal_micro = current_micro - reversal_micro
                curr_earned_micro = bal_row["lifetime_earned_micro"] if bal_row and bal_row["lifetime_earned_micro"] is not None else 0
                curr_rev_micro = bal_row["lifetime_reversed_micro"] if bal_row and bal_row["lifetime_reversed_micro"] is not None else 0
                new_rev_micro = curr_rev_micro + reversal_micro

                conn.execute(
                    """
                    UPDATE credit_balances
                    SET total_credits = ?, total_micro_units = ?,
                        lifetime_earned = ?, lifetime_earned_micro = ?,
                        lifetime_reversed = ?, lifetime_reversed_micro = ?,
                        last_reconciled_at = ?
                    WHERE node_id = ?
                    """,
                    (
                        from_micro_units(new_bal_micro),
                        new_bal_micro,
                        from_micro_units(curr_earned_micro),
                        curr_earned_micro,
                        from_micro_units(new_rev_micro),
                        new_rev_micro,
                        ts,
                        orig["node_id"],
                    ),
                )

                # Audit log
                audit_id = f"aud-{uuid.uuid4().hex[:12]}"
                conn.execute(
                    """
                    INSERT INTO accounting_audit_logs (
                        audit_id, action_type, target_id, actor, timestamp, details_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        audit_id,
                        "credit_reversal",
                        entry_id,
                        actor,
                        ts,
                        json.dumps({
                            "reversal_entry_id": reversal_entry_id,
                            "delta": rev_delta_float,
                            "delta_micro": -reversal_micro,
                            "reason": reason,
                            "remaining_eligible_after": from_micro_units(remaining_eligible_micro - reversal_micro),
                        }),
                    ),
                )

                conn.commit()
            except Exception:
                conn.rollback()
                raise

        logger.info(f"Reversed ledger entry {entry_id} with compensating entry {reversal_entry_id}")
        return CreditLedgerEntryRecord(
            entry_id=reversal_entry_id,
            node_id=orig["node_id"],
            category="reversal",
            credit_delta=rev_delta_float,
            credit_micro_units=-reversal_micro,
            event_id=orig["event_id"],
            policy_version=self._policy.policy_version,
            timestamp=ts,
            idempotency_key=target_idem,
            reason=rev_reason,
            audit_metadata=meta,
            reversal_ref=entry_id,
            window_start=None,
            window_end=None,
        )

    def reconcile_balance(self, node_id: str) -> CreditBalanceRecord:
        """
        Reconciles the credit balance table against the ground-truth sum of all ledger entries
        using integer micro-units for deterministic precision.
        """
        ts = self._now_iso()
        with get_db_connection(self.db_path) as conn:
            stats = conn.execute(
                """
                SELECT
                    COALESCE(SUM(credit_micro_units), 0) AS total_micro,
                    COALESCE(SUM(CASE WHEN credit_micro_units > 0 THEN credit_micro_units ELSE 0 END), 0) AS earned_micro,
                    COALESCE(SUM(CASE WHEN credit_micro_units < 0 THEN ABS(credit_micro_units) ELSE 0 END), 0) AS rev_micro
                FROM credit_ledger_entries
                WHERE node_id = ?
                """,
                (node_id,),
            ).fetchone()

            total_micro = int(stats["total_micro"])
            earned_micro = int(stats["earned_micro"])
            rev_micro = int(stats["rev_micro"])

            total_float = from_micro_units(total_micro)
            earned_float = from_micro_units(earned_micro)
            rev_float = from_micro_units(rev_micro)

            conn.execute(
                """
                INSERT INTO credit_balances (
                    node_id, total_credits, total_micro_units,
                    lifetime_earned, lifetime_earned_micro,
                    lifetime_reversed, lifetime_reversed_micro,
                    last_reconciled_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET
                    total_credits = excluded.total_credits,
                    total_micro_units = excluded.total_micro_units,
                    lifetime_earned = excluded.lifetime_earned,
                    lifetime_earned_micro = excluded.lifetime_earned_micro,
                    lifetime_reversed = excluded.lifetime_reversed,
                    lifetime_reversed_micro = excluded.lifetime_reversed_micro,
                    last_reconciled_at = excluded.last_reconciled_at
                """,
                (node_id, total_float, total_micro, earned_float, earned_micro, rev_float, rev_micro, ts),
            )
            conn.commit()

        return CreditBalanceRecord(
            node_id=node_id,
            total_credits=total_float,
            total_micro_units=total_micro,
            lifetime_earned=earned_float,
            lifetime_earned_micro=earned_micro,
            lifetime_reversed=rev_float,
            lifetime_reversed_micro=rev_micro,
            last_reconciled_at=ts,
        )

    def get_node_balance(self, node_id: str) -> CreditBalanceRecord:
        """Retrieves the current reconciled credit balance for a node."""
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM credit_balances WHERE node_id = ?",
                (node_id,),
            ).fetchone()

        if row:
            return CreditBalanceRecord(
                node_id=row["node_id"],
                total_credits=row["total_credits"],
                total_micro_units=row["total_micro_units"],
                lifetime_earned=row["lifetime_earned"],
                lifetime_earned_micro=row["lifetime_earned_micro"],
                lifetime_reversed=row["lifetime_reversed"],
                lifetime_reversed_micro=row["lifetime_reversed_micro"],
                last_reconciled_at=row["last_reconciled_at"],
            )

        # If no row exists, reconcile from ledger
        return self.reconcile_balance(node_id)

    def get_ledger_entries(
        self,
        node_id: str,
        category: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[CreditLedgerEntryRecord]:
        """Queries paginated ledger entries for a node with optional category/time filtering."""
        query = "SELECT * FROM credit_ledger_entries WHERE node_id = ?"
        params: List[Any] = [node_id]

        if category:
            query += " AND category = ?"
            params.append(category.lower().strip())
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)

        query += " ORDER BY timestamp DESC, entry_id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with get_db_connection(self.db_path) as conn:
            rows = conn.execute(query, tuple(params)).fetchall()

        entries: List[CreditLedgerEntryRecord] = []
        for r in rows:
            parsed_meta = None
            if r["audit_metadata"]:
                try:
                    parsed_meta = json.loads(r["audit_metadata"])
                except Exception:
                    pass
            entries.append(
                CreditLedgerEntryRecord(
                    entry_id=r["entry_id"],
                    node_id=r["node_id"],
                    category=r["category"],
                    credit_delta=r["credit_delta"],
                    credit_micro_units=r["credit_micro_units"],
                    event_id=r["event_id"],
                    policy_version=r["policy_version"],
                    timestamp=r["timestamp"],
                    idempotency_key=r["idempotency_key"],
                    reason=r["reason"],
                    audit_metadata=parsed_meta,
                    reversal_ref=r["reversal_ref"],
                    window_start=r["window_start"],
                    window_end=r["window_end"],
                )
            )

        return entries

    def get_node_credit_summary(self, node_id: str) -> NodeCreditSummary:
        """Computes a categorized credit breakdown for a node."""
        bal = self.get_node_balance(node_id)
        with get_db_connection(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT
                    category,
                    COALESCE(SUM(credit_micro_units), 0) AS total_micro,
                    COUNT(*) AS count
                FROM credit_ledger_entries
                WHERE node_id = ?
                GROUP BY category
                """,
                (node_id,),
            ).fetchall()

            total_entries = sum(r["count"] for r in rows)
            cat_map = {r["category"]: from_micro_units(int(r["total_micro"])) for r in rows}

        return NodeCreditSummary(
            node_id=node_id,
            current_balance=bal.total_credits,
            storage_credits=round(cat_map.get("storage", 0.0), 6),
            upload_credits=round(cat_map.get("transfer_upload", 0.0), 6),
            download_credits=round(cat_map.get("transfer_download", 0.0), 6),
            replication_credits=round(cat_map.get("replication", 0.0), 6),
            repair_credits=round(cat_map.get("repair", 0.0), 6),
            reversal_credits=round(cat_map.get("reversal", 0.0), 6),
            entry_count=total_entries,
            last_updated=bal.last_reconciled_at,
        )

    # -------------------------------------------------------------------------
    # 3. Deterministic Contribution Awarding & Overlap Prevention
    # -------------------------------------------------------------------------

    def award_storage_credits(
        self,
        node_id: str,
        window_hours: float = 24.0,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> Optional[CreditLedgerEntryRecord]:
        """
        Calculates and awards storage-time contribution credits (ECC) strictly based on
        verified bytes maintained in active files over the evaluated window.
        Unused provider quota is NEVER rewarded.
        Enforces UTC interval boundary locking to prevent double-crediting across adjacent
        or overlapping time windows.
        """
        with get_db_connection(self.db_path) as conn:
            node_row = conn.execute(
                "SELECT * FROM nodes WHERE node_id = ?",
                (node_id,),
            ).fetchone()

        if not node_row:
            return None

        w_end = self._parse_iso(end_time) if end_time else datetime.now(timezone.utc)
        w_start = self._parse_iso(start_time) if start_time else (w_end - timedelta(hours=window_hours))

        if w_start >= w_end:
            return None

        w_start_iso = w_start.isoformat()
        w_end_iso = w_end.isoformat()

        # Check existing storage accounting intervals to prevent overlapping awards
        with get_db_connection(self.db_path) as conn:
            # 1. Exact or superset interval already covered
            fully_covered = conn.execute(
                """
                SELECT entry_id FROM storage_accounting_intervals
                WHERE node_id = ? AND window_start <= ? AND window_end >= ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (node_id, w_start_iso, w_end_iso),
            ).fetchone()

            if fully_covered:
                existing_entry = conn.execute(
                    "SELECT * FROM credit_ledger_entries WHERE entry_id = ?",
                    (fully_covered["entry_id"],),
                ).fetchone()
                if existing_entry:
                    parsed_meta = None
                    if existing_entry["audit_metadata"]:
                        try:
                            parsed_meta = json.loads(existing_entry["audit_metadata"])
                        except Exception:
                            pass
                    return CreditLedgerEntryRecord(
                        entry_id=existing_entry["entry_id"],
                        node_id=existing_entry["node_id"],
                        category=existing_entry["category"],
                        credit_delta=existing_entry["credit_delta"],
                        credit_micro_units=existing_entry["credit_micro_units"],
                        event_id=existing_entry["event_id"],
                        policy_version=existing_entry["policy_version"],
                        timestamp=existing_entry["timestamp"],
                        idempotency_key=existing_entry["idempotency_key"],
                        reason=existing_entry["reason"],
                        audit_metadata=parsed_meta,
                        reversal_ref=existing_entry["reversal_ref"],
                        window_start=existing_entry["window_start"],
                        window_end=existing_entry["window_end"],
                    )

            # 2. Check for partially overlapping intervals
            overlapping = conn.execute(
                """
                SELECT * FROM storage_accounting_intervals
                WHERE node_id = ? AND window_start < ? AND window_end > ?
                ORDER BY window_end DESC
                """,
                (node_id, w_end_iso, w_start_iso),
            ).fetchall()

        # Clip start to end of latest overlapping interval to avoid double-crediting
        effective_start = w_start
        for ov in overlapping:
            ov_end = self._parse_iso(ov["window_end"])
            if ov_end > effective_start:
                effective_start = ov_end

        if effective_start >= w_end:
            # Interval is completely partitioned across multiple prior jobs
            return None

        effective_hours = max(0.01, (w_end - effective_start).total_seconds() / 3600.0)

        # Ground truth verified bytes in active file catalog
        verified_bytes = self.metering_service.calculate_authoritative_stored_bytes(node_id)
        if verified_bytes <= 0:
            snaps = self.metering_service.get_capacity_snapshots(node_id, limit=1)
            verified_bytes = snaps[0].used_bytes if snaps and snaps[0].is_valid else 0

        if verified_bytes <= 0:
            return None

        # Uptime availability factor
        uptime = self.metering_service.calculate_node_uptime(
            node_id, window_start=effective_start.isoformat(), window_end=w_end_iso
        )
        avail_pct = uptime.availability_percentage

        # Multiplier bounded by policy
        min_m = self._policy.availability_multiplier_min
        max_m = self._policy.availability_multiplier_max
        multiplier = min_m + (max_m - min_m) * (avail_pct / 100.0)

        # Formula: (verified_byte_hours / (1024^3 * 24)) * storage_weight * availability_multiplier
        byte_hours = verified_bytes * effective_hours
        gb_days = byte_hours / (1024.0 ** 3 * 24.0)
        credits_earned = round(gb_days * self._policy.storage_weight_per_gb_day * multiplier, 6)

        if credits_earned <= 0:
            return None

        eff_start_iso = effective_start.isoformat()
        idem_key = f"storage:{node_id}:{eff_start_iso[:19]}:{w_end_iso[:19]}"
        reason = (
            f"Verified storage contribution for {effective_hours:.1f}h window "
            f"({verified_bytes} bytes, {avail_pct:.1f}% availability)"
        )
        metadata = {
            "verified_bytes": verified_bytes,
            "window_hours": round(effective_hours, 2),
            "availability_percentage": round(avail_pct, 2),
            "multiplier": round(multiplier, 4),
            "gb_days": round(gb_days, 6),
            "window_start": eff_start_iso,
            "window_end": w_end_iso,
        }

        entry = self.record_ledger_entry(
            node_id=node_id,
            category="storage",
            credit_delta=credits_earned,
            idempotency_key=idem_key,
            reason=reason,
            audit_metadata=metadata,
            window_start=eff_start_iso,
            window_end=w_end_iso,
        )

        # Record interval in tracking table to lock out future overlaps
        interval_id = f"sai-{uuid.uuid4().hex[:12]}"
        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO storage_accounting_intervals (
                    interval_id, node_id, window_start, window_end, entry_id, bytes_stored, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (interval_id, node_id, eff_start_iso, w_end_iso, entry.entry_id, verified_bytes, self._now_iso()),
            )
            conn.commit()

        return entry

    def award_transfer_credits(
        self,
        event_id: str,
    ) -> Optional[CreditLedgerEntryRecord]:
        """
        Awards ECC credits for a completed bandwidth transfer event.
        Failed transfers or non-positive bytes earn 0 credits.
        """
        with get_db_connection(self.db_path) as conn:
            evt = conn.execute(
                "SELECT * FROM metering_transfer_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()

        if not evt:
            return None

        if evt["status"] != "success" or evt["payload_bytes"] <= 0:
            return None

        # Verify node registration
        node_id = evt["node_id"]
        with get_db_connection(self.db_path) as conn:
            node_exists = conn.execute(
                "SELECT node_id FROM nodes WHERE node_id = ?",
                (node_id,),
            ).fetchone()
        if not node_exists:
            return None

        direction = evt["direction"].lower()
        payload_bytes = evt["payload_bytes"]
        gb = payload_bytes / (1024.0 ** 3)

        if direction == "upload":
            category = "transfer_upload"
            rate = self._policy.upload_weight_per_gb
            desc = "Client upload ingress payload transfer"
        else:
            category = "transfer_download"
            rate = self._policy.download_weight_per_gb
            desc = "Client download egress payload transfer"

        credits_earned = round(gb * rate, 6)
        if credits_earned <= 0:
            credits_earned = 0.000001  # Minimum 1 micro-ECC

        idem_key = f"award:transfer:{event_id}"
        reason = f"{desc} ({payload_bytes} bytes)"
        metadata = {
            "event_id": event_id,
            "payload_bytes": payload_bytes,
            "rate_per_gb": rate,
            "direction": direction,
            "operation_type": evt["operation_type"],
        }

        return self.record_ledger_entry(
            node_id=node_id,
            category=category,
            credit_delta=credits_earned,
            idempotency_key=idem_key,
            reason=reason,
            event_id=event_id,
            audit_metadata=metadata,
        )

    def award_operation_credits(
        self,
        operation_id: str,
    ) -> Optional[CreditLedgerEntryRecord]:
        """
        Awards ECC credits for a verified completed replication or self-healing repair operation.
        Credits are assigned to the target node maintaining the recovered data.
        Failed operations earn 0 credits.
        """
        with get_db_connection(self.db_path) as conn:
            op = conn.execute(
                "SELECT * FROM metering_operation_events WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()

        if not op:
            return None

        if op["status"] != "completed":
            return None

        target_node = op["target_node_id"]
        op_type = op["operation_type"].lower()
        payload_bytes = max(0, op["payload_bytes"])
        gb = payload_bytes / (1024.0 ** 3)

        if op_type == "repair":
            category = "repair"
            base_points = self._policy.repair_op_weight
            byte_rate = self._policy.repair_weight_per_gb
            desc = "Verified self-healing chunk repair"
        else:
            category = "replication"
            base_points = self._policy.replication_op_weight
            byte_rate = self._policy.replication_weight_per_gb
            desc = "Verified proactive chunk replication"

        credits_earned = round(base_points + (gb * byte_rate), 6)
        idem_key = f"award:operation:{operation_id}"
        reason = f"{desc} completion ({payload_bytes} bytes)"
        metadata = {
            "operation_id": operation_id,
            "operation_type": op_type,
            "source_node_id": op["source_node_id"],
            "target_node_id": target_node,
            "chunk_id": op["chunk_id"],
            "payload_bytes": payload_bytes,
            "base_points": base_points,
        }

        return self.record_ledger_entry(
            node_id=target_node,
            category=category,
            credit_delta=credits_earned,
            idempotency_key=idem_key,
            reason=reason,
            event_id=operation_id,
            audit_metadata=metadata,
        )

    def process_contribution_accounting(
        self,
        node_id: Optional[str] = None,
        window_hours: float = 24.0,
        include_storage: bool = True,
        include_transfers: bool = True,
        include_operations: bool = True,
    ) -> Dict[str, Any]:
        """
        Batch-processes and finalizes contribution accounting over a time window.
        Idempotent across multiple runs.
        """
        results: Dict[str, Any] = {
            "storage_entries": 0,
            "transfer_entries": 0,
            "operation_entries": 0,
            "total_credits_awarded": 0.0,
        }

        # Determine target nodes
        nodes_to_process: List[str] = []
        with get_db_connection(self.db_path) as conn:
            if node_id:
                nodes_to_process = [node_id]
            else:
                rows = conn.execute("SELECT node_id FROM nodes").fetchall()
                nodes_to_process = [r["node_id"] for r in rows]

        # 1. Storage time contribution
        if include_storage:
            for n in nodes_to_process:
                entry = self.award_storage_credits(n, window_hours=window_hours)
                if entry:
                    results["storage_entries"] += 1
                    results["total_credits_awarded"] += entry.credit_delta

        # 2. Transfer events
        if include_transfers:
            with get_db_connection(self.db_path) as conn:
                if node_id:
                    tx_rows = conn.execute(
                        "SELECT event_id FROM metering_transfer_events WHERE node_id = ? AND status = 'success'",
                        (node_id,),
                    ).fetchall()
                else:
                    tx_rows = conn.execute(
                        "SELECT event_id FROM metering_transfer_events WHERE status = 'success'",
                    ).fetchall()

            for tx in tx_rows:
                entry = self.award_transfer_credits(tx["event_id"])
                if entry:
                    results["transfer_entries"] += 1
                    results["total_credits_awarded"] += entry.credit_delta

        # 3. Operations
        if include_operations:
            with get_db_connection(self.db_path) as conn:
                if node_id:
                    op_rows = conn.execute(
                        "SELECT operation_id FROM metering_operation_events WHERE target_node_id = ? AND status = 'completed'",
                        (node_id,),
                    ).fetchall()
                else:
                    op_rows = conn.execute(
                        "SELECT operation_id FROM metering_operation_events WHERE status = 'completed'",
                    ).fetchall()

            for op in op_rows:
                entry = self.award_operation_credits(op["operation_id"])
                if entry:
                    results["operation_entries"] += 1
                    results["total_credits_awarded"] += entry.credit_delta

        # Reconcile all processed nodes
        for n in nodes_to_process:
            self.reconcile_balance(n)

        results["total_credits_awarded"] = round(results["total_credits_awarded"], 6)
        return results

    # -------------------------------------------------------------------------
    # 4. Calibrated Node Reputation & Trust Scoring (0 to 100)
    # -------------------------------------------------------------------------

    def calculate_node_reputation(
        self,
        node_id: str,
        window_hours: float = 168.0,  # Default 7-day rolling window
    ) -> NodeReputationRecord:
        """
        Calculates an objective, transparent reputation score from 0.0 to 100.0.
        Calibrated to avoid falsely attributing perfect 100% reliability to unobserved dimensions:
        - Unobserved dimensions (0 transfers or 0 operations) use an unbiased neutral prior (50.0).
        - Composite score normalizes across observed evidence.
        - Confidence indicator accurately reflects sample volume and duration.
        - New nodes with zero observations receive provisional status with neutral score (50.0)
          and zero confidence (0.0).
        """
        with get_db_connection(self.db_path) as conn:
            node_row = conn.execute("SELECT * FROM nodes WHERE node_id = ?", (node_id,)).fetchone()

        if not node_row:
            raise KeyError(f"Storage Node '{node_id}' not found in registry.")

        w_end = datetime.now(timezone.utc)
        w_start = w_end - timedelta(hours=window_hours)

        # 1. Availability Dimension (requires >= 2 heartbeats to establish observed duration)
        uptime = self.metering_service.calculate_node_uptime(
            node_id, window_start=w_start.isoformat(), window_end=w_end.isoformat()
        )
        hb_count = uptime.total_heartbeats_count

        if hb_count < 2:
            avail_score = 50.0  # Neutral prior for unobserved availability
            avail_observed = False
        else:
            avail_score = round(min(100.0, max(0.0, uptime.availability_percentage)), 2)
            avail_observed = True

        # 2. Integrity Dimension (requires >= 1 transfer)
        with get_db_connection(self.db_path) as conn:
            tx_stats = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_tx,
                    SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) AS success_tx
                FROM metering_transfer_events
                WHERE node_id = ? AND timestamp >= ?
                """,
                (node_id, w_start.isoformat()),
            ).fetchone()

            total_tx = int(tx_stats["total_tx"] or 0)
            success_tx = int(tx_stats["success_tx"] or 0)

        if total_tx == 0:
            integrity_score = 50.0  # Neutral prior: zero evidence is NOT 100% success
            integrity_observed = False
        else:
            integrity_score = round(min(100.0, max(0.0, (success_tx / total_tx) * 100.0)), 2)
            integrity_observed = True

        # 3. Recovery Dimension (requires >= 1 operation)
        with get_db_connection(self.db_path) as conn:
            op_stats = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_ops,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS success_ops
                FROM metering_operation_events
                WHERE (target_node_id = ? OR source_node_id = ?) AND completed_at >= ?
                """,
                (node_id, node_id, w_start.isoformat()),
            ).fetchone()

            total_ops = int(op_stats["total_ops"] or 0)
            success_ops = int(op_stats["success_ops"] or 0)

        if total_ops == 0:
            recovery_score = 50.0  # Neutral prior: zero evidence is NOT 100% success
            recovery_observed = False
        else:
            recovery_score = round(min(100.0, max(0.0, (success_ops / total_ops) * 100.0)), 2)
            recovery_observed = True

        # 4. Composite Score (0 to 100) using documented policy weights
        w_avail = self._policy.availability_weight
        w_integ = self._policy.integrity_weight
        w_recov = self._policy.recovery_weight

        composite = round(
            avail_score * w_avail + integrity_score * w_integ + recovery_score * w_recov,
            2,
        )
        composite = min(100.0, max(0.0, composite))

        # 5. Multi-factor Confidence Indicator (0.0 to 1.0)
        c_hb = min(1.0, hb_count / max(1, self._policy.min_observations_for_confidence)) if hb_count >= 2 else 0.0
        c_tx = min(1.0, total_tx / max(1, self._policy.min_transfers_for_confidence))
        c_ops = min(1.0, total_ops / 3.0)  # Requires at least 3 operations for full recovery confidence
        c_time = min(1.0, uptime.observed_online_seconds / 3600.0) if uptime.observed_online_seconds >= 60.0 else 0.0

        # Confidence evaluates evidence presence across all categories
        confidence = round(c_hb * 0.35 + c_tx * 0.30 + c_ops * 0.15 + c_time * 0.20, 2)
        confidence = min(1.0, max(0.0, confidence))

        if confidence >= 0.8:
            status_desc = "sufficient"
        elif confidence >= 0.3:
            status_desc = "provisional"
        else:
            status_desc = "insufficient"

        now_str = self._now_iso()
        metrics = {
            "heartbeat_observations": hb_count,
            "observed_online_seconds": uptime.observed_online_seconds,
            "total_transfers": total_tx,
            "successful_transfers": success_tx,
            "total_operations": total_ops,
            "successful_operations": success_ops,
            "window_hours": round(window_hours, 1),
            "availability_observed": avail_observed,
            "integrity_observed": integrity_observed,
            "recovery_observed": recovery_observed,
        }

        # Persist record in SQLite
        rec_id = f"rep-{uuid.uuid4().hex[:12]}"
        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO node_reputation_records (
                    record_id, node_id, reputation_score, availability_score,
                    integrity_score, recovery_score, confidence_indicator,
                    data_sufficiency_status, policy_version, calculated_at, metrics_summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rec_id,
                    node_id,
                    composite,
                    avail_score,
                    integrity_score,
                    recovery_score,
                    confidence,
                    status_desc,
                    self._policy.policy_version,
                    now_str,
                    json.dumps(metrics),
                ),
            )
            conn.commit()

        return NodeReputationRecord(
            node_id=node_id,
            reputation_score=composite,
            availability_score=avail_score,
            integrity_score=integrity_score,
            recovery_score=recovery_score,
            confidence_indicator=confidence,
            data_sufficiency_status=status_desc,
            policy_version=self._policy.policy_version,
            calculated_at=now_str,
            metrics_summary=metrics,
        )

    def list_node_reputations(self, window_hours: float = 168.0) -> List[NodeReputationRecord]:
        """Calculates and returns reputation records for all registered nodes."""
        with get_db_connection(self.db_path) as conn:
            rows = conn.execute("SELECT node_id FROM nodes ORDER BY node_id ASC").fetchall()

        records: List[NodeReputationRecord] = []
        for r in rows:
            rec = self.calculate_node_reputation(r["node_id"], window_hours=window_hours)
            records.append(rec)
        return records

    # -------------------------------------------------------------------------
    # 5. Cluster Accounting Summary
    # -------------------------------------------------------------------------

    def get_cluster_accounting_summary(self) -> ClusterAccountingSummary:
        """Aggregates cluster-wide credit totals, reversals, and reputation averages."""
        with get_db_connection(self.db_path) as conn:
            ledger_stats = conn.execute(
                """
                SELECT
                    COALESCE(SUM(CASE WHEN credit_micro_units > 0 THEN credit_micro_units ELSE 0 END), 0) AS issued_micro,
                    COALESCE(SUM(CASE WHEN credit_micro_units < 0 THEN ABS(credit_micro_units) ELSE 0 END), 0) AS reversed_micro,
                    COALESCE(SUM(credit_micro_units), 0) AS net_micro
                FROM credit_ledger_entries
                """
            ).fetchone()

            node_count = conn.execute("SELECT COUNT(*) AS count FROM nodes").fetchone()["count"]

        reps = self.list_node_reputations()
        avg_rep = (
            round(sum(r.reputation_score for r in reps) / len(reps), 2)
            if reps
            else 50.0
        )
        high_conf = sum(1 for r in reps if r.data_sufficiency_status == "sufficient")

        issued_float = from_micro_units(int(ledger_stats["issued_micro"]))
        reversed_float = from_micro_units(int(ledger_stats["reversed_micro"]))
        net_float = from_micro_units(int(ledger_stats["net_micro"]))

        return ClusterAccountingSummary(
            total_nodes_evaluated=node_count,
            total_credits_issued=issued_float,
            total_credits_reversed=reversed_float,
            net_cluster_credits=net_float,
            average_reputation_score=avg_rep,
            high_confidence_nodes_count=high_conf,
            policy_version=self._policy.policy_version,
        )

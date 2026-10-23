"""
SQLite database management for Expo Coordinator Service (Phase 2B).
Provides node registry database schema initialization and migrations for Internet connectivity metadata.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def get_db_connection(db_path: Path) -> sqlite3.Connection:
    """Returns SQLite database connection with row factory configured."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path) -> None:
    """Initializes the SQLite database schema for the node registry with Phase 2B migrations."""
    with get_db_connection(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                node_id TEXT PRIMARY KEY,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                endpoint TEXT NOT NULL,
                status TEXT NOT NULL,
                total_capacity_bytes INTEGER NOT NULL,
                used_capacity_bytes INTEGER NOT NULL,
                available_capacity_bytes INTEGER NOT NULL,
                last_seen TEXT NOT NULL,
                registered_at TEXT NOT NULL
            )
            """
        )
        
        # Schema migration for Phase 2B Internet connectivity columns & Phase 8A Provider management
        cursor = conn.execute("PRAGMA table_info(nodes)")
        existing_columns = [row["name"] for row in cursor.fetchall()]

        if "connectivity_mode" not in existing_columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN connectivity_mode TEXT DEFAULT 'LAN'")
        if "protocol_version" not in existing_columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN protocol_version TEXT DEFAULT '2B'")
        if "advertised_endpoint" not in existing_columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN advertised_endpoint TEXT")
        if "provider_id" not in existing_columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN provider_id TEXT DEFAULT 'default_provider'")
        if "is_schedulable" not in existing_columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN is_schedulable INTEGER DEFAULT 1")
        if "drain_status" not in existing_columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN drain_status TEXT DEFAULT 'none'")

        # Phase 10C: Node Lifecycle, Probation, Validation & Reliability columns
        if "lifecycle_state" not in existing_columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN lifecycle_state TEXT DEFAULT 'registered'")
            conn.execute("UPDATE nodes SET lifecycle_state = 'online' WHERE status = 'online'")
        if "probation_started_at" not in existing_columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN probation_started_at TEXT")
        if "promoted_at" not in existing_columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN promoted_at TEXT")
        if "health_check_success_count" not in existing_columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN health_check_success_count INTEGER DEFAULT 0")
        if "health_check_fail_count" not in existing_columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN health_check_fail_count INTEGER DEFAULT 0")
        if "consecutive_failures" not in existing_columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN consecutive_failures INTEGER DEFAULT 0")
        if "last_health_check_at" not in existing_columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN last_health_check_at TEXT")
        if "last_health_check_status" not in existing_columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN last_health_check_status TEXT")
        if "last_health_check_error" not in existing_columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN last_health_check_error TEXT")
        if "reliability_score" not in existing_columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN reliability_score REAL DEFAULT 0.0")
        if "probation_placed_bytes" not in existing_columns:
            conn.execute("ALTER TABLE nodes ADD COLUMN probation_placed_bytes INTEGER DEFAULT 0")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_nodes_provider ON nodes (provider_id)")

        # Phase 5A: Unified Storage Metadata and File Catalog
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                file_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                original_size INTEGER NOT NULL,
                status TEXT NOT NULL,
                redundancy_mode TEXT NOT NULL,
                manifest_version INTEGER NOT NULL,
                manifest_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

        # Phase 5C: Durable Cleanup and Reconciliation
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS deletion_jobs (
                job_id TEXT PRIMARY KEY,
                file_id TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                status TEXT NOT NULL,
                target_chunks TEXT NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

        # Phase 7A: Bandwidth and Capacity Metering
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS node_capacity_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                total_quota_bytes INTEGER NOT NULL,
                used_bytes INTEGER NOT NULL,
                remaining_quota_bytes INTEGER NOT NULL,
                physical_total_bytes INTEGER,
                physical_free_bytes INTEGER,
                measured_at TEXT NOT NULL,
                source TEXT NOT NULL,
                is_valid INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cap_node_measured ON node_capacity_snapshots (node_id, measured_at)"
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS metering_transfer_events (
                event_id TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                direction TEXT NOT NULL,
                operation_type TEXT NOT NULL,
                payload_bytes INTEGER NOT NULL,
                chunk_id TEXT,
                file_id TEXT,
                status TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_transfer_node_ts ON metering_transfer_events (node_id, timestamp)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_transfer_idem ON metering_transfer_events (idempotency_key)"
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS node_heartbeat_observations (
                observation_id TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                reported_status TEXT NOT NULL,
                response_time_ms REAL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hb_node_observed ON node_heartbeat_observations (node_id, observed_at)"
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS metering_operation_events (
                operation_id TEXT PRIMARY KEY,
                operation_type TEXT NOT NULL,
                source_node_id TEXT,
                target_node_id TEXT NOT NULL,
                chunk_id TEXT,
                payload_bytes INTEGER NOT NULL,
                status TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                duration_seconds REAL,
                idempotency_key TEXT NOT NULL UNIQUE
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_op_target_node ON metering_operation_events (target_node_id, completed_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_op_idem ON metering_operation_events (idempotency_key)"
        )

        # Phase 7B: Contribution Credits, Node Reputation and Trust Scoring
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS credit_ledger_entries (
                entry_id TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                category TEXT NOT NULL,
                credit_delta REAL NOT NULL,
                credit_micro_units INTEGER NOT NULL DEFAULT 0,
                event_id TEXT,
                policy_version TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                reason TEXT NOT NULL,
                audit_metadata TEXT,
                reversal_ref TEXT,
                window_start TEXT,
                window_end TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cle_node_ts ON credit_ledger_entries (node_id, timestamp)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cle_idem ON credit_ledger_entries (idempotency_key)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cle_category ON credit_ledger_entries (category)"
        )

        # Phase 7B.1 migrations for credit_ledger_entries
        cursor = conn.execute("PRAGMA table_info(credit_ledger_entries)")
        cle_cols = [row["name"] for row in cursor.fetchall()]
        if "credit_micro_units" not in cle_cols:
            conn.execute("ALTER TABLE credit_ledger_entries ADD COLUMN credit_micro_units INTEGER NOT NULL DEFAULT 0")
            conn.execute("UPDATE credit_ledger_entries SET credit_micro_units = CAST(ROUND(credit_delta * 1000000) AS INTEGER)")
        if "window_start" not in cle_cols:
            conn.execute("ALTER TABLE credit_ledger_entries ADD COLUMN window_start TEXT")
        if "window_end" not in cle_cols:
            conn.execute("ALTER TABLE credit_ledger_entries ADD COLUMN window_end TEXT")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS credit_balances (
                node_id TEXT PRIMARY KEY,
                total_credits REAL NOT NULL DEFAULT 0.0,
                total_micro_units INTEGER NOT NULL DEFAULT 0,
                lifetime_earned REAL NOT NULL DEFAULT 0.0,
                lifetime_earned_micro INTEGER NOT NULL DEFAULT 0,
                lifetime_reversed REAL NOT NULL DEFAULT 0.0,
                lifetime_reversed_micro INTEGER NOT NULL DEFAULT 0,
                last_reconciled_at TEXT NOT NULL
            )
            """
        )

        # Phase 7B.1 migrations for credit_balances
        cursor = conn.execute("PRAGMA table_info(credit_balances)")
        cb_cols = [row["name"] for row in cursor.fetchall()]
        if "total_micro_units" not in cb_cols:
            conn.execute("ALTER TABLE credit_balances ADD COLUMN total_micro_units INTEGER NOT NULL DEFAULT 0")
            conn.execute("UPDATE credit_balances SET total_micro_units = CAST(ROUND(total_credits * 1000000) AS INTEGER)")
        if "lifetime_earned_micro" not in cb_cols:
            conn.execute("ALTER TABLE credit_balances ADD COLUMN lifetime_earned_micro INTEGER NOT NULL DEFAULT 0")
            conn.execute("UPDATE credit_balances SET lifetime_earned_micro = CAST(ROUND(lifetime_earned * 1000000) AS INTEGER)")
        if "lifetime_reversed_micro" not in cb_cols:
            conn.execute("ALTER TABLE credit_balances ADD COLUMN lifetime_reversed_micro INTEGER NOT NULL DEFAULT 0")
            conn.execute("UPDATE credit_balances SET lifetime_reversed_micro = CAST(ROUND(lifetime_reversed * 1000000) AS INTEGER)")

        # Phase 7B.1: Storage accounting intervals tracking table for idempotency & overlap prevention
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS storage_accounting_intervals (
                interval_id TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                window_start TEXT NOT NULL,
                window_end TEXT NOT NULL,
                entry_id TEXT NOT NULL,
                bytes_stored INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_storage_int_node ON storage_accounting_intervals (node_id, window_start, window_end)"
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS node_reputation_records (
                record_id TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                reputation_score REAL NOT NULL,
                availability_score REAL NOT NULL,
                integrity_score REAL NOT NULL,
                recovery_score REAL NOT NULL,
                confidence_indicator REAL NOT NULL,
                data_sufficiency_status TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                calculated_at TEXT NOT NULL,
                metrics_summary TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_rep_node_calc ON node_reputation_records (node_id, calculated_at)"
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS accounting_audit_logs (
                audit_id TEXT PRIMARY KEY,
                action_type TEXT NOT NULL,
                target_id TEXT,
                actor TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details_json TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_target ON accounting_audit_logs (target_id, timestamp)"
        )

        # Phase 8B: Node Drain Jobs for Safe Lifecycle Hardening
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS node_drain_jobs (
                drain_id TEXT PRIMARY KEY,
                node_id TEXT NOT NULL UNIQUE,
                provider_id TEXT NOT NULL,
                status TEXT NOT NULL,
                total_chunks INTEGER NOT NULL DEFAULT 0,
                migrated_chunks INTEGER NOT NULL DEFAULT 0,
                remaining_chunks INTEGER NOT NULL DEFAULT 0,
                failed_chunks INTEGER NOT NULL DEFAULT 0,
                reason TEXT,
                started_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_drain_node ON node_drain_jobs (node_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_drain_provider ON node_drain_jobs (provider_id)"
        )

        # Phase 8B: Explicit Provider Credentials & Role Separation
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_credentials (
                credential_id TEXT PRIMARY KEY,
                principal_id TEXT UNIQUE NOT NULL,
                provider_id TEXT NOT NULL,
                secret_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cred_principal ON provider_credentials (principal_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cred_provider ON provider_credentials (provider_id)")

        # Phase 8B: Provider Web Dashboard Hashed Sessions & CSRF Tokens
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_sessions (
                session_hash TEXT PRIMARY KEY,
                provider_id TEXT NOT NULL,
                csrf_token TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_accessed_at TEXT NOT NULL
            )
            """
        )
        # Migrate session_id to session_hash if upgrading an older schema
        cursor_sess = conn.execute("PRAGMA table_info(provider_sessions)")
        sess_cols = [row["name"] for row in cursor_sess.fetchall()]
        if sess_cols and "session_hash" not in sess_cols and "session_id" in sess_cols:
            conn.execute("ALTER TABLE provider_sessions RENAME COLUMN session_id TO session_hash")

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_session_provider ON provider_sessions (provider_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_session_expires ON provider_sessions (expires_at)"
        )

        # Phase 8C: Durable Node Drain Chunk & Shard Migrations
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS node_drain_migrations (
                migration_id TEXT PRIMARY KEY,
                drain_id TEXT NOT NULL,
                file_id TEXT NOT NULL,
                chunk_id TEXT NOT NULL,
                shard_index INTEGER,
                source_node_id TEXT NOT NULL,
                destination_node_id TEXT,
                status TEXT NOT NULL,
                retry_count INTEGER NOT NULL DEFAULT 0,
                max_retries INTEGER NOT NULL DEFAULT 3,
                last_error TEXT,
                payload_bytes INTEGER NOT NULL DEFAULT 0,
                sha256_checksum TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY (drain_id) REFERENCES node_drain_jobs(drain_id)
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_mig_drain ON node_drain_migrations (drain_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_mig_status ON node_drain_migrations (status)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_mig_source ON node_drain_migrations (source_node_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_mig_dest ON node_drain_migrations (destination_node_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_mig_chunk ON node_drain_migrations (file_id, chunk_id, shard_index)"
        )

        # Phase 10A: Distinct Account Identities, Roles & Sessions
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                account_id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'consumer',
                capabilities TEXT NOT NULL DEFAULT 'consumer',
                status TEXT NOT NULL DEFAULT 'active',
                provider_id TEXT,
                email_verified INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_accounts_email ON accounts (email)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_accounts_provider ON accounts (provider_id)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS account_sessions (
                session_hash TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL,
                provider_id TEXT,
                csrf_token TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_accessed_at TEXT NOT NULL,
                FOREIGN KEY (account_id) REFERENCES accounts(account_id)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_acc_sess_account ON account_sessions (account_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_acc_sess_expires ON account_sessions (expires_at)")

        # Phase 10A migrations: link account_id on provider_credentials and provider_sessions if missing
        cursor_pc = conn.execute("PRAGMA table_info(provider_credentials)")
        pc_cols = [row["name"] for row in cursor_pc.fetchall()]
        if "account_id" not in pc_cols:
            conn.execute("ALTER TABLE provider_credentials ADD COLUMN account_id TEXT")

        cursor_ps = conn.execute("PRAGMA table_info(provider_sessions)")
        ps_cols = [row["name"] for row in cursor_ps.fetchall()]
        if "account_id" not in ps_cols:
            conn.execute("ALTER TABLE provider_sessions ADD COLUMN account_id TEXT")

        # Phase 10C: Provider Onboarding Consent and Status Table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_onboarding (
                provider_id TEXT PRIMARY KEY,
                account_id TEXT,
                terms_version TEXT NOT NULL,
                terms_accepted_at TEXT NOT NULL,
                accepted_at TEXT,
                is_verified INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_onboard_account ON provider_onboarding (account_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_onboard_status ON provider_onboarding (status)")

        cursor_po = conn.execute("PRAGMA table_info(provider_onboarding)")
        po_cols = [row["name"] for row in cursor_po.fetchall()]
        if "accepted_at" not in po_cols:
            conn.execute("ALTER TABLE provider_onboarding ADD COLUMN accepted_at TEXT")
        if "terms_accepted_at" not in po_cols:
            conn.execute("ALTER TABLE provider_onboarding ADD COLUMN terms_accepted_at TEXT")
        if "is_verified" not in po_cols:
            conn.execute("ALTER TABLE provider_onboarding ADD COLUMN is_verified INTEGER NOT NULL DEFAULT 1")

        # Phase 10C: Node Validation Audit Records Table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS node_validation_records (
                validation_id TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                status TEXT NOT NULL,
                checks_performed TEXT NOT NULL,
                details_json TEXT,
                failure_reason TEXT,
                performed_at TEXT NOT NULL,
                duration_ms REAL,
                FOREIGN KEY (node_id) REFERENCES nodes(node_id)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_val_node ON node_validation_records (node_id, performed_at)")

        # Phase 10D: Account Storage Quotas and Upload Reservations
        cursor_acc = conn.execute("PRAGMA table_info(accounts)")
        acc_cols = [row["name"] for row in cursor_acc.fetchall()]
        if "quota_bytes" not in acc_cols:
            conn.execute("ALTER TABLE accounts ADD COLUMN quota_bytes INTEGER NOT NULL DEFAULT 10737418240")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS account_quota_reservations (
                reservation_id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                file_id TEXT,
                reserved_bytes INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active'
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_quota_res_account ON account_quota_reservations (account_id, status, expires_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_quota_res_file ON account_quota_reservations (file_id)")

        # Phase 10E: Email/SMS Verification, Password Reset Tokens & Rate Limits
        if "email_verified_at" not in acc_cols:
            conn.execute("ALTER TABLE accounts ADD COLUMN email_verified_at TEXT")
        if "phone_number" not in acc_cols:
            conn.execute("ALTER TABLE accounts ADD COLUMN phone_number TEXT")
        if "phone_verified" not in acc_cols:
            conn.execute("ALTER TABLE accounts ADD COLUMN phone_verified INTEGER NOT NULL DEFAULT 0")
        if "phone_verified_at" not in acc_cols:
            conn.execute("ALTER TABLE accounts ADD COLUMN phone_verified_at TEXT")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS account_verification_tokens (
                token_hash TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                target TEXT NOT NULL,
                token_type TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL DEFAULT 5,
                last_attempt_at TEXT,
                ip_address TEXT,
                FOREIGN KEY (account_id) REFERENCES accounts(account_id)
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tok_acc_type ON account_verification_tokens (account_id, token_type, used_at, expires_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tok_target_type ON account_verification_tokens (target, token_type)"
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS verification_rate_limits (
                limit_id TEXT PRIMARY KEY,
                identifier TEXT NOT NULL,
                action_type TEXT NOT NULL,
                attempted_at TEXT NOT NULL,
                ip_address TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vrl_ident_action ON verification_rate_limits (identifier, action_type, attempted_at)"
        )

        # Phase 10F: Administrative Audit Log & Observability
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_audit_log (
                audit_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                admin_account_id TEXT NOT NULL,
                admin_email TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                details_json TEXT,
                ip_address TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON admin_audit_log (timestamp DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_admin ON admin_audit_log (admin_account_id, timestamp DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_target ON admin_audit_log (target_type, target_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts (status)"
        )

        conn.commit()


def record_audit_event(
    db_path: Path,
    admin_account_id: str,
    admin_email: str,
    action: str,
    target_type: str,
    target_id: str,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
) -> str:
    """Records an administrative action in the durable audit log (Phase 10F)."""
    audit_id = str(uuid.uuid4())
    now_str = datetime.now(timezone.utc).isoformat()
    details_str = json.dumps(details) if details else None
    with get_db_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO admin_audit_log (
                audit_id, timestamp, admin_account_id, admin_email,
                action, target_type, target_id, details_json, ip_address
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit_id,
                now_str,
                admin_account_id,
                admin_email,
                action,
                target_type,
                target_id,
                details_str,
                ip_address,
            ),
        )
        conn.commit()
    return audit_id


def get_audit_events(
    db_path: Path,
    limit: int = 50,
    offset: int = 0,
    action: Optional[str] = None,
    admin_id: Optional[str] = None,
) -> Tuple[int, List[Dict[str, Any]]]:
    """Retrieves paginated and bounded audit events from the audit log (Phase 10F)."""
    safe_limit = max(1, min(100, int(limit)))
    safe_offset = max(0, int(offset))

    where_clauses = []
    params: List[Any] = []

    if action and action.strip():
        where_clauses.append("action = ?")
        params.append(action.strip())

    if admin_id and admin_id.strip():
        where_clauses.append("(admin_account_id = ? OR admin_email = ?)")
        params.extend([admin_id.strip(), admin_id.strip()])

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    with get_db_connection(db_path) as conn:
        count_cursor = conn.execute(
            f"SELECT COUNT(*) AS total FROM admin_audit_log {where_sql}",
            params,
        )
        total = count_cursor.fetchone()["total"]

        query_sql = f"""
            SELECT * FROM admin_audit_log
            {where_sql}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        rows = conn.execute(query_sql, params + [safe_limit, safe_offset]).fetchall()

        events = []
        for r in rows:
            parsed_details = None
            if r["details_json"]:
                try:
                    parsed_details = json.loads(r["details_json"])
                except Exception:
                    parsed_details = {"raw": r["details_json"]}
            events.append(
                {
                    "audit_id": r["audit_id"],
                    "timestamp": r["timestamp"],
                    "admin_account_id": r["admin_account_id"],
                    "admin_email": r["admin_email"],
                    "action": r["action"],
                    "target_type": r["target_type"],
                    "target_id": r["target_id"],
                    "details": parsed_details,
                    "ip_address": r["ip_address"],
                }
            )

        return total, events


def reassign_legacy_file_ownership(db_path: Path, legacy_owner_id: str, target_account_id: str) -> int:
    """
    Safely reassigns logical files from a legacy owner_id (e.g. a shared development token)
    to a verified target account UUID. Preserves all manifests, encryption keys, and chunk records.
    Returns the count of reassigned files.
    """
    if not legacy_owner_id or not target_account_id:
        raise ValueError("Both legacy_owner_id and target_account_id must be non-empty strings.")

    now_str = datetime.now(timezone.utc).isoformat()
    with get_db_connection(db_path) as conn:
        cursor = conn.execute(
            "UPDATE files SET owner_id = ?, updated_at = ? WHERE owner_id = ?",
            (target_account_id.strip(), now_str, legacy_owner_id.strip())
        )
        conn.commit()
        return cursor.rowcount

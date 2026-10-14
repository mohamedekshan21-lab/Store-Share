"""
SQLite database management for Expo Coordinator Service (Phase 2B).
Provides node registry database schema initialization and migrations for Internet connectivity metadata.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path


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

        conn.commit()


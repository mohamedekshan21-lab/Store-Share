"""
Phase 4B Automatic Repair & Self-Healing Subsystem for Expo Distributed Storage.
Provides chunk health inspection, under-replication detection, per-chunk locking,
idempotent repair worker execution, bounded retries, and SQLite job persistence.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from pydantic import BaseModel, Field

from client.chunker import FileManifest, ChunkMetadata, ChunkPlacement, ShardMetadata, compute_sha256
from client.client import ExpoClient, ClientError, IntegrityVerificationError
from client.placement import select_nodes_for_placement, check_node_reachability
from client.erasure import encode_ciphertext_chunk, reconstruct_ciphertext_chunk

logger = logging.getLogger("expo_repair")


class RepairState:
    """Repair job & chunk health state constants."""
    HEALTHY = "HEALTHY"
    UNDER_REPLICATED = "UNDER_REPLICATED"
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    REPAIRING = "REPAIRING"
    REPAIRED = "REPAIRED"
    SUCCEEDED = "SUCCEEDED"
    REPAIR_FAILED = "REPAIR_FAILED"
    RETRY_WAIT = "RETRY_WAIT"
    UNRECOVERABLE = "UNRECOVERABLE"


class RepairJob(BaseModel):
    """Persistent model representing an individual chunk repair job."""
    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file_id: str = Field(..., description="Target file UUID")
    chunk_id: str = Field(..., description="Target chunk UUID")
    sequence: int = Field(default=0, description="Chunk sequence index")
    required_replication_factor: int = Field(default=2, description="Configured replication factor")
    source_node_id: Optional[str] = Field(None, description="Selected healthy source Storage Node ID")
    source_node_endpoint: Optional[str] = Field(None, description="Source Storage Node endpoint URL")
    destination_node_id: Optional[str] = Field(None, description="Replacement Storage Node ID")
    destination_node_endpoint: Optional[str] = Field(None, description="Replacement Storage Node endpoint URL")
    state: str = Field(default=RepairState.PENDING if hasattr(RepairState, "PENDING") else "PENDING", description="Job execution state")
    attempt_count: int = Field(default=0, description="Current attempt number")
    max_attempts: int = Field(default=3, description="Maximum allowed repair retries")
    last_error: Optional[str] = Field(None, description="Last error message if failed")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = Field(None, description="Completion ISO timestamp")


class RepairJobStore:
    """SQLite-backed persistent store for RepairJob records."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        if self.db_path == ":memory:":
            self._persistent_conn: Optional[sqlite3.Connection] = sqlite3.connect(":memory:", check_same_thread=False)
            self._persistent_conn.row_factory = sqlite3.Row
        else:
            self._persistent_conn = None
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._persistent_conn is not None:
            return self._persistent_conn
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_connection()
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS repair_jobs (
                    job_id TEXT PRIMARY KEY,
                    file_id TEXT NOT NULL,
                    chunk_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    required_replication_factor INTEGER NOT NULL,
                    source_node_id TEXT,
                    source_node_endpoint TEXT,
                    destination_node_id TEXT,
                    destination_node_endpoint TEXT,
                    state TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL,
                    max_attempts INTEGER NOT NULL,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_repair_file ON repair_jobs (file_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_repair_chunk ON repair_jobs (chunk_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_repair_state ON repair_jobs (state);")
            conn.commit()
            if self._persistent_conn is None:
                conn.close()

    def create_job(self, job: RepairJob) -> RepairJob:
        with self._lock:
            conn = self._get_connection()
            conn.execute(
                """
                INSERT OR REPLACE INTO repair_jobs (
                    job_id, file_id, chunk_id, sequence, required_replication_factor,
                    source_node_id, source_node_endpoint, destination_node_id, destination_node_endpoint,
                    state, attempt_count, max_attempts, last_error, created_at, updated_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    job.job_id,
                    job.file_id,
                    job.chunk_id,
                    job.sequence,
                    job.required_replication_factor,
                    job.source_node_id,
                    job.source_node_endpoint,
                    job.destination_node_id,
                    job.destination_node_endpoint,
                    job.state,
                    job.attempt_count,
                    job.max_attempts,
                    job.last_error,
                    job.created_at,
                    job.updated_at,
                    job.completed_at,
                ),
            )
            conn.commit()
            if self._persistent_conn is None:
                conn.close()
        return job

    def get_job(self, job_id: str) -> Optional[RepairJob]:
        with self._lock:
            conn = self._get_connection()
            row = conn.execute("SELECT * FROM repair_jobs WHERE job_id = ?", (job_id,)).fetchone()
            if self._persistent_conn is None:
                conn.close()
            if row:
                return RepairJob(**dict(row))
        return None

    def get_job_by_chunk(self, chunk_id: str) -> Optional[RepairJob]:
        with self._lock:
            conn = self._get_connection()
            row = conn.execute("SELECT * FROM repair_jobs WHERE chunk_id = ? ORDER BY created_at DESC LIMIT 1", (chunk_id,)).fetchone()
            if self._persistent_conn is None:
                conn.close()
            if row:
                return RepairJob(**dict(row))
        return None

    def list_jobs(self, state: Optional[str] = None, file_id: Optional[str] = None) -> List[RepairJob]:
        query = "SELECT * FROM repair_jobs WHERE 1=1"
        params: List[Any] = []
        if state:
            query += " AND state = ?"
            params.append(state)
        if file_id:
            query += " AND file_id = ?"
            params.append(file_id)
        query += " ORDER BY created_at DESC"

        with self._lock:
            conn = self._get_connection()
            rows = conn.execute(query, params).fetchall()
            if self._persistent_conn is None:
                conn.close()
            return [RepairJob(**dict(r)) for r in rows]

    def update_job(self, job: RepairJob) -> RepairJob:
        job.updated_at = datetime.now(timezone.utc).isoformat()
        return self.create_job(job)


class RepairLockManager:
    """Thread-safe per-chunk locking mechanism to prevent duplicate concurrent repair execution."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active_chunks: Set[str] = set()

    def acquire_lock(self, chunk_id: str) -> bool:
        with self._lock:
            if chunk_id in self._active_chunks:
                return False
            self._active_chunks.add(chunk_id)
            return True

    def release_lock(self, chunk_id: str) -> None:
        with self._lock:
            self._active_chunks.discard(chunk_id)

    def is_locked(self, chunk_id: str) -> bool:
        with self._lock:
            return chunk_id in self._active_chunks


def _download_chunk_from_endpoint(
    client: ExpoClient,
    chunk_id: str,
    n_endpoint: Optional[str],
    node_id: Optional[str] = None,
    coordinator_url: Optional[str] = None,
    capability_token: Optional[str] = None,
) -> bytes:
    """Safely downloads chunk bytes from a specific node endpoint, preserving client.base_url."""
    if not n_endpoint or n_endpoint == getattr(client, "base_url", None) or hasattr(client, "nodes_info") or hasattr(client, "node_map") or type(client) is not ExpoClient:
        orig_url = getattr(client, "base_url", None)
        try:
            if n_endpoint:
                client.base_url = n_endpoint
            if capability_token:
                try:
                    return client.download_chunk_bytes(chunk_id, capability_token=capability_token)
                except TypeError:
                    return client.download_chunk_bytes(chunk_id)
            return client.download_chunk_bytes(chunk_id)
        finally:
            if orig_url is not None:
                client.base_url = orig_url
    else:
        if node_id and hasattr(client, "get_node_client"):
            node_client = client.get_node_client(node_id, endpoint=n_endpoint, coordinator_url=coordinator_url)
        else:
            node_client = ExpoClient(node_url=n_endpoint, auth_token=client.auth_token, timeout=client.timeout)
        if capability_token:
            try:
                return node_client.download_chunk_bytes(chunk_id, capability_token=capability_token)
            except TypeError:
                return node_client.download_chunk_bytes(chunk_id)
        return node_client.download_chunk_bytes(chunk_id)


def _upload_chunk_to_endpoint(
    client: ExpoClient,
    chunk_bytes: bytes,
    opaque_filename: str,
    n_endpoint: Optional[str],
    node_id: Optional[str] = None,
    coordinator_url: Optional[str] = None,
    capability_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Safely uploads chunk bytes to a specific node endpoint, preserving client.base_url."""
    if not n_endpoint or n_endpoint == getattr(client, "base_url", None) or hasattr(client, "nodes_info") or hasattr(client, "node_map") or type(client) is not ExpoClient:
        orig_url = getattr(client, "base_url", None)
        try:
            if n_endpoint:
                client.base_url = n_endpoint
            if capability_token:
                try:
                    return client.upload_chunk_bytes(chunk_bytes, opaque_filename, capability_token=capability_token)
                except TypeError:
                    return client.upload_chunk_bytes(chunk_bytes, opaque_filename)
            return client.upload_chunk_bytes(chunk_bytes, opaque_filename)
        finally:
            if orig_url is not None:
                client.base_url = orig_url
    else:
        if node_id and hasattr(client, "get_node_client"):
            node_client = client.get_node_client(node_id, endpoint=n_endpoint, coordinator_url=coordinator_url)
        else:
            node_client = ExpoClient(node_url=n_endpoint, auth_token=client.auth_token, timeout=client.timeout)
        if capability_token:
            try:
                return node_client.upload_chunk_bytes(chunk_bytes, opaque_filename, capability_token=capability_token)
            except TypeError:
                return node_client.upload_chunk_bytes(chunk_bytes, opaque_filename)
        return node_client.upload_chunk_bytes(chunk_bytes, opaque_filename)


def _delete_file_from_endpoint(
    client: ExpoClient,
    file_id: str,
    n_endpoint: Optional[str],
    node_id: Optional[str] = None,
    coordinator_url: Optional[str] = None,
    capability_token: Optional[str] = None,
) -> None:
    """Safely deletes a chunk from a specific node endpoint, preserving client.base_url."""
    if not n_endpoint or n_endpoint == getattr(client, "base_url", None) or hasattr(client, "nodes_info") or hasattr(client, "node_map") or type(client) is not ExpoClient:
        orig_url = getattr(client, "base_url", None)
        try:
            if n_endpoint:
                client.base_url = n_endpoint
            if capability_token:
                try:
                    client.delete_file(file_id, capability_token=capability_token)
                except TypeError:
                    client.delete_file(file_id)
            else:
                client.delete_file(file_id)
        finally:
            if orig_url is not None:
                client.base_url = orig_url
    else:
        if node_id and hasattr(client, "get_node_client"):
            node_client = client.get_node_client(node_id, endpoint=n_endpoint, coordinator_url=coordinator_url)
        else:
            node_client = ExpoClient(node_url=n_endpoint, auth_token=client.auth_token, timeout=client.timeout)
        if capability_token:
            try:
                node_client.delete_file(file_id, capability_token=capability_token)
            except TypeError:
                node_client.delete_file(file_id)
        else:
            node_client.delete_file(file_id)



class ChunkHealthInfo(BaseModel):
    """Diagnostic health result for an individual chunk across all placements."""
    chunk_id: str
    sequence: int
    required_replication_factor: int
    healthy_placements: List[ChunkPlacement] = Field(default_factory=list)
    corrupt_placements: List[ChunkPlacement] = Field(default_factory=list)
    unreachable_placements: List[ChunkPlacement] = Field(default_factory=list)
    state: str = RepairState.HEALTHY


class ManifestHealthSummary(BaseModel):
    """Diagnostic health summary for a file manifest."""
    file_id: str
    original_filename: str
    chunk_count: int
    replication_factor: int
    healthy_chunks_count: int
    under_replicated_chunks_count: int
    unrecoverable_chunks_count: int
    chunk_reports: List[ChunkHealthInfo] = Field(default_factory=list)


class RepairEngine:
    """
    Core Phase 4B Automatic Repair & Self-Healing Engine.
    Orchestrates health inspections, under-replication detection, source/destination selection,
    ciphertext downloads/uploads, SHA-256 verification, atomic metadata updates, and retries.
    """

    def __init__(
        self,
        job_store: Optional[RepairJobStore] = None,
        lock_manager: Optional[RepairLockManager] = None,
        max_concurrent_jobs: int = 4,
        max_retries: int = 3,
        retry_backoff_seconds: float = 0.0,
    ) -> None:
        self.job_store = job_store or RepairJobStore()
        self.lock_manager = lock_manager or RepairLockManager()
        self.max_concurrent_jobs = max_concurrent_jobs
        self.max_retries = max_retries
        self.retry_backoff_seconds = retry_backoff_seconds

    def inspect_chunk_health(
        self,
        chunk_meta: ChunkMetadata,
        replication_factor: int,
        client: Optional[ExpoClient] = None,
        coordinator_url: Optional[str] = None,
    ) -> ChunkHealthInfo:
        """Probes each placement or shard of a chunk to verify node reachability and SHA-256 data integrity."""
        base_client = client or ExpoClient()

        if chunk_meta.shards:
            # Erasure Coding Chunk Health Inspection
            k = chunk_meta.data_shard_count or 4
            m = chunk_meta.parity_shard_count or 2
            total_shards = k + m

            healthy_placements: List[ChunkPlacement] = []
            corrupt_placements: List[ChunkPlacement] = []
            unreachable_placements: List[ChunkPlacement] = []

            for s_meta in chunk_meta.shards:
                n_endpoint = s_meta.node_endpoint
                if not n_endpoint and coordinator_url:
                    try:
                        from coordinator.coordinator_client import CoordinatorClient
                        coord_client = CoordinatorClient(coordinator_url=coordinator_url, timeout=base_client.timeout)
                        rec = coord_client.get_node(s_meta.node_id)
                        n_endpoint = rec.get("advertised_endpoint") or rec.get("endpoint")
                    except Exception:
                        n_endpoint = None

                p_rep = ChunkPlacement(
                    node_id=s_meta.node_id,
                    node_endpoint=n_endpoint or base_client.base_url,
                    role=f"SHARD-{s_meta.shard_index}",
                )

                try:
                    shard_bytes = _download_chunk_from_endpoint(
                        base_client, s_meta.shard_id, n_endpoint, node_id=s_meta.node_id, coordinator_url=coordinator_url
                    )
                    computed_hash = compute_sha256(shard_bytes)
                    if computed_hash == s_meta.shard_sha256.lower():
                        healthy_placements.append(p_rep)
                    else:
                        corrupt_placements.append(p_rep)
                except Exception:
                    unreachable_placements.append(p_rep)

            if len(healthy_placements) >= total_shards:
                state = RepairState.HEALTHY
            elif len(healthy_placements) >= k:
                state = RepairState.UNDER_REPLICATED
            else:
                state = RepairState.UNRECOVERABLE

            return ChunkHealthInfo(
                chunk_id=chunk_meta.chunk_id,
                sequence=chunk_meta.sequence,
                required_replication_factor=total_shards,
                healthy_placements=healthy_placements,
                corrupt_placements=corrupt_placements,
                unreachable_placements=unreachable_placements,
                state=state,
            )

        # Standard Replication Chunk Health Inspection
        placements = chunk_meta.get_effective_placements()

        healthy: List[ChunkPlacement] = []
        corrupt: List[ChunkPlacement] = []
        unreachable: List[ChunkPlacement] = []

        for p in placements:
            n_endpoint = p.node_endpoint
            if not n_endpoint and coordinator_url:
                try:
                    from coordinator.coordinator_client import CoordinatorClient
                    coord_client = CoordinatorClient(coordinator_url=coordinator_url, timeout=base_client.timeout)
                    rec = coord_client.get_node(p.node_id)
                    n_endpoint = rec.get("advertised_endpoint") or rec.get("endpoint")
                except Exception:
                    n_endpoint = None

            try:
                chunk_bytes = _download_chunk_from_endpoint(
                    base_client, chunk_meta.chunk_id, n_endpoint, node_id=p.node_id, coordinator_url=coordinator_url
                )

                computed_hash = compute_sha256(chunk_bytes)
                if computed_hash == chunk_meta.sha256.lower():
                    healthy.append(p)
                else:
                    corrupt.append(p)
            except Exception:
                unreachable.append(p)

        if len(healthy) >= replication_factor:
            state = RepairState.HEALTHY
        elif len(healthy) > 0:
            state = RepairState.UNDER_REPLICATED
        else:
            state = RepairState.UNRECOVERABLE

        return ChunkHealthInfo(
            chunk_id=chunk_meta.chunk_id,
            sequence=chunk_meta.sequence,
            required_replication_factor=replication_factor,
            healthy_placements=healthy,
            corrupt_placements=corrupt,
            unreachable_placements=unreachable,
            state=state,
        )

    def inspect_manifest_health(
        self,
        manifest: FileManifest,
        client: Optional[ExpoClient] = None,
        coordinator_url: Optional[str] = None,
    ) -> ManifestHealthSummary:
        """Inspects all chunks in a FileManifest and returns a comprehensive health summary."""
        reports: List[ChunkHealthInfo] = []
        healthy_cnt = 0
        under_rep_cnt = 0
        unrec_cnt = 0

        req_rep = manifest.total_shards if manifest.redundancy_mode == "erasure" else manifest.replication_factor

        for chunk_meta in manifest.chunks:
            rep = self.inspect_chunk_health(
                chunk_meta=chunk_meta,
                replication_factor=req_rep,
                client=client,
                coordinator_url=coordinator_url,
            )
            reports.append(rep)

            if rep.state == RepairState.HEALTHY:
                healthy_cnt += 1
            elif rep.state == RepairState.UNDER_REPLICATED:
                under_rep_cnt += 1
            elif rep.state == RepairState.UNRECOVERABLE:
                unrec_cnt += 1

        return ManifestHealthSummary(
            file_id=manifest.file_id,
            original_filename=manifest.original_filename,
            chunk_count=len(manifest.chunks),
            replication_factor=manifest.replication_factor,
            healthy_chunks_count=healthy_cnt,
            under_replicated_chunks_count=under_rep_cnt,
            unrecoverable_chunks_count=unrec_cnt,
            chunk_reports=reports,
        )

    def _repair_erasure_coded_chunk(
        self,
        manifest: FileManifest,
        chunk_meta: ChunkMetadata,
        client: ExpoClient,
        job: RepairJob,
        coordinator_url: str = "http://127.0.0.1:9000",
        candidate_nodes: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[ChunkMetadata, RepairJob]:
        """Executes idempotent repair for a single under-sharded erasure-coded chunk."""
        k = chunk_meta.data_shard_count or manifest.data_shards or 4
        m = chunk_meta.parity_shard_count or manifest.parity_shards or 2
        total_shards = k + m
        padlen = chunk_meta.padding_length if chunk_meta.padding_length is not None else 0
        orig_c_size = chunk_meta.original_ciphertext_size or chunk_meta.size

        # Probe current shard health
        healthy_shards: List[Tuple[int, bytes, ShardMetadata]] = []
        missing_or_corrupt_shards: List[ShardMetadata] = []

        for s_meta in chunk_meta.shards:
            n_endpoint = s_meta.node_endpoint
            if not n_endpoint and coordinator_url:
                try:
                    from coordinator.coordinator_client import CoordinatorClient
                    coord_client = CoordinatorClient(coordinator_url=coordinator_url, timeout=client.timeout)
                    rec = coord_client.get_node(s_meta.node_id)
                    n_endpoint = rec.get("advertised_endpoint") or rec.get("endpoint")
                except Exception:
                    n_endpoint = None

            try:
                shard_bytes = _download_chunk_from_endpoint(
                    client, s_meta.shard_id, n_endpoint, node_id=s_meta.node_id, coordinator_url=coordinator_url
                )
                computed_hash = compute_sha256(shard_bytes)
                if computed_hash == s_meta.shard_sha256.lower():
                    healthy_shards.append((s_meta.shard_index, shard_bytes, s_meta))
                else:
                    missing_or_corrupt_shards.append(s_meta)
            except Exception:
                missing_or_corrupt_shards.append(s_meta)

        # 1. Idempotency Check: Already healthy?
        if len(healthy_shards) >= total_shards:
            job.state = RepairState.SUCCEEDED
            job.completed_at = datetime.now(timezone.utc).isoformat()
            self.job_store.update_job(job)
            logger.info(f"Erasure-coded chunk '{chunk_meta.chunk_id}' already has {len(healthy_shards)} healthy shards. Repair skipped.")
            return chunk_meta, job

        # 2. Check Unrecoverable State (< k healthy shards)
        if len(healthy_shards) < k:
            job.state = RepairState.UNRECOVERABLE
            job.last_error = f"Insufficient valid shards ({len(healthy_shards)}) to reconstruct chunk (minimum {k} required)."
            self.job_store.update_job(job)
            logger.error(f"Repair impossible for erasure-coded chunk '{chunk_meta.chunk_id}': {job.last_error}")
            return chunk_meta, job

        # 3. Reconstruct original ciphertext chunk payload from healthy shards
        reconstr_shards_input = [(idx, b) for idx, b, _ in healthy_shards]
        try:
            reconstructed_c_bytes = reconstruct_ciphertext_chunk(
                available_shards=reconstr_shards_input,
                data_shards=k,
                parity_shards=m,
                padding_length=padlen,
                original_ciphertext_size=orig_c_size,
            )
        except Exception as exc:
            job.state = RepairState.REPAIR_FAILED
            job.last_error = f"Reconstruction failed during repair: {str(exc)}"
            self.job_store.update_job(job)
            raise IntegrityVerificationError(job.last_error) from exc

        # 4. Re-encode ciphertext chunk payload to obtain all missing shard byte payloads
        re_encoded_shards, _, _, _ = encode_ciphertext_chunk(reconstructed_c_bytes, k, m)
        re_encoded_by_index = {s.shard_index: s for s in re_encoded_shards}

        existing_node_ids = {s_meta.node_id for _, _, s_meta in healthy_shards}

        # 5. Repair each missing/corrupted shard onto a distinct replacement Storage Node
        for missing_meta in missing_or_corrupt_shards:
            target_idx = missing_meta.shard_index
            re_shard = re_encoded_by_index[target_idx]

            # Discover replacement node not holding any healthy shard of this chunk
            eligible_nodes: List[Dict[str, Any]] = []
            if candidate_nodes is not None:
                eligible_nodes = [n for n in candidate_nodes if n.get("node_id") not in existing_node_ids]
            elif coordinator_url:
                try:
                    from coordinator.coordinator_client import CoordinatorClient
                    coord_client = CoordinatorClient(coordinator_url=coordinator_url, timeout=client.timeout)
                    all_nodes = coord_client.list_nodes(status="online", min_available_bytes=len(re_shard.payload))
                    eligible_nodes = [n for n in all_nodes if n.get("node_id") not in existing_node_ids]
                except Exception as exc:
                    logger.warning(f"Failed to discover destination nodes via Coordinator: {str(exc)}")

            if not eligible_nodes:
                job.state = RepairState.RETRY_WAIT
                job.last_error = f"No eligible destination Storage Node available for shard index {target_idx}."
                self.job_store.update_job(job)
                raise ClientError(job.last_error)

            dest_node = eligible_nodes[0]
            dest_node_id = dest_node.get("node_id")
            dest_endpoint = dest_node.get("advertised_endpoint") or dest_node.get("endpoint")

            job.destination_node_id = dest_node_id
            job.destination_node_endpoint = dest_endpoint
            self.job_store.update_job(job)

            # Upload replacement shard to destination node
            opaque_filename = f"{missing_meta.shard_id}.dat"
            upload_meta = _upload_chunk_to_endpoint(
                client, re_shard.payload, opaque_filename, dest_endpoint, node_id=dest_node_id, coordinator_url=coordinator_url
            )
            stored_file_id = upload_meta.get("file_id", missing_meta.shard_id)

            # Verify destination copy SHA-256 integrity
            verify_bytes = _download_chunk_from_endpoint(
                client, stored_file_id, dest_endpoint, node_id=dest_node_id, coordinator_url=coordinator_url
            )
            if compute_sha256(verify_bytes) != re_shard.sha256.lower():
                job.state = RepairState.REPAIR_FAILED
                job.last_error = f"Destination node '{dest_node_id}' stored shard payload failed SHA-256 verification."
                self.job_store.update_job(job)
                try:
                    _delete_file_from_endpoint(
                        client, stored_file_id, dest_endpoint, node_id=dest_node_id, coordinator_url=coordinator_url
                    )
                except Exception:
                    pass
                raise IntegrityVerificationError(job.last_error)


            # Atomically update shard placement metadata
            missing_meta.node_id = dest_node_id
            missing_meta.node_endpoint = dest_endpoint
            missing_meta.shard_size = len(re_shard.payload)
            missing_meta.shard_sha256 = re_shard.sha256
            existing_node_ids.add(dest_node_id)

        job.state = RepairState.SUCCEEDED
        job.completed_at = datetime.now(timezone.utc).isoformat()
        job.last_error = None
        self.job_store.update_job(job)

        logger.info(f"Erasure-coded chunk '{chunk_meta.chunk_id}' successfully repaired across replacement nodes!")
        return chunk_meta, job

    def repair_under_replicated_chunk(
        self,
        manifest: FileManifest,
        chunk_meta: ChunkMetadata,
        client: ExpoClient,
        coordinator_url: str = "http://127.0.0.1:9000",
        candidate_nodes: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[ChunkMetadata, RepairJob]:
        """
        Executes idempotent repair for a single under-replicated or under-sharded chunk:
        1. Obtains per-chunk repair lock.
        2. Routes to erasure-coded repair path if manifest.redundancy_mode == 'erasure' or chunk_meta.shards present.
        3. Otherwise executes replication repair algorithm.
        """
        chunk_id = chunk_meta.chunk_id
        if not self.lock_manager.acquire_lock(chunk_id):
            job = self.job_store.get_job_by_chunk(chunk_id) or RepairJob(
                file_id=manifest.file_id,
                chunk_id=chunk_id,
                sequence=chunk_meta.sequence,
                required_replication_factor=manifest.replication_factor,
                state=RepairState.REPAIRING,
                last_error="Repair job currently locked by another worker.",
            )
            return chunk_meta, job

        job: Optional[RepairJob] = None
        try:
            # Create or resume repair job record
            existing_job = self.job_store.get_job_by_chunk(chunk_id)
            if not existing_job or existing_job.state in (RepairState.SUCCEEDED, RepairState.REPAIRED):
                job = RepairJob(
                    file_id=manifest.file_id,
                    chunk_id=chunk_id,
                    sequence=chunk_meta.sequence,
                    required_replication_factor=manifest.replication_factor if manifest.redundancy_mode != "erasure" else (manifest.total_shards or 6),
                    max_attempts=self.max_retries,
                    state=RepairState.RUNNING,
                )
            else:
                job = existing_job
                job.state = RepairState.RUNNING
                job.attempt_count += 1

            self.job_store.create_job(job)

            if manifest.redundancy_mode == "erasure" or chunk_meta.shards:
                return self._repair_erasure_coded_chunk(
                    manifest=manifest,
                    chunk_meta=chunk_meta,
                    client=client,
                    job=job,
                    coordinator_url=coordinator_url,
                    candidate_nodes=candidate_nodes,
                )

            # Inspect current chunk health (replication mode)
            health_info = self.inspect_chunk_health(
                chunk_meta=chunk_meta,
                replication_factor=manifest.replication_factor,
                client=client,
                coordinator_url=coordinator_url,
            )

            # 1. Idempotency Check: Already healthy?
            if len(health_info.healthy_placements) >= manifest.replication_factor:
                job.state = RepairState.SUCCEEDED
                job.completed_at = datetime.now(timezone.utc).isoformat()
                self.job_store.update_job(job)
                logger.info(f"Chunk '{chunk_id}' already has {len(health_info.healthy_placements)} healthy copies. Repair skipped.")
                return chunk_meta, job

            # 2. Check for Unrecoverable State (0 healthy copies)
            if not health_info.healthy_placements:
                job.state = RepairState.UNRECOVERABLE
                job.last_error = f"Zero healthy copies available for Chunk ID '{chunk_id}'."
                self.job_store.update_job(job)
                logger.error(f"Repair impossible for Chunk ID '{chunk_id}': No healthy source placements.")
                return chunk_meta, job

            # 3. Repair missing replicas until required replication factor is satisfied
            while len(health_info.healthy_placements) < manifest.replication_factor:
                # Select Source Node
                source_placement = health_info.healthy_placements[0]
                job.source_node_id = source_placement.node_id
                job.source_node_endpoint = source_placement.node_endpoint
                self.job_store.update_job(job)

                # Select Destination Node
                existing_node_ids = {p.node_id for p in health_info.healthy_placements}

                eligible_nodes: List[Dict[str, Any]] = []
                if candidate_nodes is not None:
                    eligible_nodes = [n for n in candidate_nodes if n.get("node_id") not in existing_node_ids]
                elif coordinator_url:
                    try:
                        from coordinator.coordinator_client import CoordinatorClient
                        coord_client = CoordinatorClient(coordinator_url=coordinator_url, timeout=client.timeout)
                        all_nodes = coord_client.list_nodes(status="online", min_available_bytes=chunk_meta.size)
                        eligible_nodes = [n for n in all_nodes if n.get("node_id") not in existing_node_ids]
                    except Exception as exc:
                        logger.warning(f"Failed to discover destination nodes via Coordinator: {str(exc)}")

                if not eligible_nodes:
                    if not health_info.healthy_placements:
                        job.state = RepairState.RETRY_WAIT
                        job.last_error = "No eligible destination Storage Node available that does not already hold this chunk."
                        self.job_store.update_job(job)
                        raise ClientError(job.last_error)
                    break

                dest_node = eligible_nodes[0]
                dest_node_id = dest_node.get("node_id")
                dest_endpoint = dest_node.get("advertised_endpoint") or dest_node.get("endpoint")

                job.destination_node_id = dest_node_id
                job.destination_node_endpoint = dest_endpoint
                self.job_store.update_job(job)

                # Download Encrypted Ciphertext Chunk from Source Node
                src_ep = source_placement.node_endpoint
                chunk_bytes = _download_chunk_from_endpoint(
                    client, chunk_meta.chunk_id, src_ep, node_id=source_placement.node_id, coordinator_url=coordinator_url
                )
                if compute_sha256(chunk_bytes) != chunk_meta.sha256.lower():
                    job.state = RepairState.REPAIR_FAILED
                    job.last_error = f"Source node '{source_placement.node_id}' returned corrupted chunk payload."
                    self.job_store.update_job(job)
                    raise IntegrityVerificationError(job.last_error)

                # Upload Encrypted Ciphertext Chunk to Destination Node
                dest_ep = dest_endpoint
                opaque_filename = f"{chunk_id}.dat"
                upload_meta = _upload_chunk_to_endpoint(
                    client, chunk_bytes, opaque_filename, dest_ep, node_id=dest_node_id, coordinator_url=coordinator_url
                )
                stored_file_id = upload_meta.get("file_id", chunk_id)

                # Verify Destination Copy Integrity
                verify_bytes = _download_chunk_from_endpoint(
                    client, stored_file_id, dest_ep, node_id=dest_node_id, coordinator_url=coordinator_url
                )
                if compute_sha256(verify_bytes) != chunk_meta.sha256.lower():
                    job.state = RepairState.REPAIR_FAILED
                    job.last_error = f"Destination node '{dest_node_id}' stored payload failed SHA-256 verification."
                    self.job_store.update_job(job)
                    try:
                        _delete_file_from_endpoint(
                            client, stored_file_id, dest_ep, node_id=dest_node_id, coordinator_url=coordinator_url
                        )
                    except Exception:
                        pass
                    raise IntegrityVerificationError(job.last_error)


                # Atomic Metadata Update for this replica placement
                new_placement = ChunkPlacement(
                    node_id=dest_node_id,
                    node_endpoint=dest_endpoint,
                    role="REPLICA",
                )
                health_info.healthy_placements.append(new_placement)
                chunk_meta.placements = list(health_info.healthy_placements)
                chunk_meta.node_id = health_info.healthy_placements[0].node_id
                chunk_meta.node_endpoint = health_info.healthy_placements[0].node_endpoint

            job.state = RepairState.SUCCEEDED
            job.completed_at = datetime.now(timezone.utc).isoformat()
            job.last_error = None
            self.job_store.update_job(job)

            logger.info(f"Chunk '{chunk_id}' successfully repaired! Current healthy copies: {len(health_info.healthy_placements)}.")
            return chunk_meta, job

        except Exception as exc:
            if job is not None:
                job.state = RepairState.REPAIR_FAILED if job.attempt_count >= job.max_attempts else RepairState.RETRY_WAIT
                job.last_error = str(exc)
                self.job_store.update_job(job)
            raise ClientError(f"Repair execution failed for Chunk '{chunk_id}': {str(exc)}") from exc
        finally:
            self.lock_manager.release_lock(chunk_id)

    def repair_manifest(
        self,
        manifest: FileManifest,
        client: ExpoClient,
        coordinator_url: str = "http://127.0.0.1:9000",
        candidate_nodes: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[FileManifest, List[RepairJob]]:
        """
        Executes bounded parallel repairs for all under-replicated chunks in a FileManifest.
        Returns updated FileManifest and list of completed RepairJobs.
        """
        health = self.inspect_manifest_health(manifest, client=client, coordinator_url=coordinator_url)
        jobs: List[RepairJob] = []

        if health.under_replicated_chunks_count == 0:
            logger.info(f"File ID '{manifest.file_id}' is fully healthy. No repair required.")
            return manifest, jobs

        under_rep_reports = [r for r in health.chunk_reports if r.state == RepairState.UNDER_REPLICATED]

        with ThreadPoolExecutor(max_workers=min(self.max_concurrent_jobs, len(under_rep_reports))) as executor:
            future_to_chunk = {}
            for rep in under_rep_reports:
                chunk_meta = next((c for c in manifest.chunks if c.chunk_id == rep.chunk_id), None)
                if chunk_meta:
                    future = executor.submit(
                        self.repair_under_replicated_chunk,
                        manifest=manifest,
                        chunk_meta=chunk_meta,
                        client=client,
                        coordinator_url=coordinator_url,
                        candidate_nodes=candidate_nodes,
                    )
                    future_to_chunk[future] = chunk_meta

            for future in as_completed(future_to_chunk):
                try:
                    updated_meta, job = future.result()
                    jobs.append(job)
                except Exception as exc:
                    logger.error(f"Chunk repair worker raised exception: {str(exc)}")

        return manifest, jobs

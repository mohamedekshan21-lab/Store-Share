"""
Phase 5C: Durable Cleanup, Reconciliation and Recovery.
"""

from __future__ import annotations

import json
import uuid
import httpx
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

from coordinator.app.database import get_db_connection
from coordinator.app.config import CoordinatorSettings
from coordinator.app.models import DeletionJobRecord, ReconciliationReport


class ReconciliationService:
    def __init__(self, settings: CoordinatorSettings):
        self.settings = settings
        self.db_path = settings.db_path

    def _get_headers(self) -> Dict[str, str]:
        headers = {}
        if self.settings.auth_token and self.settings.auth_token.strip():
            token = self.settings.auth_token.strip()
            headers["X-Auth-Token"] = token
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def run_reconciliation(self, dry_run: bool = True) -> ReconciliationReport:
        report = ReconciliationReport(status="dry_run" if dry_run else "executed")
        
        with get_db_connection(self.db_path) as conn:
            # 1. Stalled Deletion Jobs
            stalled_jobs = conn.execute(
                "SELECT * FROM deletion_jobs WHERE status IN ('pending', 'in_progress', 'retryable_failure')"
            ).fetchall()
            
            # We don't execute deletion jobs synchronously here, we just count them.
            # In a real background worker, we'd spawn tasks. For Phase 5C, we can process them here if not dry_run
            
            # 2. Collect all active chunks
            active_files = conn.execute(
                "SELECT manifest_json FROM files WHERE status NOT IN ('deleted')"
            ).fetchall()
            
            expected_filenames = set()
            for row in active_files:
                manifest = json.loads(row["manifest_json"])
                for chunk in manifest.get("chunks", []):
                    # For replicas
                    c_id = chunk.get("chunk_id")
                    if c_id:
                        expected_filenames.add(f"{c_id}.dat")
                    for p in chunk.get("placements", []):
                        p_cid = p.get("chunk_id")
                        if p_cid:
                            expected_filenames.add(f"{p_cid}.dat")
                    # For erasure shards
                    for shard in chunk.get("shards", []):
                        s_id = shard.get("shard_id")
                        if s_id:
                            expected_filenames.add(f"{s_id}.dat")
            
            # 3. Query all Storage Nodes
            nodes = conn.execute(
                "SELECT node_id, endpoint, advertised_endpoint FROM nodes WHERE status = 'online'"
            ).fetchall()
            
            orphaned_files = [] # tuples of (node_id, endpoint, file_id, original_filename)
            
            for node in nodes:
                endpoint = node["advertised_endpoint"] or node["endpoint"]
                node_id = node["node_id"]
                try:
                    res = httpx.get(
                        f"{endpoint}/files",
                        headers={"X-Auth-Token": self.settings.auth_token} if self.settings.auth_token else {},
                        timeout=httpx.Timeout(5.0, connect=3.0),
                    )
                    if res.status_code == 200:
                        node_files = res.json()
                        if isinstance(node_files, dict):
                            node_files = node_files.get("files", [])
                        print("DEBUG RECONCILIATION NODE_FILES:", node_files)
                        for nf in node_files:
                            orig = nf.get("original_filename")
                            created_at_str = nf.get("created_at")
                            if not created_at_str:
                                print("DEBUG NO CREATED AT STR:", orig)
                                continue
                            try:
                                created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
                                if created_at.tzinfo is None:
                                    created_at = created_at.replace(tzinfo=timezone.utc)
                            except Exception as e:
                                print("DEBUG DATE PARSE ERROR:", e)
                                continue
                            
                            # if it's older than 1 hour and not expected
                            diff = (datetime.now(timezone.utc) - created_at).total_seconds()
                            print(f"DEBUG ORIG={orig} DIFF={diff} EXPECTED={orig in expected_filenames}")
                            if diff > 3600:
                                if orig not in expected_filenames:
                                    orphaned_files.append((node_id, endpoint, nf.get("file_id"), orig))
                                    report.orphaned_objects_detected += 1
                except Exception as e:
                    print("DEBUG RECONCILIATION EXCEPTION:", e)
                    # Ignore unreachable nodes during reconciliation
                    pass

            if not dry_run:
                # Execute stalled deletion jobs
                for job_row in stalled_jobs:
                    job = dict(job_row)
                    self._process_deletion_job_sync(conn, job)
                    report.stalled_deletions_resumed += 1
                
                # Cleanup orphaned files
                for node_id, endpoint, file_id, orig in orphaned_files:
                    try:
                        del_res = httpx.delete(
                            f"{endpoint}/files/{file_id}",
                            headers=self._get_headers(),
                            timeout=httpx.Timeout(5.0, connect=3.0),
                        )
                        if del_res.status_code in (200, 204):
                            report.orphaned_objects_cleaned += 1
                    except Exception:
                        pass

        return report

    def create_deletion_job(self, file_id: str, owner_id: str, manifest_json: str) -> str:
        job_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        
        # Parse manifest to get target chunks
        manifest = json.loads(manifest_json)
        target_chunks = []
        for chunk in manifest.get("chunks", []):
            c_id = chunk.get("chunk_id")
            placements = chunk.get("placements", [])
            if not placements and chunk.get("node_endpoint"):
                placements = [{"node_endpoint": chunk.get("node_endpoint")}]
            
            for placement in placements:
                p_cid = placement.get("chunk_id") or c_id
                target_chunks.append({
                    "node_id": placement.get("node_id"),
                    "node_endpoint": placement.get("node_endpoint"),
                    "filename": f"{p_cid}.dat",
                    "c_id": p_cid
                })
            for shard in chunk.get("shards", []):
                s_id = shard.get("shard_id")
                target_chunks.append({
                    "node_id": shard.get("node_id"),
                    "node_endpoint": shard.get("node_endpoint"),
                    "filename": f"{s_id}.dat",
                    "c_id": s_id
                })

        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO deletion_jobs (
                    job_id, file_id, owner_id, status, target_chunks, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (job_id, file_id, owner_id, "pending", json.dumps(target_chunks), now, now)
            )
            
            # Also set the file status to deleting
            conn.execute(
                "UPDATE files SET status = 'deleting', updated_at = ? WHERE file_id = ?",
                (now, file_id)
            )
            conn.commit()
            
        return job_id
        
    def process_deletion_job_bg(self, job_id: str):
        with get_db_connection(self.db_path) as conn:
            row = conn.execute("SELECT * FROM deletion_jobs WHERE job_id = ?", (job_id,)).fetchone()
            if not row:
                return
            job = dict(row)
            self._process_deletion_job_sync(conn, job)

    def _process_deletion_job_sync(self, conn, job: dict):
        job_id = job["job_id"]
        target_chunks = json.loads(job["target_chunks"])
        now = datetime.now(timezone.utc).isoformat()
        
        conn.execute(
            "UPDATE deletion_jobs SET status = 'in_progress', attempt_count = attempt_count + 1, updated_at = ? WHERE job_id = ?",
            (now, job_id)
        )
        conn.commit()

        remaining_chunks = []
        for chunk_target in target_chunks:
            endpoint = chunk_target.get("node_endpoint")
            filename = chunk_target.get("filename")
            c_id = chunk_target.get("c_id")
            n_id = chunk_target.get("node_id")

            # Resolve internal endpoint if direct endpoint missing or known
            candidate_endpoints = []
            if endpoint:
                candidate_endpoints.append(endpoint.rstrip("/"))

            if n_id:
                try:
                    from coordinator.app.node_registry import NodeRegistry
                    reg = NodeRegistry(self.settings)
                    node_rec = reg.get_node(n_id)
                    if node_rec:
                        if node_rec.endpoint and node_rec.endpoint.rstrip("/") not in candidate_endpoints:
                            candidate_endpoints.append(node_rec.endpoint.rstrip("/"))
                        if node_rec.advertised_endpoint and node_rec.advertised_endpoint.rstrip("/") not in candidate_endpoints:
                            candidate_endpoints.append(node_rec.advertised_endpoint.rstrip("/"))
                except Exception:
                    pass

            if not candidate_endpoints:
                continue
            
            success = False
            timeout_setting = httpx.Timeout(2.0, connect=1.0)
            headers = self._get_headers()


            for ep in candidate_endpoints:
                try:
                    # Try direct deletion by c_id first
                    del_direct = httpx.delete(f"{ep}/files/{c_id}", headers=headers, timeout=timeout_setting)
                    if del_direct.status_code in (200, 204, 404):
                        success = True
                        break

                    res = httpx.get(f"{ep}/files", headers=headers, timeout=timeout_setting)
                    if res.status_code == 200:
                        found_file_id = None
                        node_files = res.json()
                        if isinstance(node_files, dict):
                            node_files = node_files.get("files", [])
                        for nf in node_files:
                            if nf.get("file_id") == c_id or nf.get("original_filename") == filename or nf.get("original_filename") == f"{c_id}.dat":
                                found_file_id = nf.get("file_id")
                                break
                        if found_file_id:
                            del_res = httpx.delete(f"{ep}/files/{found_file_id}", headers=headers, timeout=timeout_setting)
                            if del_res.status_code in (200, 204, 404):
                                success = True
                                break
                        else:
                            # Not found on node -> considered cleaned up
                            success = True
                            break
                except Exception:
                    pass

                
            if not success:
                remaining_chunks.append(chunk_target)

        now = datetime.now(timezone.utc).isoformat()
        if len(remaining_chunks) == 0:
            # Complete
            conn.execute(
                "UPDATE deletion_jobs SET status = 'completed', target_chunks = '[]', updated_at = ? WHERE job_id = ?",
                (now, job_id)
            )
            # Finalize file catalog
            conn.execute(
                "UPDATE files SET status = 'deleted', updated_at = ? WHERE file_id = ?",
                (now, job["file_id"])
            )
        else:
            conn.execute(
                "UPDATE deletion_jobs SET status = 'retryable_failure', target_chunks = ?, updated_at = ? WHERE job_id = ?",
                (json.dumps(remaining_chunks), now, job_id)
            )
        conn.commit()

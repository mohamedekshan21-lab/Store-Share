"""
Expo Storage Node Client API implementation (Phase 3B).
Performs remote health checks, node identity checks, storage capacity inspection,
SHA-256 integrity-verified uploads, downloads, file listing, deletion over LAN/Internet,
and Phase 3B Multi-Node Chunk Placement & Distributed Storage Pipelines.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import httpx

from client.config import get_client_settings, ClientSettings
from client.crypto import AESGCMCrypto, CryptoError, DecryptionError
from client.chunker import (
    FileManifest,
    ChunkMetadata,
    ChunkPlacement,
    ShardMetadata,
    split_payload_into_chunks,
    reassemble_chunks,
    compute_sha256,
    DEFAULT_CHUNK_SIZE_BYTES,
)
from client.placement import (
    select_nodes_for_placement,
    assign_chunks_round_robin,
    assign_chunks_with_replication,
    assign_shards_for_erasure_coding,
)
from client.erasure import (
    encode_ciphertext_chunk,
    reconstruct_ciphertext_chunk,
    validate_erasure_config,
    ErasureCodingError,
    InvalidCodingConfigError,
    ReconstructionError,
)
from client.connectivity import ConnectionManager, RouteType


class ClientError(Exception):
    """Base exception for Expo Client errors."""


class IntegrityVerificationError(ClientError):
    """Raised when SHA-256 checksum integrity check fails during upload/download."""


class ExpoClient:
    """Client for interacting with Expo Storage Nodes and Coordinator over HTTP/HTTPS."""

    def __init__(
        self,
        node_url: Optional[str] = None,
        auth_token: Optional[str] = None,
        timeout: float = 30.0,
        relay_token: Optional[str] = None,
        coordinator_url: Optional[str] = None,
        connection_manager: Optional[ConnectionManager] = None,
    ) -> None:
        settings = get_client_settings()
        self.base_url = (node_url or settings.base_url).rstrip("/")
        self.auth_token = auth_token if auth_token is not None else settings.auth_token
        self.timeout = timeout
        self.relay_token = relay_token
        coord_url = coordinator_url or getattr(settings, "coordinator_url", None)
        self.coordinator_url = coord_url.rstrip("/") if coord_url else None
        self.connection_manager = connection_manager or (
            ConnectionManager(
                coordinator_url=self.coordinator_url,
                auth_token=self.auth_token,
                probe_timeout=min(5.0, self.timeout),
            ) if self.coordinator_url else None
        )

    def _get_headers(self) -> Dict[str, str]:
        """Builds HTTP headers including authentication and relay token if set."""
        headers = {}
        if self.relay_token and self.relay_token.strip():
            headers["X-Relay-Token"] = self.relay_token.strip()
        if self.auth_token and self.auth_token.strip():
            token = self.auth_token.strip()
            headers["X-Auth-Token"] = token
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def get_node_client(
        self,
        node_id: str,
        endpoint: Optional[str] = None,
        coordinator_url: Optional[str] = None,
    ) -> ExpoClient:
        """
        Resolves the appropriate network route (Direct or Relayed) to a Storage Node
        and returns a configured ExpoClient instance for that route.
        """
        if type(self) is not ExpoClient:
            if endpoint:
                self.base_url = endpoint
            return self

        coord_url = coordinator_url or self.coordinator_url
        if not coord_url and (not endpoint or endpoint == self.base_url):
            return self
        conn_mgr = self.connection_manager
        if not conn_mgr and coord_url:
            conn_mgr = ConnectionManager(
                coordinator_url=coord_url,
                auth_token=self.auth_token,
                probe_timeout=min(5.0, self.timeout),
            )
            self.connection_manager = conn_mgr

        if conn_mgr:
            route = conn_mgr.resolve_route(node_id, direct_endpoint=endpoint)
            if route.is_routable:
                return ExpoClient(
                    node_url=route.target_url,
                    auth_token=self.auth_token,
                    timeout=self.timeout,
                    relay_token=route.session_token,
                    coordinator_url=coord_url,
                    connection_manager=conn_mgr,
                )

        target_ep = endpoint or self.base_url
        return ExpoClient(
            node_url=target_ep,
            auth_token=self.auth_token,
            timeout=self.timeout,
            coordinator_url=coord_url,
            connection_manager=conn_mgr,
        )


    def health(self) -> Dict[str, Any]:
        """Checks Storage Node liveness."""
        url = f"{self.base_url}/health"
        try:
            res = httpx.get(url, timeout=self.timeout)
            res.raise_for_status()
            return res.json()
        except httpx.HTTPError as exc:
            raise ClientError(f"Health check failed: {str(exc)}") from exc

    def node_info(self) -> Dict[str, Any]:
        """Retrieves persistent Node ID, status, and last seen timestamp."""
        url = f"{self.base_url}/node"
        try:
            res = httpx.get(url, timeout=self.timeout)
            res.raise_for_status()
            return res.json()
        except httpx.HTTPError as exc:
            raise ClientError(f"Failed to retrieve node info: {str(exc)}") from exc

    def storage_info(self) -> Dict[str, Any]:
        """Retrieves node quota, used bytes, and available capacity."""
        url = f"{self.base_url}/storage"
        try:
            res = httpx.get(url, headers=self._get_headers(), timeout=self.timeout)
            res.raise_for_status()
            return res.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                raise ClientError("Authentication failed: Missing or invalid node auth token.") from exc
            raise ClientError(f"Storage query failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise ClientError(f"Storage query failed: {str(exc)}") from exc

    def upload_file(self, file_path: str | Path) -> Dict[str, Any]:
        """Uploads a file to the remote node with pre-calculated SHA-256 checksum header."""
        path = Path(file_path).resolve()
        if not path.is_file():
            raise ClientError(f"Local file not found: '{path}'")

        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(64 * 1024):
                hasher.update(chunk)
        local_sha256 = hasher.hexdigest().lower()

        headers = self._get_headers()
        headers["X-SHA256-Checksum"] = local_sha256

        url = f"{self.base_url}/files"
        try:
            with open(path, "rb") as f:
                files = {"file": (path.name, f, "application/octet-stream")}
                res = httpx.post(url, files=files, headers=headers, timeout=self.timeout)
            
            res.raise_for_status()
            metadata = res.json()
            
            server_sha256 = metadata.get("sha256")
            if server_sha256 and server_sha256.lower() != local_sha256:
                raise IntegrityVerificationError(
                    f"Upload integrity check failed: Local SHA-256 '{local_sha256}' != Server '{server_sha256}'."
                )

            metadata["integrity_verified"] = True
            return metadata

        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            detail = exc.response.json().get("detail", exc.response.text) if exc.response.content else exc.response.text
            if code == 507:
                raise ClientError(f"Upload failed - Quota Exceeded (507): {detail}") from exc
            elif code == 401:
                raise ClientError("Upload failed - Unauthorized (401): Invalid or missing token.") from exc
            elif code == 400:
                raise ClientError(f"Upload failed - Bad Request (400): {detail}") from exc
            raise ClientError(f"Upload failed ({code}): {detail}") from exc
        except httpx.HTTPError as exc:
            raise ClientError(f"Upload network error: {str(exc)}") from exc

    def upload_chunk_bytes(self, chunk_bytes: bytes, filename: str, capability_token: Optional[str] = None) -> Dict[str, Any]:
        """Uploads raw binary chunk payload to remote Storage Node as an opaque object."""
        local_sha256 = compute_sha256(chunk_bytes)
        headers = self._get_headers()
        headers["X-SHA256-Checksum"] = local_sha256
        if capability_token and capability_token.strip():
            headers["X-Capability-Token"] = capability_token.strip()
        timeout = httpx.Timeout(self.timeout, connect=min(10.0, self.timeout))

        url = f"{self.base_url}/files"
        try:
            with httpx.Client(timeout=timeout) as client:
                files = {"file": (filename, chunk_bytes, "application/octet-stream")}
                res = client.post(url, files=files, headers=headers)
                res.raise_for_status()
                metadata = res.json()

            server_sha256 = metadata.get("sha256")
            if server_sha256 and server_sha256.lower() != local_sha256:
                raise IntegrityVerificationError(
                    f"Chunk upload integrity check failed: Computed SHA-256 '{local_sha256}' != Server '{server_sha256}'."
                )
            return metadata
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            detail = exc.response.json().get("detail", exc.response.text) if exc.response.content else exc.response.text
            if code == 507:
                raise ClientError(f"Chunk upload failed - Quota Exceeded (507): {detail}") from exc
            raise ClientError(f"Chunk upload failed ({code}): {detail}") from exc
        except httpx.ConnectError as exc:
            raise ClientError(f"Chunk upload failed - Node connection refused at '{self.base_url}': {str(exc)}") from exc
        except httpx.TimeoutException as exc:
            raise ClientError(f"Chunk upload failed - Connection timed out at '{self.base_url}': {str(exc)}") from exc
        except httpx.HTTPError as exc:
            raise ClientError(f"Chunk upload network error: {str(exc)}") from exc

    def download_chunk_bytes(self, file_id: str, max_retries: int = 1, capability_token: Optional[str] = None) -> bytes:
        """Downloads raw chunk bytes from remote Storage Node and verifies SHA-256 checksum with bounded retries."""
        url = f"{self.base_url}/files/{file_id}"
        headers = self._get_headers()
        if capability_token and capability_token.strip():
            headers["X-Capability-Token"] = capability_token.strip()
        timeout = httpx.Timeout(self.timeout, connect=min(10.0, self.timeout))

        last_error: Optional[Exception] = None
        for attempt in range(max_retries + 1):
            try:
                with httpx.Client(timeout=timeout) as client:
                    res = client.get(url, headers=headers)
                    if res.status_code == 401:
                        raise ClientError("Authentication failed: Missing or invalid node auth token.")
                    elif res.status_code == 404:
                        raise ClientError(f"Remote chunk file not found (404): ID '{file_id}'")
                    res.raise_for_status()

                    chunk_bytes = res.content
                    expected_sha256 = res.headers.get("X-SHA256-Checksum", "").strip().lower()
                    computed_sha256 = compute_sha256(chunk_bytes)

                    if expected_sha256 and computed_sha256 != expected_sha256:
                        raise IntegrityVerificationError(
                            f"Chunk download SHA-256 integrity verification failed! Expected '{expected_sha256}', but calculated '{computed_sha256}'."
                        )
                    return chunk_bytes
            except (IntegrityVerificationError, ClientError):
                raise
            except httpx.ConnectError as exc:
                last_error = ClientError(f"Node connection refused or host unreachable at '{self.base_url}': {str(exc)}")
                if attempt < max_retries:
                    time.sleep(0.1)
                    continue
            except httpx.TimeoutException as exc:
                last_error = ClientError(f"Node connection timed out at '{self.base_url}': {str(exc)}")
                if attempt < max_retries:
                    time.sleep(0.1)
                    continue
            except httpx.HTTPError as exc:
                raise ClientError(f"Chunk download network error: {str(exc)}") from exc

        if last_error:
            raise last_error
        raise ClientError(f"Chunk download failed for ID '{file_id}'")

    def list_files(self) -> List[Dict[str, Any]]:
        """Lists metadata for all files stored on the remote node."""
        url = f"{self.base_url}/files"
        try:
            res = httpx.get(url, headers=self._get_headers(), timeout=self.timeout)
            res.raise_for_status()
            return res.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                raise ClientError("Authentication failed: Missing or invalid node auth token.") from exc
            raise ClientError(f"List files failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise ClientError(f"List files network error: {str(exc)}") from exc

    def download_file(self, file_id: str, output_path: str | Path) -> Dict[str, Any]:
        """Downloads file from remote node and verifies SHA-256 checksum integrity."""
        out_path = Path(output_path).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        
        url = f"{self.base_url}/files/{file_id}"
        hasher = hashlib.sha256()

        try:
            with httpx.stream("GET", url, headers=self._get_headers(), timeout=self.timeout) as res:
                if res.status_code == 401:
                    raise ClientError("Authentication failed: Missing or invalid node auth token.")
                elif res.status_code == 404:
                    raise ClientError(f"Remote file not found (404): ID '{file_id}'")
                elif res.status_code != 200:
                    raise ClientError(f"Download failed ({res.status_code}): {res.read().decode('utf-8', errors='ignore')}")

                expected_sha256 = res.headers.get("X-SHA256-Checksum", "").strip().lower()

                with open(out_path, "wb") as f_out:
                    for chunk in res.iter_bytes(chunk_size=64 * 1024):
                        hasher.update(chunk)
                        f_out.write(chunk)

            computed_sha256 = hasher.hexdigest().lower()

            if expected_sha256 and computed_sha256 != expected_sha256:
                if out_path.exists():
                    out_path.unlink(missing_ok=True)
                raise IntegrityVerificationError(
                    f"Download SHA-256 integrity verification failed! Expected '{expected_sha256}', but calculated '{computed_sha256}'."
                )

            return {
                "status": "downloaded",
                "file_id": file_id,
                "output_path": str(out_path),
                "sha256": computed_sha256,
                "integrity_verified": True,
            }

        except httpx.HTTPError as exc:
            if out_path.exists():
                out_path.unlink(missing_ok=True)
            raise ClientError(f"Download network error: {str(exc)}") from exc

    def delete_file(self, file_id: str, capability_token: Optional[str] = None) -> bool:
        """Deletes file on remote node."""
        url = f"{self.base_url}/files/{file_id}"
        headers = self._get_headers()
        if capability_token and capability_token.strip():
            headers["X-Capability-Token"] = capability_token.strip()
        try:
            res = httpx.delete(url, headers=headers, timeout=self.timeout)
            if res.status_code == 404:
                raise ClientError(f"Remote file not found (404): ID '{file_id}'")
            elif res.status_code == 401:
                raise ClientError("Authentication failed: Missing or invalid node auth token.")
            res.raise_for_status()
            return True
        except httpx.HTTPError as exc:
            raise ClientError(f"Delete file failed: {str(exc)}") from exc

    def list_coordinator_nodes(
        self,
        coordinator_url: str = "http://127.0.0.1:9000",
        status: Optional[str] = None,
        connectivity_mode: Optional[str] = None,
        min_available_bytes: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Queries Coordinator to discover available registered Storage Nodes."""
        from coordinator.coordinator_client import CoordinatorClient
        coord_client = CoordinatorClient(coordinator_url=coordinator_url, timeout=self.timeout)
        return coord_client.list_nodes(
            status=status,
            connectivity_mode=connectivity_mode,
            min_available_bytes=min_available_bytes,
        )

    def select_storage_node(
        self,
        coordinator_url: str = "http://127.0.0.1:9000",
        required_bytes: int = 1048576,
        online_only: bool = True,
        preferred_connectivity: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Queries Coordinator to select the best eligible Storage Node matching criteria."""
        from coordinator.coordinator_client import CoordinatorClient
        coord_client = CoordinatorClient(coordinator_url=coordinator_url, timeout=self.timeout)
        return coord_client.select_node(
            required_bytes=required_bytes,
            online_only=online_only,
            preferred_connectivity=preferred_connectivity,
        )

    # Phase 3A, 3B & 4C Client-Side Encryption, Chunking, Multi-Node Replication & Erasure Coding Pipelines
    def encrypt_and_upload_file(
        self,
        file_path: str | Path,
        key: Optional[bytes] = None,
        chunk_size: Optional[int] = None,
        coordinator_url: Optional[str] = None,
        target_node_count: int = 3,
        preferred_connectivity: Optional[str] = None,
        require_reachable: bool = False,
        replication_factor: int = 1,
        redundancy_mode: Optional[str] = None,
        data_shards: Optional[int] = None,
        parity_shards: Optional[int] = None,
        candidate_nodes: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[FileManifest, bytes]:
        """
        Phase 4A & 4C Multi-Node Upload Pipeline:
        Supports both replication and erasure coding redundancy strategies.
        
        1. Reads unencrypted plaintext file and computes original SHA-256.
        2. Generates fresh AES-256 DEK (if omitted) and random 96-bit nonce/IV.
        3. Encrypts payload locally using AES-256-GCM.
        4. Splits encrypted payload into deterministic chunks.
        5. If redundancy_mode == 'erasure':
           - Encodes encrypted chunks into data (k) and parity (m) shards using Reed-Solomon.
           - Assigns each shard of an encoded chunk to a distinct Storage Node ID.
           - Uploads each shard with SHA-256 verification metadata.
           - Builds and returns schema v3 FileManifest.
        6. If redundancy_mode == 'replication':
           - Assigns primary and replica placements using assign_chunks_with_replication().
           - Uploads chunk copies to primary and replica nodes.
           - Builds and returns schema v2 FileManifest.
        """
        settings = get_client_settings()
        mode = (redundancy_mode or settings.redundancy_mode).strip().lower()

        if mode not in ("replication", "erasure"):
            raise ClientError(f"Invalid redundancy_mode '{mode}': Must be 'replication' or 'erasure'.")

        ec_k = ec_m = None
        if mode == "erasure":
            ec_k = data_shards if data_shards is not None else settings.ec_data_shards
            ec_m = parity_shards if parity_shards is not None else settings.ec_parity_shards
            try:
                validate_erasure_config(ec_k, ec_m)
            except InvalidCodingConfigError as exc:
                raise ClientError(f"Invalid coding configuration: {exc}") from exc

        path = Path(file_path).resolve()
        if not path.is_file():
            raise ClientError(f"Local file not found: '{path}'")

        with open(path, "rb") as f:
            plaintext = f.read()

        orig_size = len(plaintext)
        orig_sha256 = compute_sha256(plaintext)

        dek = key if key is not None else AESGCMCrypto.generate_key()
        if len(dek) != AESGCMCrypto.KEY_SIZE_BYTES:
            raise ClientError(f"Invalid encryption key size: must be {AESGCMCrypto.KEY_SIZE_BYTES} bytes.")

        ciphertext, nonce = AESGCMCrypto.encrypt(plaintext, dek)
        encrypted_size = len(ciphertext)

        c_size = chunk_size if chunk_size is not None and chunk_size > 0 else DEFAULT_CHUNK_SIZE_BYTES
        chunks_tuples = split_payload_into_chunks(ciphertext, chunk_size=c_size)

        if mode == "erasure":
            return self._encrypt_and_upload_erasure(
                path=path,
                dek=dek,
                nonce=nonce,
                ciphertext=ciphertext,
                orig_size=orig_size,
                orig_sha256=orig_sha256,
                chunks_tuples=chunks_tuples,
                c_size=c_size,
                k=ec_k,
                m=ec_m,
                coordinator_url=coordinator_url,
                target_node_count=target_node_count,
                preferred_connectivity=preferred_connectivity,
                require_reachable=require_reachable,
                candidate_nodes=candidate_nodes,
            )

        else:
            # Replication mode
            if replication_factor < 1:
                raise ClientError("replication_factor must be an integer >= 1.")

            min_nodes_required = max(target_node_count, replication_factor)
            selected_nodes: List[Dict[str, Any]] = candidate_nodes if candidate_nodes is not None else []
            if not selected_nodes:
                if coordinator_url:
                    from coordinator.coordinator_client import CoordinatorClient
                    coord_client = CoordinatorClient(coordinator_url=coordinator_url, timeout=self.timeout)
                    selected_nodes = select_nodes_for_placement(
                        coordinator_client=coord_client,
                        required_chunk_size=c_size,
                        target_node_count=min_nodes_required,
                        preferred_connectivity=preferred_connectivity,
                        require_reachable=require_reachable,
                        connection_manager=self.connection_manager,
                    )
                else:
                    try:
                        selected_nodes = self.list_coordinator_nodes()
                    except Exception:
                        pass

            if not selected_nodes:
                node_id_val = None
                try:
                    info = self.node_info()
                    node_id_val = info.get("node_id", "NODE-LOCAL")
                except Exception:
                    node_id_val = "NODE-LOCAL"

                selected_nodes = [{
                    "node_id": node_id_val,
                    "endpoint": self.base_url,
                    "advertised_endpoint": self.base_url,
                    "connectivity_mode": "LAN",
                }]

            if len(selected_nodes) < replication_factor:
                raise ClientError(
                    f"Upload aborted: Required replication factor {replication_factor} cannot be satisfied "
                    f"(only {len(selected_nodes)} eligible nodes available)."
                )

            chunk_assignments = assign_chunks_with_replication(
                chunks_tuples, selected_nodes, replication_factor=replication_factor
            )

            # Phase 10B: Request signed upload capabilities from Coordinator if available
            upload_caps: Dict[str, Dict[str, str]] = {}
            if coordinator_url:
                try:
                    cap_payload = {
                        "file_id": file_id,
                        "chunks": [
                            {
                                "chunk_id": c_id,
                                "node_ids": [p[0] for p in placements],
                                "size": len(c_bytes),
                                "sha256": c_sha256,
                            }
                            for _, c_id, c_bytes, c_sha256, placements in chunk_assignments
                        ]
                    }
                    cap_headers = self._get_headers()
                    with httpx.Client(timeout=self.timeout) as cc:
                        cap_res = cc.post(f"{coordinator_url}/catalog/capabilities/upload", json=cap_payload, headers=cap_headers)
                        if cap_res.status_code == 200:
                            upload_caps = cap_res.json().get("capabilities", {})
                        elif cap_res.status_code in (400, 401, 403, 507):
                            detail = cap_res.json().get("detail", cap_res.text) if cap_res.content else cap_res.text
                            raise ClientError(f"Upload capability request rejected ({cap_res.status_code}): {detail}")
                except ClientError:
                    raise
                except Exception:
                    pass

            manifest_chunks: List[ChunkMetadata] = []
            uploaded_records: List[Tuple[ExpoClient, str]] = []

            try:
                for seq, c_id, c_bytes, c_sha256, placements in chunk_assignments:
                    chunk_placements: List[ChunkPlacement] = []
                    primary_file_id = None

                    for n_id, n_endpoint, role in placements:
                        ep = n_endpoint or self.base_url
                        if hasattr(self, "nodes_info") or hasattr(self, "node_map") or not hasattr(self, "get_node_client") or type(self) is not ExpoClient:
                            node_client = self
                            self.base_url = ep
                        else:
                            node_client = self.get_node_client(n_id, endpoint=ep, coordinator_url=coordinator_url)

                        opaque_filename = f"{c_id}.dat"
                        node_cap = upload_caps.get(c_id, {}).get(n_id)
                        if node_cap:
                            try:
                                upload_meta = node_client.upload_chunk_bytes(c_bytes, opaque_filename, capability_token=node_cap)
                            except TypeError:
                                upload_meta = node_client.upload_chunk_bytes(c_bytes, opaque_filename)
                        else:
                            upload_meta = node_client.upload_chunk_bytes(c_bytes, opaque_filename)
                        stored_file_id = upload_meta.get("file_id", c_id)


                        if primary_file_id is None:
                            primary_file_id = stored_file_id

                        uploaded_records.append((node_client, stored_file_id))

                        chunk_placements.append(
                            ChunkPlacement(
                                node_id=n_id,
                                node_endpoint=ep,
                                role=role,
                                chunk_id=stored_file_id,
                            )
                        )

                    primary_node_id = placements[0][0]
                    primary_endpoint = placements[0][1] or self.base_url

                    manifest_chunks.append(
                        ChunkMetadata(
                            chunk_id=primary_file_id or c_id,
                            sequence=seq,
                            size=len(c_bytes),
                            sha256=c_sha256,
                            node_id=primary_node_id,
                            node_endpoint=primary_endpoint,
                            placements=chunk_placements,
                        )
                    )

            except Exception as exc:
                for client_item, stored_id in uploaded_records:
                    try:
                        client_item.delete_file(stored_id)
                    except Exception:
                        pass
                raise ClientError(f"Multi-node chunk upload failed during transfer: {str(exc)}") from exc

            file_id = str(uuid.uuid4())
            created_at = datetime.now(timezone.utc).isoformat()
            manifest = FileManifest(
                file_id=file_id,
                original_filename=path.name,
                original_size=orig_size,
                original_sha256=orig_sha256,
                encrypted_size=encrypted_size,
                chunk_size=c_size,
                chunk_count=len(manifest_chunks),
                replication_factor=replication_factor,
                manifest_version=2,
                encryption_algorithm="AES-256-GCM",
                nonce_hex=nonce.hex(),
                created_at=created_at,
                chunks=manifest_chunks,
                redundancy_mode="replication",
            )

            return manifest, dek

    def _encrypt_and_upload_erasure(
        self,
        path: Path,
        dek: bytes,
        nonce: bytes,
        ciphertext: bytes,
        orig_size: int,
        orig_sha256: str,
        chunks_tuples: List[Tuple[int, str, bytes, str]],
        c_size: int,
        k: int,
        m: int,
        coordinator_url: Optional[str],
        target_node_count: int,
        preferred_connectivity: Optional[str],
        require_reachable: bool,
        candidate_nodes: Optional[List[Dict[str, Any]]],
    ) -> Tuple[FileManifest, bytes]:
        total_shards = k + m
        selected_nodes = candidate_nodes if candidate_nodes is not None else []
        if not selected_nodes:
            if coordinator_url:
                from coordinator.coordinator_client import CoordinatorClient
                coord_client = CoordinatorClient(coordinator_url=coordinator_url, timeout=self.timeout)
                selected_nodes = select_nodes_for_placement(
                    coordinator_client=coord_client,
                    required_chunk_size=c_size,
                    target_node_count=max(target_node_count, total_shards),
                    preferred_connectivity=preferred_connectivity,
                    require_reachable=require_reachable,
                    connection_manager=self.connection_manager,
                )
            else:
                try:
                    selected_nodes = self.list_coordinator_nodes()
                except Exception:
                    pass

        if not selected_nodes:
            node_id_val = None
            try:
                info = self.node_info()
                node_id_val = info.get("node_id", "NODE-LOCAL")
            except Exception:
                node_id_val = "NODE-LOCAL"

            selected_nodes = [{
                "node_id": node_id_val,
                "endpoint": self.base_url,
                "advertised_endpoint": self.base_url,
                "connectivity_mode": "LAN",
            }]

        encoded_chunks = []
        sha256_map = {}
        for seq, c_id, c_bytes, c_sha256 in chunks_tuples:
            shards_list, c_orig_size, c_enc_size, padlen = encode_ciphertext_chunk(c_bytes, data_shards=k, parity_shards=m)
            encoded_chunks.append((seq, c_id, shards_list, c_orig_size, c_enc_size, padlen))
            sha256_map[c_id] = c_sha256

        shard_assignments = assign_shards_for_erasure_coding(encoded_chunks, selected_nodes, data_shards=k, parity_shards=m)

        # Phase 10B: Request signed upload capabilities for shards from Coordinator
        upload_caps: Dict[str, Dict[str, str]] = {}
        if coordinator_url:
            try:
                cap_payload = {
                    "file_id": file_id,
                    "chunks": [
                        {
                            "chunk_id": shard.shard_id,
                            "node_ids": [n_id],
                            "size": len(shard.payload),
                            "sha256": shard.sha256,
                        }
                        for _, _, shard_placements, _, _, _ in shard_assignments
                        for shard, n_id, _ in shard_placements
                    ]
                }
                cap_headers = self._get_headers()
                with httpx.Client(timeout=self.timeout) as cc:
                    cap_res = cc.post(f"{coordinator_url}/catalog/capabilities/upload", json=cap_payload, headers=cap_headers)
                    if cap_res.status_code == 200:
                        upload_caps = cap_res.json().get("capabilities", {})
                    elif cap_res.status_code in (400, 401, 403, 507):
                        detail = cap_res.json().get("detail", cap_res.text) if cap_res.content else cap_res.text
                        raise ClientError(f"Upload capability request rejected ({cap_res.status_code}): {detail}")
            except ClientError:
                raise
            except Exception:
                pass

        manifest_chunks: List[ChunkMetadata] = []
        uploaded_records: List[Tuple[ExpoClient, str]] = []

        try:
            for seq, c_id, shard_placements, o_s, e_s, p_l in shard_assignments:
                manifest_shards: List[ShardMetadata] = []
                for shard, n_id, n_endpoint in shard_placements:
                    ep = n_endpoint or self.base_url
                    if hasattr(self, "nodes_info") or hasattr(self, "node_map") or not hasattr(self, "get_node_client") or type(self) is not ExpoClient:
                        node_client = self
                        self.base_url = ep
                    else:
                        node_client = self.get_node_client(n_id, endpoint=ep, coordinator_url=coordinator_url)


                    opaque_filename = f"{shard.shard_id}"
                    if not opaque_filename.endswith(".dat"):
                        opaque_filename += ".dat"
                        
                    shard_cap = upload_caps.get(shard.shard_id, {}).get(n_id)
                    if shard_cap:
                        try:
                            upload_meta = node_client.upload_chunk_bytes(shard.payload, opaque_filename, capability_token=shard_cap)
                        except TypeError:
                            upload_meta = node_client.upload_chunk_bytes(shard.payload, opaque_filename)
                    else:
                        upload_meta = node_client.upload_chunk_bytes(shard.payload, opaque_filename)
                    stored_file_id = upload_meta.get("file_id", shard.shard_id)

                    uploaded_records.append((node_client, stored_file_id))

                    manifest_shards.append(
                        ShardMetadata(
                            shard_id=stored_file_id,
                            chunk_id=c_id,
                            shard_index=shard.shard_index,
                            shard_type=shard.shard_type,
                            shard_size=len(shard.payload),
                            shard_sha256=shard.sha256,
                            node_id=n_id,
                            node_endpoint=ep,
                        )
                    )

                manifest_chunks.append(
                    ChunkMetadata(
                        chunk_id=c_id,
                        sequence=seq,
                        size=e_s,
                        sha256=sha256_map[c_id],
                        original_ciphertext_size=o_s,
                        encoded_size=e_s,
                        padding_length=p_l,
                        data_shard_count=k,
                        parity_shard_count=m,
                        shards=manifest_shards,
                    )
                )

        except Exception as exc:
            for client_item, stored_id in uploaded_records:
                try:
                    client_item.delete_file(stored_id)
                except Exception:
                    pass
            raise ClientError(f"Multi-node shard upload failed during transfer: {str(exc)}") from exc

        file_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        encrypted_size = len(ciphertext)
        
        manifest = FileManifest(
            file_id=file_id,
            original_filename=path.name,
            original_size=orig_size,
            original_sha256=orig_sha256,
            encrypted_size=encrypted_size,
            chunk_size=c_size,
            chunk_count=len(manifest_chunks),
            manifest_version=3,
            encryption_algorithm="AES-256-GCM",
            nonce_hex=nonce.hex(),
            created_at=created_at,
            chunks=manifest_chunks,
            redundancy_mode="erasure",
            erasure_coding_algorithm="Reed-Solomon-ZFEC",
            data_shards=k,
            parity_shards=m,
            total_shards=total_shards,
        )

        return manifest, dek

    def download_and_decrypt_file(
        self,
        manifest_input: Union[FileManifest, Dict[str, Any], str],
        key_input: Union[bytes, str],
        output_path: str | Path,
        coordinator_url: Optional[str] = None,
    ) -> Path:
        """
        Multi-Node Replicated / Erasure-Coded Download Pipeline:
        1. Parses FileManifest and resolves encryption key.
        2. Routes to erasure-coded download pipeline if manifest.redundancy_mode == 'erasure'.
        3. Otherwise uses replicated download pipeline with primary-to-replica failover.
        4. Decrypts and verifies reconstructed original file SHA-256.
        """
        if isinstance(manifest_input, FileManifest):
            manifest = manifest_input
        elif isinstance(manifest_input, str):
            manifest = FileManifest.from_json(manifest_input)
        elif isinstance(manifest_input, dict):
            manifest = FileManifest.model_validate(manifest_input)
        else:
            raise ClientError("Invalid manifest input: must be FileManifest, dict, or JSON string.")

        if isinstance(key_input, bytes):
            dek = key_input
        elif isinstance(key_input, str):
            try:
                dek = bytes.fromhex(key_input.strip())
            except ValueError:
                raise ClientError("Invalid key input: string key must be valid hex.")
        else:
            raise ClientError("Invalid key input: must be bytes or hex string.")

        if len(dek) != AESGCMCrypto.KEY_SIZE_BYTES:
            raise ClientError(f"Invalid key length: expected {AESGCMCrypto.KEY_SIZE_BYTES} bytes, got {len(dek)}.")

        nonce = bytes.fromhex(manifest.nonce_hex)

        if manifest.redundancy_mode == "erasure":
            return self._download_and_decrypt_erasure_coded_file(
                manifest=manifest,
                dek=dek,
                nonce=nonce,
                output_path=output_path,
                coordinator_url=coordinator_url,
            )

        # Replication download path
        downloaded_chunks: List[Tuple[int, bytes]] = []

        for chunk_meta in manifest.chunks:
            placements = chunk_meta.get_effective_placements()
            if not placements:
                raise ClientError(f"No valid placement records for Chunk ID '{chunk_meta.chunk_id}' in manifest.")

            accepted_chunk_bytes: Optional[bytes] = None
            attempt_logs: List[str] = []

            for placement in placements:
                n_endpoint = placement.node_endpoint
                n_id = placement.node_id

                if not n_endpoint and coordinator_url:
                    try:
                        from coordinator.coordinator_client import CoordinatorClient
                        coord_client = CoordinatorClient(coordinator_url=coordinator_url, timeout=self.timeout)
                        node_rec = coord_client.get_node(n_id)
                        n_endpoint = node_rec.get("advertised_endpoint") or node_rec.get("endpoint")
                    except Exception:
                        n_endpoint = None

                if not n_endpoint:
                    n_endpoint = self.base_url

                if hasattr(self, "nodes_info") or hasattr(self, "node_map") or not hasattr(self, "get_node_client") or type(self) is not ExpoClient:
                    node_client = self
                    self.base_url = n_endpoint
                else:
                    node_client = self.get_node_client(n_id, endpoint=n_endpoint, coordinator_url=coordinator_url)


                try:
                    target_chunk_id = getattr(placement, "chunk_id", None) or chunk_meta.chunk_id
                    cap_token = getattr(placement, "capability", None)
                    if cap_token:
                        try:
                            chunk_bytes = node_client.download_chunk_bytes(target_chunk_id, capability_token=cap_token)
                        except TypeError:
                            chunk_bytes = node_client.download_chunk_bytes(target_chunk_id)
                    else:
                        chunk_bytes = node_client.download_chunk_bytes(target_chunk_id)
                    computed_hash = compute_sha256(chunk_bytes)
                    if computed_hash != chunk_meta.sha256.lower():
                        attempt_logs.append(
                            f"Node '{n_id}' ({n_endpoint}) [{placement.role}]: SHA-256 mismatch (Expected '{chunk_meta.sha256}', got '{computed_hash}')"
                        )
                        continue

                    accepted_chunk_bytes = chunk_bytes
                    break
                except Exception as exc:
                    attempt_logs.append(f"Node '{n_id}' ({n_endpoint}) [{placement.role}]: Download error - {str(exc)}")

            if accepted_chunk_bytes is None:
                log_summary = "; ".join(attempt_logs)
                if any("SHA-256 mismatch" in log for log in attempt_logs):
                    raise IntegrityVerificationError(
                        f"Chunk SHA-256 verification failed for File ID '{manifest.file_id}' (Chunk ID: '{chunk_meta.chunk_id}', Sequence: {chunk_meta.sequence}): {log_summary}"
                    )
                raise ClientError(
                    f"All placements failed for File ID '{manifest.file_id}' (Chunk ID: '{chunk_meta.chunk_id}', Sequence: {chunk_meta.sequence}): {log_summary}"
                )

            downloaded_chunks.append((chunk_meta.sequence, accepted_chunk_bytes))

        # Reassemble ciphertext
        ciphertext = reassemble_chunks(downloaded_chunks)
        if len(ciphertext) != manifest.encrypted_size:
            raise IntegrityVerificationError(
                f"Encrypted size mismatch for File ID '{manifest.file_id}': Expected {manifest.encrypted_size} bytes, reassembled {len(ciphertext)} bytes."
            )

        # Decrypt payload
        try:
            plaintext = AESGCMCrypto.decrypt(ciphertext, key=dek, nonce=nonce)
        except DecryptionError as exc:
            raise IntegrityVerificationError(f"Decryption failed for File ID '{manifest.file_id}': {str(exc)}") from exc

        # Verify reconstructed file SHA-256
        reconstructed_sha256 = compute_sha256(plaintext)
        if reconstructed_sha256 != manifest.original_sha256.lower():
            raise IntegrityVerificationError(
                f"Final reconstructed file SHA-256 mismatch for File ID '{manifest.file_id}'! Expected '{manifest.original_sha256}', calculated '{reconstructed_sha256}'."
            )

        # Save to output file
        out_p = Path(output_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "wb") as f_out:
            f_out.write(plaintext)

        return out_p

    def _download_and_decrypt_erasure_coded_file(
        self,
        manifest: FileManifest,
        dek: bytes,
        nonce: bytes,
        output_path: str | Path,
        coordinator_url: Optional[str] = None,
    ) -> Path:
        """Helper to execute erasure-coded download & Reed-Solomon reconstruction pipeline."""
        downloaded_chunks: List[Tuple[int, bytes]] = []

        for chunk_meta in manifest.chunks:
            k = chunk_meta.data_shard_count or manifest.data_shards or 4
            m = chunk_meta.parity_shard_count or manifest.parity_shards or 2
            padlen = chunk_meta.padding_length if chunk_meta.padding_length is not None else 0
            orig_c_size = chunk_meta.original_ciphertext_size or chunk_meta.size
            shards = chunk_meta.shards

            if not shards:
                raise ClientError(f"No valid shard placement records for Chunk ID '{chunk_meta.chunk_id}' in erasure coding manifest.")

            available_shards: List[Tuple[int, bytes]] = []
            attempt_logs: List[str] = []

            for shard_meta in shards:
                n_endpoint = shard_meta.node_endpoint
                n_id = shard_meta.node_id

                if not n_endpoint and coordinator_url:
                    try:
                        from coordinator.coordinator_client import CoordinatorClient
                        coord_client = CoordinatorClient(coordinator_url=coordinator_url, timeout=self.timeout)
                        node_rec = coord_client.get_node(n_id)
                        n_endpoint = node_rec.get("advertised_endpoint") or node_rec.get("endpoint")
                    except Exception:
                        n_endpoint = None

                if not n_endpoint:
                    n_endpoint = self.base_url

                if hasattr(self, "nodes_info") or hasattr(self, "node_map") or not hasattr(self, "get_node_client") or type(self) is not ExpoClient:
                    node_client = self
                    self.base_url = n_endpoint
                else:
                    node_client = self.get_node_client(n_id, endpoint=n_endpoint, coordinator_url=coordinator_url)


                try:
                    cap_token = getattr(shard_meta, "capability", None)
                    if cap_token:
                        try:
                            shard_bytes = node_client.download_chunk_bytes(shard_meta.shard_id, capability_token=cap_token)
                        except TypeError:
                            shard_bytes = node_client.download_chunk_bytes(shard_meta.shard_id)
                    else:
                        shard_bytes = node_client.download_chunk_bytes(shard_meta.shard_id)
                    computed_hash = compute_sha256(shard_bytes)
                    if computed_hash != shard_meta.shard_sha256.lower():
                        attempt_logs.append(
                            f"Shard {shard_meta.shard_index} ({shard_meta.shard_type}) on Node '{n_id}' ({n_endpoint}): SHA-256 mismatch (Expected '{shard_meta.shard_sha256}', got '{computed_hash}')"
                        )
                        continue

                    available_shards.append((shard_meta.shard_index, shard_bytes))
                    if len(available_shards) >= k:
                        break
                except Exception as exc:
                    attempt_logs.append(f"Shard {shard_meta.shard_index} ({shard_meta.shard_type}) on Node '{n_id}' ({n_endpoint}): Download error - {str(exc)}")

            if len(available_shards) < k:
                log_summary = "; ".join(attempt_logs)
                if any("SHA-256 mismatch" in log for log in attempt_logs):
                    raise IntegrityVerificationError(
                        f"Erasure coding shard SHA-256 verification failed for File ID '{manifest.file_id}' (Chunk ID: '{chunk_meta.chunk_id}', Sequence: {chunk_meta.sequence}): Only {len(available_shards)} valid shards retrieved, minimum {k} required. Details: {log_summary}"
                    )
                raise ClientError(
                    f"Insufficient valid shards to reconstruct File ID '{manifest.file_id}' (Chunk ID: '{chunk_meta.chunk_id}', Sequence: {chunk_meta.sequence}): Only {len(available_shards)} valid shards retrieved, minimum {k} required. Details: {log_summary}"
                )

            try:
                reconstructed_chunk_bytes = reconstruct_ciphertext_chunk(
                    available_shards=available_shards,
                    data_shards=k,
                    parity_shards=m,
                    padding_length=padlen,
                    original_ciphertext_size=orig_c_size,
                )
            except Exception as exc:
                raise IntegrityVerificationError(
                    f"Reconstruction failed for File ID '{manifest.file_id}' (Chunk ID: '{chunk_meta.chunk_id}'): {str(exc)}"
                ) from exc

            downloaded_chunks.append((chunk_meta.sequence, reconstructed_chunk_bytes))

        # Reassemble ciphertext
        ciphertext = reassemble_chunks(downloaded_chunks)
        if len(ciphertext) != manifest.encrypted_size:
            raise IntegrityVerificationError(
                f"Encrypted size mismatch for File ID '{manifest.file_id}': Expected {manifest.encrypted_size} bytes, reassembled {len(ciphertext)} bytes."
            )

        # Decrypt payload
        try:
            plaintext = AESGCMCrypto.decrypt(ciphertext, key=dek, nonce=nonce)
        except DecryptionError as exc:
            raise IntegrityVerificationError(f"Decryption failed for File ID '{manifest.file_id}': {str(exc)}") from exc

        # Verify reconstructed file SHA-256
        reconstructed_sha256 = compute_sha256(plaintext)
        if reconstructed_sha256 != manifest.original_sha256.lower():
            raise IntegrityVerificationError(
                f"Final reconstructed file SHA-256 mismatch for File ID '{manifest.file_id}'! Expected '{manifest.original_sha256}', calculated '{reconstructed_sha256}'."
            )

        # Save to output file
        out_p = Path(output_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "wb") as f_out:
            f_out.write(plaintext)

        return out_p


    # Phase 3C Diagnostic Methods
    def check_node_connectivity(
        self,
        node_id_or_endpoint: str,
        coordinator_url: Optional[str] = None,
        timeout: float = 5.0,
    ) -> Any:
        """
        Phase 3C Node Reachability Diagnostic:
        Performs direct GET /health reachability probe on node advertised_endpoint.
        If node_id is passed, resolves endpoint via Coordinator first.
        """
        from client.placement import check_node_reachability

        endpoint = node_id_or_endpoint
        node_id = "UNKNOWN"

        if not endpoint.startswith("http://") and not endpoint.startswith("https://"):
            # Assume it is a node_id, resolve via Coordinator
            coord_url = coordinator_url or "http://127.0.0.1:9000"
            from coordinator.coordinator_client import CoordinatorClient
            coord_client = CoordinatorClient(coordinator_url=coord_url, timeout=self.timeout)
            node_record = coord_client.get_node(node_id_or_endpoint)
            endpoint = node_record.get("advertised_endpoint") or node_record.get("endpoint") or ""
            node_id = node_record.get("node_id", node_id_or_endpoint)

        return check_node_reachability(endpoint=endpoint, node_id=node_id, timeout=timeout)

    def check_all_nodes_connectivity(
        self,
        coordinator_url: str = "http://127.0.0.1:9000",
        status_filter: Optional[str] = None,
        timeout: float = 5.0,
    ) -> List[Any]:
        """
        Phase 3C Network-Wide Diagnostic:
        Discovers all registered Storage Nodes from Coordinator and verifies consumer reachability for each.
        """
        from coordinator.coordinator_client import CoordinatorClient
        from client.placement import check_node_reachability, NodeReachabilityResult

        coord_client = CoordinatorClient(coordinator_url=coordinator_url, timeout=self.timeout)
        nodes = coord_client.list_nodes(status=status_filter)

        results: List[NodeReachabilityResult] = []
        for n in nodes:
            n_id = n.get("node_id", "UNKNOWN")
            ep = n.get("advertised_endpoint") or n.get("endpoint")
            if ep:
                res = check_node_reachability(endpoint=ep, node_id=n_id, timeout=timeout)
                results.append(res)
            else:
                results.append(NodeReachabilityResult(node_id=n_id, endpoint="NONE", reachability="UNREACHABLE", reason="No endpoint registered"))

        return results

    # -------------------------------------------------------------------------
    # Phase 5B: Unified File-Management Operations
    # -------------------------------------------------------------------------

    def upload_logical_file(
        self,
        file_path: str | Path,
        coordinator_url: str = "http://127.0.0.1:9000",
        key: Optional[bytes] = None,
        chunk_size: Optional[int] = None,
        redundancy_mode: str = "replication",
        replication_factor: int = 2,
        data_shards: Optional[int] = None,
        parity_shards: Optional[int] = None,
        target_node_count: int = 3,
        preferred_connectivity: Optional[str] = None,
        require_reachable: bool = False,
        candidate_nodes: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Unified upload: Encrypts, uploads chunks, and registers the file in the Coordinator catalog."""
        # 1. Perform client-side encryption and distributed physical upload
        manifest, dek = self.encrypt_and_upload_file(
            file_path=file_path,
            key=key,
            chunk_size=chunk_size,
            redundancy_mode=redundancy_mode,
            replication_factor=replication_factor,
            data_shards=data_shards,
            parity_shards=parity_shards,
            target_node_count=target_node_count,
            preferred_connectivity=preferred_connectivity,
            require_reachable=require_reachable,
            candidate_nodes=candidate_nodes,
            coordinator_url=coordinator_url
        )

        # 2. Register the successful manifest to the Coordinator Catalog
        from coordinator.coordinator_client import CoordinatorClient
        coord_client = CoordinatorClient(coordinator_url=coordinator_url, auth_token=self.auth_token, timeout=self.timeout)
        
        record = coord_client.register_logical_file(manifest.model_dump())
        
        return {
            "file_id": record["file_id"],
            "key_hex": dek.hex(),
            "manifest": manifest,
            "catalog_record": record,
            "status": "available"
        }

    def list_logical_files(self, coordinator_url: str = "http://127.0.0.1:9000") -> List[Dict[str, Any]]:
        """Lists files owned by this client via the Coordinator Catalog."""
        from coordinator.coordinator_client import CoordinatorClient
        coord_client = CoordinatorClient(coordinator_url=coordinator_url, auth_token=self.auth_token, timeout=self.timeout)
        return coord_client.list_logical_files()

    def download_logical_file(
        self,
        file_id: str,
        output_path: str | Path,
        key_input: Union[bytes, str],
        coordinator_url: str = "http://127.0.0.1:9000"
    ) -> Dict[str, Any]:
        """Unified download: Fetches catalog metadata, downloads physical chunks, and decrypts."""
        from coordinator.coordinator_client import CoordinatorClient
        from client.chunker import FileManifest
        
        # 1. Retrieve logical file manifest from Catalog
        coord_client = CoordinatorClient(coordinator_url=coordinator_url, auth_token=self.auth_token, timeout=self.timeout)
        record = coord_client.get_logical_file(file_id)
        if record.get("status") in ("deleted", "deleting"):
            raise ClientError(f"Logical file '{file_id}' has been marked as '{record.get('status')}' and cannot be downloaded.")
        
        manifest_data = json.loads(record["manifest_json"])
        manifest = FileManifest(**manifest_data)
        
        # 2. Perform distributed physical download and decryption
        out_path = self.download_and_decrypt_file(
            manifest_input=manifest,
            output_path=output_path,
            key_input=key_input,
            coordinator_url=coordinator_url
        )
        return {
            "status": "downloaded",
            "output_path": out_path,
            "sha256": manifest.original_sha256
        }

    def delete_logical_file(
        self,
        file_id: str,
        coordinator_url: str = "http://127.0.0.1:9000",
        sync_cleanup: bool = False,
    ) -> Dict[str, Any]:
        """Unified deletion: Delegates durable physical cleanup to Coordinator deletion jobs."""
        from coordinator.coordinator_client import CoordinatorClient
        
        coord_client = CoordinatorClient(coordinator_url=coordinator_url, auth_token=self.auth_token, timeout=self.timeout)
        
        # 1. Transition to 'deleting' state idempotently. Spawns durable physical cleanup job on the Coordinator.
        record = coord_client.delete_logical_file(file_id, sync_cleanup=sync_cleanup)
        
        return {
            "status": record.get("status", "deleting"),
            "file_id": file_id,
            "physical_success_count": 0,
            "physical_failure_count": 0,
            "catalog_record": record
        }

    def get_file_storage_status(
        self,
        file_id: str,
        coordinator_url: str = "http://127.0.0.1:9000",
    ) -> Dict[str, Any]:
        """Queries physical storage health, degradation status, and placement health for a logical file."""
        from coordinator.coordinator_client import CoordinatorClient
        coord_client = CoordinatorClient(coordinator_url=coordinator_url, auth_token=self.auth_token, timeout=self.timeout)
        return coord_client.get_file_status(file_id)

    def get_quota(
        self,
        coordinator_url: str = "http://127.0.0.1:9000",
    ) -> Dict[str, Any]:
        """Queries account storage limits, committed usage, in-flight reservations, and available quota."""
        from coordinator.coordinator_client import CoordinatorClient
        coord_client = CoordinatorClient(coordinator_url=coordinator_url, auth_token=self.auth_token, timeout=self.timeout)
        return coord_client.get_quota()

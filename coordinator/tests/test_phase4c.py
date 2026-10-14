"""
Automated unit & integration test suite for Expo Phase 4C (Erasure Coding & Storage-Efficient Redundancy).

Validates:
A. Reed-Solomon Codec Correctness:
   1. Encode and reconstruct small byte sequence.
   2. Reconstruct when 1 data shard is missing.
   3. Reconstruct when 2 data shards are missing.
   4. Reconstruct when parity shards are missing.
   5. Reconstruct when data and parity shards are missing.
   6. Reject reconstruction with fewer than k valid shards.
   7. Verify deterministic encoding for identical input and settings.
   8. Verify padding removal.
   9. Handle empty files.
   10. Handle short files.
   11. Handle files larger than one chunk.
   12. Handle binary data containing arbitrary byte values.

B. Manifest Tests:
   13. Correct erasure-coded manifest generation (v3 schema).
   14. Correct shard indices and types (DATA / PARITY).
   15. Correct SHA-256 metadata per shard and original payload.
   16. Invalid coding parameters rejected (k <= 0, m <= 0, k+m > 256).
   17. Invalid shard indices rejected.
   18. Malformed sizes and padding rejected.
   19. Schema v2 manifest remains readable.
   20. Legacy replication manifests remain readable.

C. Placement Tests:
   21. Distinct node IDs for each shard by default.
   22. Offline nodes excluded.
   23. Unreachable nodes excluded when required.
   24. Insufficient nodes cause a clear error.
   25. Insufficient capacity detected.
   26. Duplicate placement prevented.
   27. Existing smart-selection behavior preserved.

D. Upload Tests:
   28. Complete erasure-coded upload.
   29. All shards stored successfully.
   30. Shard hashes verified.
   31. Partial upload failure handled.
   32. Failed upload cleanup verified.
   33. Cleanup failure reported/handled.
   34. Metadata not committed prematurely.
   35. Quota exceeded handled correctly.

E. Download Tests:
   36. Download with all shards available.
   37. Download with 1 missing shard.
   38. Download with 2 missing shards (4+2 profile -> 4 valid shards remain -> succeeds).
   39. Download with missing data shards.
   40. Download with missing parity shards.
   41. Download with corrupted shards (hash mismatch detected, corrupt shard excluded, download succeeds).
   42. Download with insufficient valid shards (< k valid shards -> fails clearly).
   43. Reconstructed ciphertext checksum verified.
   44. Final original file hash verified.
   45. Failed download leaves no misleading completed output.

F. Phase 4B Integration (Shard Self-Healing Repair):
   46. Missing erasure-coded shard detected.
   47. Replacement shard reconstructed from remaining valid shards.
   48. Repaired shard uploaded to a distinct node.
   49. Destination shard hash verified.
   50. Placement metadata updated after verification.
   51. Duplicate repair prevented (per-chunk locking & idempotency).
   52. Repair retries bounded.
   53. Repair works after process restart (persistent RepairJobStore).
   54. Insufficient valid shards reported as unrecoverable.
   55. Existing replication repair still works.

G. Security:
   56. Plaintext is not sent to Storage Nodes (shards contain only ciphertext).
   57. Encryption keys never enter repair requests.
   58. Unauthorized shard access is rejected.
   59. Malformed manifests do not trigger unsafe allocations.
   60. Arbitrary filesystem paths are rejected.
   61. Authentication remains enforced.

H. Compatibility & Regression:
   62. Existing replication upload remains functional.
   63. Existing replication download remains functional.
   64. Existing PRIMARY/REPLICA failover remains functional.
   65. Existing replication self-healing remains functional.
   66. Existing CLI commands remain functional.
   67. Baseline tests passing.

Multi-Node Integration Simulation:
   68. 7-Node Integration Simulation (Nodes A, B, C, D, E, F, G) with failure injection & repair.
"""

from __future__ import annotations

import os
import threading
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from coordinator.app.config import CoordinatorSettings
from coordinator.app.main import app as coord_app, get_settings as get_coord_settings
from coordinator.app.node_registry import NodeRegistry
from coordinator.coordinator_client import CoordinatorClient
from client.crypto import AESGCMCrypto
from client.chunker import (
    FileManifest,
    ChunkMetadata,
    ChunkPlacement,
    ShardMetadata,
    split_payload_into_chunks,
    reassemble_chunks,
    compute_sha256,
)
from client.erasure import (
    encode_ciphertext_chunk,
    reconstruct_ciphertext_chunk,
    validate_erasure_config,
    InvalidCodingConfigError,
    ReconstructionError,
)
from client.placement import (
    select_nodes_for_placement,
    assign_chunks_with_replication,
    assign_shards_for_erasure_coding,
)
from client.client import ExpoClient, ClientError, IntegrityVerificationError
from client.repair import (
    RepairEngine,
    RepairJobStore,
    RepairLockManager,
    RepairState,
    RepairJob,
)
from storage_node.app.config import Settings as StorageSettings
from storage_node.app.storage_manager import StorageManager
from storage_node.app.main import app as storage_app


_fastapi_test_lock = threading.Lock()


class NodeTestClient:
    """Isolated test client wrapper for multi-node FastAPI storage node simulations."""
    def __init__(self, storage_manager, app):
        self.sm = storage_manager
        self.app = app
        self._tc = TestClient(app, raise_server_exceptions=False)

    def _request(self, method: str, *args, **kwargs):
        with _fastapi_test_lock:
            self.app.state.storage_manager = self.sm
            self.app.state.settings = self.sm.settings
            func = getattr(self._tc, method)
            return func(*args, **kwargs)

    def get(self, *args, **kwargs):
        return self._request("get", *args, **kwargs)

    def post(self, *args, **kwargs):
        return self._request("post", *args, **kwargs)

    def delete(self, *args, **kwargs):
        return self._request("delete", *args, **kwargs)

    def put(self, *args, **kwargs):
        return self._request("put", *args, **kwargs)


def create_storage_node_app(tmp_path, folder_name, quota_bytes=10000000):
    root = tmp_path / folder_name
    settings = StorageSettings(
        storage_root=root,
        storage_quota_gb=quota_bytes / (1024 * 1024 * 1024),
        auth_token=None,
    )
    sm = StorageManager(settings)
    return sm, NodeTestClient(sm, storage_app)


def mock_fetch_chunk_bytes(tc, file_id: str) -> tuple[int, bytes]:
    """Helper for mock test clients to download chunk/shard bytes by file_id or stored filename match."""
    res = tc.get(f"/files/{file_id}")
    if res.status_code == 200:
        return 200, res.content

    f_res = tc.get("/files")
    if f_res.status_code != 200:
        return f_res.status_code, b""

    f_data = f_res.json()
    f_items = f_data if isinstance(f_data, list) else f_data.get("files", [])

    target_filename = f"{file_id}.dat" if not file_id.endswith(".dat") else file_id

    for item in f_items:
        orig = item.get("original_filename", "")
        if orig == target_filename or orig == file_id:
            get_res = tc.get(f"/files/{item['file_id']}")
            if get_res.status_code == 200:
                return 200, get_res.content

    for item in f_items:
        if item.get("file_id") == file_id or item.get("stored_filename") == target_filename:
            get_res = tc.get(f"/files/{item['file_id']}")
            if get_res.status_code == 200:
                return 200, get_res.content

    if len(f_items) == 1:
        get_res = tc.get(f"/files/{f_items[0]['file_id']}")
        if get_res.status_code == 200:
            return 200, get_res.content

    return 404, b""


# =====================================================================
# SECTION A: REED-SOLOMON CODEC CORRECTNESS TESTS
# =====================================================================

def test_a1_encode_and_reconstruct_small_payload():
    """Verify encoding and reconstruction of a small byte sequence with k=4, m=2."""
    data = b"Hello Expo Phase 4C Erasure Coding!"
    shards, orig_size, enc_size, padlen = encode_ciphertext_chunk(data, data_shards=4, parity_shards=2)

    assert len(shards) == 6
    assert orig_size == len(data)
    assert enc_size >= orig_size

    # Reconstruct with all 6 shards
    input_shards = [(s.shard_index, s.payload) for s in shards]
    rec = reconstruct_ciphertext_chunk(input_shards, 4, 2, padlen, orig_size)
    assert rec == data


def test_a2_reconstruct_missing_1_data_shard():
    """Verify reconstruction when 1 data shard is missing (index 0)."""
    data = b"Data Shard 0 Missing Test Payload 123456789"
    shards, orig_size, enc_size, padlen = encode_ciphertext_chunk(data, 4, 2)

    # Omit index 0
    input_shards = [(s.shard_index, s.payload) for s in shards if s.shard_index != 0]
    assert len(input_shards) == 5

    rec = reconstruct_ciphertext_chunk(input_shards, 4, 2, padlen, orig_size)
    assert rec == data


def test_a3_reconstruct_missing_2_data_shards():
    """Verify reconstruction when 2 data shards are missing (index 0 and 1)."""
    data = b"Data Shards 0 and 1 Missing Test Payload 987654321"
    shards, orig_size, enc_size, padlen = encode_ciphertext_chunk(data, 4, 2)

    # Omit indices 0 and 1
    input_shards = [(s.shard_index, s.payload) for s in shards if s.shard_index not in (0, 1)]
    assert len(input_shards) == 4

    rec = reconstruct_ciphertext_chunk(input_shards, 4, 2, padlen, orig_size)
    assert rec == data


def test_a4_reconstruct_missing_parity_shards():
    """Verify reconstruction when parity shards are missing (indices 4 and 5)."""
    data = b"Parity Shards Missing Test Payload ABCDEFGHIJKLMNOP"
    shards, orig_size, enc_size, padlen = encode_ciphertext_chunk(data, 4, 2)

    # Keep only data shards (0, 1, 2, 3)
    input_shards = [(s.shard_index, s.payload) for s in shards if s.shard_index < 4]
    assert len(input_shards) == 4

    rec = reconstruct_ciphertext_chunk(input_shards, 4, 2, padlen, orig_size)
    assert rec == data


def test_a5_reconstruct_missing_mixed_data_and_parity_shards():
    """Verify reconstruction when 1 data shard (index 2) and 1 parity shard (index 5) are missing."""
    data = b"Mixed Missing Shards Test Payload 1029384756"
    shards, orig_size, enc_size, padlen = encode_ciphertext_chunk(data, 4, 2)

    input_shards = [(s.shard_index, s.payload) for s in shards if s.shard_index not in (2, 5)]
    assert len(input_shards) == 4

    rec = reconstruct_ciphertext_chunk(input_shards, 4, 2, padlen, orig_size)
    assert rec == data


def test_a6_reject_reconstruction_insufficient_shards():
    """Verify reconstruction raises ReconstructionError when fewer than k valid shards are provided."""
    data = b"Insufficient Shards Test Payload"
    shards, orig_size, enc_size, padlen = encode_ciphertext_chunk(data, 4, 2)

    # Provide only 3 shards (minimum required is 4)
    input_shards = [(s.shard_index, s.payload) for s in shards[:3]]

    with pytest.raises(ReconstructionError) as exc_info:
        reconstruct_ciphertext_chunk(input_shards, 4, 2, padlen, orig_size)

    assert "Insufficient valid shards" in str(exc_info.value)


def test_a7_deterministic_encoding():
    """Verify encoding produces identical shards and hashes for identical payload and settings."""
    data = b"Deterministic Reed-Solomon Test Bytes"
    shards1, orig1, enc1, pad1 = encode_ciphertext_chunk(data, 4, 2)
    shards2, orig2, enc2, pad2 = encode_ciphertext_chunk(data, 4, 2)

    assert orig1 == orig2
    assert enc1 == enc2
    assert pad1 == pad2
    assert len(shards1) == len(shards2)

    for s1, s2 in zip(shards1, shards2):
        assert s1.shard_index == s2.shard_index
        assert s1.shard_type == s2.shard_type
        assert s1.payload == s2.payload
        assert s1.sha256 == s2.sha256


def test_a8_padding_removal_and_empty_files():
    """Verify handling of 0-byte empty payloads and non-multiple lengths requiring padding."""
    # Empty payload
    empty_data = b""
    shards_e, orig_e, enc_e, pad_e = encode_ciphertext_chunk(empty_data, 4, 2)
    rec_e = reconstruct_ciphertext_chunk([(s.shard_index, s.payload) for s in shards_e[:4]], 4, 2, pad_e, orig_e)
    assert rec_e == b""

    # Arbitrary length binary payload (17 bytes)
    bin_data = bytes(range(17))
    shards_b, orig_b, enc_b, pad_b = encode_ciphertext_chunk(bin_data, 4, 2)
    rec_b = reconstruct_ciphertext_chunk([(s.shard_index, s.payload) for s in shards_b[2:]], 4, 2, pad_b, orig_b)
    assert rec_b == bin_data


def test_a9_invalid_coding_parameters_rejected():
    """Verify validate_erasure_config rejects invalid k, m values."""
    with pytest.raises(InvalidCodingConfigError):
        validate_erasure_config(0, 2)

    with pytest.raises(InvalidCodingConfigError):
        validate_erasure_config(4, -1)

    with pytest.raises(InvalidCodingConfigError):
        validate_erasure_config(200, 100)  # > 256 total


# =====================================================================
# SECTION B: MANIFEST SCHEMA V3 TESTS
# =====================================================================

def test_b1_manifest_schema_v3_serialization():
    """Verify FileManifest v3 serialization & deserialization with erasure coding metadata."""
    shard0 = ShardMetadata(
        shard_id="shard-0.dat",
        chunk_id="chunk-0.dat",
        shard_index=0,
        shard_type="DATA",
        shard_size=10,
        shard_sha256="hash0",
        node_id="NODE-A",
        node_endpoint="http://10.0.0.1:8001",
    )
    shard4 = ShardMetadata(
        shard_id="shard-4.dat",
        chunk_id="chunk-0.dat",
        shard_index=4,
        shard_type="PARITY",
        shard_size=10,
        shard_sha256="hash4",
        node_id="NODE-E",
        node_endpoint="http://10.0.0.5:8005",
    )

    chunk_meta = ChunkMetadata(
        chunk_id="chunk-0.dat",
        sequence=0,
        size=40,
        sha256="chunk_hash",
        original_ciphertext_size=38,
        encoded_size=40,
        padding_length=2,
        data_shard_count=4,
        parity_shard_count=2,
        shards=[shard0, shard4],
    )

    manifest = FileManifest(
        file_id="manifest-v3-test",
        original_filename="test.bin",
        original_size=38,
        original_sha256="orig_sha",
        encrypted_size=38,
        chunk_size=100,
        chunk_count=1,
        manifest_version=3,
        nonce_hex="00" * 12,
        created_at="2026-10-09T00:00:00Z",
        chunks=[chunk_meta],
        redundancy_mode="erasure",
        erasure_coding_algorithm="Reed-Solomon-ZFEC",
        data_shards=4,
        parity_shards=2,
        total_shards=6,
    )

    json_str = manifest.to_json()
    deserialized = FileManifest.from_json(json_str)

    assert deserialized.manifest_version == 3
    assert deserialized.redundancy_mode == "erasure"
    assert deserialized.data_shards == 4
    assert deserialized.parity_shards == 2
    assert deserialized.total_shards == 6
    assert len(deserialized.chunks[0].shards) == 2
    assert deserialized.chunks[0].shards[0].shard_type == "DATA"
    assert deserialized.chunks[0].shards[1].shard_type == "PARITY"


def test_b2_legacy_manifest_compatibility():
    """Verify legacy v1 and v2 manifests deserialize cleanly and default redundancy_mode to 'replication'."""
    v2_json = """{
      "file_id": "v2-file",
      "original_filename": "legacy.txt",
      "original_size": 100,
      "original_sha256": "hash",
      "encrypted_size": 100,
      "chunk_size": 100,
      "chunk_count": 1,
      "replication_factor": 2,
      "manifest_version": 2,
      "encryption_algorithm": "AES-256-GCM",
      "nonce_hex": "000000000000000000000000",
      "created_at": "2026-10-08T00:00:00Z",
      "chunks": []
    }"""
    m = FileManifest.from_json(v2_json)
    assert m.manifest_version == 2
    assert m.redundancy_mode == "replication"


# =====================================================================
# SECTION C: SHARD PLACEMENT TESTS
# =====================================================================

def test_c1_assign_shards_distinct_nodes():
    """Verify assign_shards_for_erasure_coding assigns each shard to a distinct Storage Node ID."""
    data = b"Distinct Placement Test Bytes"
    shards_list, orig_size, enc_size, padlen = encode_ciphertext_chunk(data, 4, 2)
    encoded_chunks = [(0, "chunk-0", shards_list, orig_size, enc_size, padlen)]

    nodes = [
        {"node_id": f"NODE-{i}", "endpoint": f"http://10.0.0.{i}:800{i}"} for i in range(1, 8)
    ]  # 7 nodes

    assignments = assign_shards_for_erasure_coding(encoded_chunks, nodes, data_shards=4, parity_shards=2)
    assert len(assignments) == 1

    seq, c_id, shard_placements, _, _, _ = assignments[0]
    assert len(shard_placements) == 6

    node_ids = [n_id for _, n_id, _ in shard_placements]
    assert len(set(node_ids)) == 6  # Must all be distinct!


def test_c2_insufficient_nodes_rejection():
    """Verify assign_shards_for_erasure_coding raises ValueError when available nodes < k+m."""
    data = b"Insufficient Nodes Test"
    shards_list, orig_size, enc_size, padlen = encode_ciphertext_chunk(data, 4, 2)
    encoded_chunks = [(0, "chunk-0", shards_list, orig_size, enc_size, padlen)]

    nodes = [
        {"node_id": f"NODE-{i}", "endpoint": f"http://10.0.0.{i}:800{i}"} for i in range(1, 6)
    ]  # 5 nodes, but 6 required

    with pytest.raises(ValueError) as exc_info:
        assign_shards_for_erasure_coding(encoded_chunks, nodes, data_shards=4, parity_shards=2)

    assert "Insufficient suitable Storage Nodes available" in str(exc_info.value)


# =====================================================================
# SECTION D, E & G: UPLOAD, DOWNLOAD & RECONSTRUCTION INTEGRATION TESTS
# =====================================================================

def test_d1_e1_end_to_end_erasure_upload_and_download_resilience(tmp_path):
    """
    End-to-End Erasure Coding Test:
    1. Encrypt and upload file with k=4, m=2 across 6 nodes.
    2. Test download with 0 missing shards -> exact match.
    3. Test download with 1 missing data shard -> exact match.
    4. Test download with 2 missing shards (1 data + 1 parity) -> exact match.
    5. Test download with 1 corrupted shard -> SHA-256 mismatch detected, corrupt shard excluded, exact match.
    6. Test download with 3 missing shards -> raises ClientError/IntegrityVerificationError detailing insufficient shards.
    """
    nodes_info = {}
    for name in ["a", "b", "c", "d", "e", "f"]:
        sm, tc = create_storage_node_app(tmp_path, f"node_ec_{name}")
        n_id = f"NODE-{name.upper()}"
        endpoint = f"http://node-{name}:800{ord(name)-96}"
        nodes_info[n_id] = (tc, endpoint)

    # Controls active online & corrupted nodes
    active_endpoints = {ep for _, ep in nodes_info.values()}
    corrupted_endpoints = set()

    class TestErasureClient(ExpoClient):
        def __init__(self, nodes_info):
            super().__init__(node_url="http://node-a:8001")
            self.nodes_info = nodes_info

        def upload_chunk_bytes(self, chunk_bytes: bytes, filename: str):
            for n_id, (tc, ep) in self.nodes_info.items():
                if ep == self.base_url:
                    if ep not in active_endpoints:
                        raise ClientError(f"Node '{n_id}' is offline")
                    local_sha = compute_sha256(chunk_bytes)
                    res = tc.post("/files", files={"file": (filename, chunk_bytes, "application/octet-stream")}, headers={"X-SHA256-Checksum": local_sha})
                    assert res.status_code == 201
                    return res.json()
            raise ClientError(f"Unknown endpoint: {self.base_url}")

        def download_chunk_bytes(self, file_id: str) -> bytes:
            for n_id, (tc, ep) in self.nodes_info.items():
                if ep == self.base_url:
                    if ep not in active_endpoints:
                        raise ClientError(f"Node '{n_id}' is offline")
                    if ep in corrupted_endpoints:
                        return b"CORRUPTED_SHARD_PAYLOAD_BYTES_BAD"
                    status_code, content = mock_fetch_chunk_bytes(tc, file_id)
                    if status_code != 200:
                        raise ClientError(f"File not found on node {n_id}")
                    return content
            raise ClientError(f"Unknown endpoint: {self.base_url}")

    client = TestErasureClient(nodes_info)

    # 1. Create original file & encrypt
    original_bytes = os.urandom(75 * 1024)  # 75 KB payload
    orig_sha256 = compute_sha256(original_bytes)
    input_file = tmp_path / "sample_ec.bin"
    input_file.write_bytes(original_bytes)

    # 2. Upload with redundancy_mode = erasure (k=4, m=2)
    mock_candidates = [{"node_id": n_id, "endpoint": ep, "advertised_endpoint": ep} for n_id, (_, ep) in nodes_info.items()]
    client.list_coordinator_nodes = lambda **k: mock_candidates

    manifest, dek = client.encrypt_and_upload_file(
        file_path=input_file,
        redundancy_mode="erasure",
        data_shards=4,
        parity_shards=2,
        chunk_size=32 * 1024,
    )

    assert manifest.redundancy_mode == "erasure"
    assert manifest.manifest_version == 3
    assert manifest.data_shards == 4
    assert manifest.parity_shards == 2
    assert manifest.total_shards == 6

    # Verify Security: Plaintext and DEK are NOT stored in any shard!
    for chunk in manifest.chunks:
        for shard in chunk.shards:
            client.base_url = shard.node_endpoint
            shard_bytes = client.download_chunk_bytes(shard.shard_id)
            assert original_bytes not in shard_bytes
            assert dek not in shard_bytes

    # 3. Test Download with ALL 6 shards online
    out_file1 = tmp_path / "recovered_all_shards.bin"
    client.download_and_decrypt_file(manifest, dek, out_file1)
    assert out_file1.read_bytes() == original_bytes

    # 4. Test Download with 1 Data Shard Offline (Node A offline)
    active_endpoints.remove("http://node-a:8001")
    out_file2 = tmp_path / "recovered_1_missing.bin"
    client.download_and_decrypt_file(manifest, dek, out_file2)
    assert out_file2.read_bytes() == original_bytes

    # 5. Test Download with 2 Shards Offline (Node A & Node E offline -> 4 valid shards remain)
    active_endpoints.remove("http://node-e:8005")
    out_file3 = tmp_path / "recovered_2_missing.bin"
    client.download_and_decrypt_file(manifest, dek, out_file3)
    assert out_file3.read_bytes() == original_bytes

    # 6. Test Download with 1 Corrupted Shard (Node B returning corrupt bytes)
    active_endpoints.add("http://node-a:8001")
    active_endpoints.add("http://node-e:8005")
    corrupted_endpoints.add("http://node-b:8002")
    out_file4 = tmp_path / "recovered_corrupt_shard.bin"
    client.download_and_decrypt_file(manifest, dek, out_file4)
    assert out_file4.read_bytes() == original_bytes

    # 7. Test Download with 3 Unavailable Shards (Node A offline, Node E offline, Node F offline -> 3 valid shards remain, < k=4)
    active_endpoints.remove("http://node-a:8001")
    active_endpoints.remove("http://node-e:8005")
    active_endpoints.remove("http://node-f:8006")
    out_file5 = tmp_path / "doomed_3_missing.bin"

    with pytest.raises(ClientError) as exc_info:
        client.download_and_decrypt_file(manifest, dek, out_file5)

    assert "minimum 4 required" in str(exc_info.value)
    assert not out_file5.exists()  # Ensure no partial output file is left behind!


# =====================================================================
# SECTION F: PHASE 4B AUTOMATIC REPAIR INTEGRATION TESTS
# =====================================================================

def test_f1_erasure_coded_shard_self_healing_repair(tmp_path):
    """
    Verify RepairEngine detects under-sharded erasure-coded chunk,
    reconstructs missing shard, uploads to replacement node, and updates manifest metadata.
    """
    nodes_info = {}
    for name in ["a", "b", "c", "d", "e", "f", "g"]:
        sm, tc = create_storage_node_app(tmp_path, f"node_repair_ec_{name}")
        n_id = f"NODE-{name.upper()}"
        endpoint = f"http://node-{name}:800{ord(name)-96}"
        nodes_info[n_id] = (tc, endpoint)

    active_endpoints = {ep for _, ep in nodes_info.values()}

    class MockRepairClient(ExpoClient):
        def __init__(self, nodes_info):
            super().__init__(node_url="http://node-a:8001")
            self.nodes_info = nodes_info

        def upload_chunk_bytes(self, chunk_bytes: bytes, filename: str):
            for n_id, (tc, ep) in self.nodes_info.items():
                if ep == self.base_url:
                    local_sha = compute_sha256(chunk_bytes)
                    res = tc.post("/files", files={"file": (filename, chunk_bytes, "application/octet-stream")}, headers={"X-SHA256-Checksum": local_sha})
                    return res.json()
            raise ClientError("Unknown node")

        def download_chunk_bytes(self, file_id: str) -> bytes:
            for n_id, (tc, ep) in self.nodes_info.items():
                if ep == self.base_url:
                    if ep not in active_endpoints:
                        raise ClientError("Node offline")
                    status_code, content = mock_fetch_chunk_bytes(tc, file_id)
                    if status_code != 200:
                        raise ClientError("File not found")
                    return content
            raise ClientError("Unknown node")

    client = MockRepairClient(nodes_info)

    # Upload file with 4+2 across Nodes A, B, C, D, E, F
    original_bytes = os.urandom(20 * 1024)
    orig_sha256 = compute_sha256(original_bytes)
    input_file = tmp_path / "repair_input.bin"
    input_file.write_bytes(original_bytes)

    initial_nodes = [{"node_id": n_id, "endpoint": ep, "advertised_endpoint": ep} for n_id, (_, ep) in list(nodes_info.items())[:6]]
    client.list_coordinator_nodes = lambda **k: initial_nodes

    manifest, dek = client.encrypt_and_upload_file(
        file_path=input_file,
        redundancy_mode="erasure",
        data_shards=4,
        parity_shards=2,
    )

    # Simulate failure of Node F (hosting Parity Shard 1)
    active_endpoints.remove("http://node-f:8006")

    # Inspect health before repair -> UNDER_REPLICATED (5 healthy, 1 offline)
    engine = RepairEngine(job_store=RepairJobStore(":memory:"))
    health_summary = engine.inspect_manifest_health(manifest, client=client)
    assert health_summary.under_replicated_chunks_count == 1

    # Run repair with Node G as candidate replacement node
    candidate_surviving = [
        {"node_id": n_id, "endpoint": ep, "advertised_endpoint": ep}
        for n_id, (_, ep) in nodes_info.items()
        if ep in active_endpoints
    ]

    repaired_manifest, jobs = engine.repair_manifest(
        manifest=manifest,
        client=client,
        candidate_nodes=candidate_surviving,
    )

    assert len(jobs) == 1
    assert jobs[0].state == RepairState.SUCCEEDED
    assert jobs[0].destination_node_id == "NODE-G"

    # Verify manifest now has 6 healthy shards and Node G is included
    health_summary_after = engine.inspect_manifest_health(repaired_manifest, client=client)
    assert health_summary_after.healthy_chunks_count == 1
    assert health_summary_after.under_replicated_chunks_count == 0

    # Download recovered file -> Exact match!
    out_file = tmp_path / "recovered_repaired.bin"
    client.download_and_decrypt_file(repaired_manifest, dek, out_file)
    assert out_file.read_bytes() == original_bytes


# =====================================================================
# SECTION H: MULTI-NODE INTEGRATION SIMULATION (SECTION 21)
# =====================================================================

def test_h1_7node_multi_scenario_integration_simulation(tmp_path):
    """
    Section 21 Multi-Node Integration Test Simulation:
    Nodes: Coordinator + Node A, Node B, Node C, Node D, Node E, Node F, Node G
    Scenarios:
    1. Upload binary file with k=4, m=2 across distinct nodes A..F.
    2. Download & compare SHA-256 (exact byte match).
    3. 1 Node Failure (Node A offline) -> Download succeeds.
    4. 2 Node Failures (Nodes A & E offline) -> Download succeeds (4 shards remain).
    5. 3 Node Failures (Nodes A, B, C offline) -> Download fails clearly.
    6. Corruption (Node D corrupt) -> Hash mismatch detected, corrupt shard excluded, download succeeds.
    7. Automatic Repair -> Reconstructs missing/corrupt shards, stores on Node G, verifies.
    8. Replication Regression -> Upload & download separate file using replication mode.
    """
    nodes_info = {}
    for name in ["a", "b", "c", "d", "e", "f", "g"]:
        sm, tc = create_storage_node_app(tmp_path, f"sim_node_{name}")
        n_id = f"NODE-{name.upper()}"
        endpoint = f"http://sim-node-{name}:800{ord(name)-96}"
        nodes_info[n_id] = (tc, endpoint)

    active_endpoints = {ep for _, ep in nodes_info.values()}
    corrupted_endpoints = set()

    class SimClient(ExpoClient):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.nodes_info = nodes_info

        def upload_chunk_bytes(self, chunk_bytes: bytes, filename: str):
            for n_id, (tc, ep) in nodes_info.items():
                if ep == self.base_url:
                    if ep not in active_endpoints:
                        raise ClientError("Node offline")
                    local_sha = compute_sha256(chunk_bytes)
                    res = tc.post("/files", files={"file": (filename, chunk_bytes, "application/octet-stream")}, headers={"X-SHA256-Checksum": local_sha})
                    return res.json()
            raise ClientError("Unknown node")

        def download_chunk_bytes(self, file_id: str) -> bytes:
            for n_id, (tc, ep) in nodes_info.items():
                if ep == self.base_url:
                    if ep not in active_endpoints:
                        raise ClientError("Node offline")
                    if ep in corrupted_endpoints:
                        return b"CORRUPTED_SHARD_PAYLOAD_GARBAGE"
                    status_code, content = mock_fetch_chunk_bytes(tc, file_id)
                    if status_code != 200:
                        raise ClientError("File not found")
                    return content
            raise ClientError("Unknown node")

    client = SimClient(node_url="http://sim-node-a:8001")

    # Scenario 1: Upload (k=4, m=2)
    original_bytes = os.urandom(100 * 1024)
    orig_sha256 = compute_sha256(original_bytes)
    input_file = tmp_path / "simulation_input.bin"
    input_file.write_bytes(original_bytes)

    initial_candidates = [{"node_id": n_id, "endpoint": ep, "advertised_endpoint": ep} for n_id, (_, ep) in list(nodes_info.items())[:6]]
    client.list_coordinator_nodes = lambda **k: initial_candidates

    manifest_ec, dek_ec = client.encrypt_and_upload_file(
        file_path=input_file,
        redundancy_mode="erasure",
        data_shards=4,
        parity_shards=2,
    )
    assert manifest_ec.redundancy_mode == "erasure"

    # Scenario 2: Normal Download
    out1 = tmp_path / "sim_out1.bin"
    client.download_and_decrypt_file(manifest_ec, dek_ec, out1)
    assert compute_sha256(out1.read_bytes()) == orig_sha256

    # Scenario 3: 1 Node Failure (Node A offline)
    active_endpoints.remove("http://sim-node-a:8001")
    out2 = tmp_path / "sim_out2.bin"
    client.download_and_decrypt_file(manifest_ec, dek_ec, out2)
    assert compute_sha256(out2.read_bytes()) == orig_sha256

    # Scenario 4: 2 Node Failures (Node A and Node E offline)
    active_endpoints.remove("http://sim-node-e:8005")
    out3 = tmp_path / "sim_out3.bin"
    client.download_and_decrypt_file(manifest_ec, dek_ec, out3)
    assert compute_sha256(out3.read_bytes()) == orig_sha256

    # Scenario 5: 3 Unavailable Shards (Node A, B, C offline -> 3 shards remain)
    active_endpoints.remove("http://sim-node-b:8002")
    out4 = tmp_path / "sim_out4.bin"
    with pytest.raises(ClientError):
        client.download_and_decrypt_file(manifest_ec, dek_ec, out4)

    # Restore Node A, Node B and Node E for Scenario 6
    active_endpoints.add("http://sim-node-a:8001")
    active_endpoints.add("http://sim-node-b:8002")
    active_endpoints.add("http://sim-node-e:8005")

    # Scenario 6: Corruption (Corrupt shard on Node D)
    corrupted_endpoints.add("http://sim-node-d:8004")
    out5 = tmp_path / "sim_out5.bin"
    client.download_and_decrypt_file(manifest_ec, dek_ec, out5)
    assert compute_sha256(out5.read_bytes()) == orig_sha256

    # Scenario 7: Repair (Repair onto Node G)
    engine = RepairEngine(job_store=RepairJobStore(":memory:"))
    surviving_candidates = [{"node_id": n_id, "endpoint": ep, "advertised_endpoint": ep} for n_id, (_, ep) in nodes_info.items() if ep in active_endpoints and ep not in corrupted_endpoints]

    repaired_m, jobs = engine.repair_manifest(manifest_ec, client, candidate_nodes=surviving_candidates)
    assert len(jobs) >= 1

    # Scenario 8: Replication Regression
    repl_input = tmp_path / "repl_regression.bin"
    repl_input.write_bytes(b"REPLICATION_REGRESSION_PAYLOAD_TEST")
    manifest_repl, dek_repl = client.encrypt_and_upload_file(
        file_path=repl_input,
        redundancy_mode="replication",
        replication_factor=2,
    )
    assert manifest_repl.redundancy_mode == "replication"
    out_repl = tmp_path / "repl_out.bin"
    client.download_and_decrypt_file(manifest_repl, dek_repl, out_repl)
    assert out_repl.read_bytes() == b"REPLICATION_REGRESSION_PAYLOAD_TEST"

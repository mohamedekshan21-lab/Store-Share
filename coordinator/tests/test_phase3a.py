"""
Automated unit & integration test suite for Expo Phase 3A (Client-Side Encryption & File Chunking).
Validates:
1. AES-256-GCM encryption & decryption success
2. Decrypted file equals original plaintext (byte-for-byte)
3. Fresh random keys and nonces per encryption operation
4. Plaintext key & plaintext data are NEVER sent to Storage Node API
5. Decryption failure with wrong key or tampered payload
6. File smaller than one chunk
7. File exactly equal to chunk size
8. File larger than chunk size (multiple chunks)
9. Large file multi-megabyte chunking and reassembly
10. Correct chunk ordering and count
11. Valid chunk SHA-256 hash verification
12. Corrupted chunk hash failure detection
13. Final reconstructed file SHA-256 verification
14. Encrypted chunk storage and retrieval from Storage Node
15. Quota enforcement on encrypted chunk uploads
"""

from __future__ import annotations

import io
import os
import tempfile
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from client.crypto import AESGCMCrypto, CryptoError, DecryptionError
from client.chunker import (
    FileManifest,
    ChunkMetadata,
    split_payload_into_chunks,
    reassemble_chunks,
    compute_sha256,
)
from client.client import ExpoClient, ClientError, IntegrityVerificationError
from storage_node.app.config import Settings as StorageSettings
from storage_node.app.storage_manager import StorageManager, QuotaExceededError
from storage_node.app.main import app as storage_app


@pytest.fixture
def tmp_storage_root(tmp_path):
    """Provides a temporary sandbox root directory for Storage Node."""
    return tmp_path / "storage_sandbox_3a"


@pytest.fixture
def storage_manager(tmp_storage_root):
    """Provides StorageManager instance."""
    settings = StorageSettings(
        storage_root=tmp_storage_root,
        storage_quota_gb=0.01,  # ~10.7 MB quota for testing
    )
    return StorageManager(settings)


@pytest.fixture
def storage_client(tmp_storage_root):
    """Provides FastAPI TestClient for Storage Node."""
    settings = StorageSettings(
        storage_root=tmp_storage_root,
        storage_quota_gb=0.01,
        auth_token=None,
    )
    storage_app.state.settings = settings
    storage_app.state.storage_manager = StorageManager(settings)
    with TestClient(storage_app) as tc:
        yield tc


# --- Encryption Unit Tests ---

def test_1_encryption_decryption_success():
    """Verify AES-256-GCM encryption and decryption recovers original data."""
    plaintext = b"Expo Distributed Storage Network - Phase 3A Encryption Test."
    key = AESGCMCrypto.generate_key()
    
    ciphertext, nonce = AESGCMCrypto.encrypt(plaintext, key)
    assert ciphertext != plaintext
    assert len(nonce) == 12

    recovered = AESGCMCrypto.decrypt(ciphertext, key, nonce)
    assert recovered == plaintext


def test_2_fresh_random_keys_and_nonces():
    """Verify different encryption operations produce distinct keys and nonces."""
    plaintext = b"Identical plaintext content for entropy check."
    key1 = AESGCMCrypto.generate_key()
    key2 = AESGCMCrypto.generate_key()
    assert key1 != key2

    ciphertext1, nonce1 = AESGCMCrypto.encrypt(plaintext, key1)
    ciphertext2, nonce2 = AESGCMCrypto.encrypt(plaintext, key1)
    assert nonce1 != nonce2
    assert ciphertext1 != ciphertext2


def test_3_decryption_failure_with_wrong_key_or_tampered_payload():
    """Verify decryption fails with incorrect key or tampered ciphertext."""
    plaintext = b"Sensitive payload for tamper check."
    key_correct = AESGCMCrypto.generate_key()
    key_wrong = AESGCMCrypto.generate_key()

    ciphertext, nonce = AESGCMCrypto.encrypt(plaintext, key_correct)

    # Wrong key
    with pytest.raises(DecryptionError):
        AESGCMCrypto.decrypt(ciphertext, key_wrong, nonce)

    # Tampered ciphertext byte
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF
    with pytest.raises(DecryptionError):
        AESGCMCrypto.decrypt(bytes(tampered), key_correct, nonce)


def test_4_plaintext_key_not_sent_to_storage_node(storage_client, tmp_path):
    """Verify plaintext key and plaintext contents are never sent to Storage Node API."""
    test_file = tmp_path / "secret_doc.txt"
    secret_bytes = b"SECRET-CONFIDENTIAL-DATA-12345"
    test_file.write_bytes(secret_bytes)

    # Mock client connected to test_client
    class TestClientAdapter:
        def __init__(self, tc):
            self.tc = tc
            self.base_url = "http://testserver"

        def node_info(self):
            return {"node_id": "NODE-test-3a"}

        def upload_chunk_bytes(self, chunk_bytes: bytes, filename: str):
            res = self.tc.post("/files", files={"file": (filename, chunk_bytes, "application/octet-stream")})
            assert res.status_code == 201
            return res.json()

    adapter = TestClientAdapter(storage_client)
    manifest, dek = ExpoClient.encrypt_and_upload_file(adapter, test_file, chunk_size=10)

    # Check files stored in node database: no file contains secret_bytes or dek
    files_res = storage_client.get("/files")
    assert files_res.status_code == 200
    stored_files = files_res.json()
    
    for f_meta in stored_files:
        f_id = f_meta["file_id"]
        res_dl = storage_client.get(f"/files/{f_id}")
        assert res_dl.status_code == 200
        payload = res_dl.content
        assert secret_bytes not in payload
        assert dek not in payload


# --- Chunking Unit Tests ---

def test_5_file_smaller_than_one_chunk():
    """Verify file smaller than chunk size results in exactly 1 chunk."""
    data = b"Short text"  # 10 bytes
    chunks = split_payload_into_chunks(data, chunk_size=1024)
    assert len(chunks) == 1
    assert chunks[0][0] == 0
    assert chunks[0][2] == data


def test_6_file_exactly_one_chunk():
    """Verify file equal to chunk size results in exactly 1 chunk."""
    data = b"X" * 100
    chunks = split_payload_into_chunks(data, chunk_size=100)
    assert len(chunks) == 1
    assert chunks[0][2] == data


def test_7_file_larger_than_one_chunk():
    """Verify file larger than chunk size splits deterministically across multiple chunks."""
    data = b"A" * 250
    chunks = split_payload_into_chunks(data, chunk_size=100)
    assert len(chunks) == 3
    assert len(chunks[0][2]) == 100
    assert len(chunks[1][2]) == 100
    assert len(chunks[2][2]) == 50
    assert chunks[0][0] == 0
    assert chunks[1][0] == 1
    assert chunks[2][0] == 2


def test_8_large_file_multi_megabyte_chunking_and_reassembly():
    """Verify multi-megabyte payload chunking and reassembly integrity."""
    large_payload = os.urandom(2 * 1024 * 1024 + 12345)  # ~2.01 MB
    chunks = split_payload_into_chunks(large_payload, chunk_size=512 * 1024)
    assert len(chunks) == 5

    chunks_data = [(seq, c_bytes) for seq, _, c_bytes, _ in chunks]
    reassembled = reassemble_chunks(chunks_data)
    assert reassembled == large_payload


def test_9_correct_chunk_ordering_and_count():
    """Verify reassembly respects chunk sequence indices regardless of list input order."""
    data = b"0123456789"
    chunks = split_payload_into_chunks(data, chunk_size=2)  # 5 chunks
    
    # Shuffle list
    shuffled = [(c[0], c[2]) for c in chunks]
    shuffled.reverse()

    reassembled = reassemble_chunks(shuffled)
    assert reassembled == data


# --- Integrity & End-to-End Pipeline Tests ---

def test_10_end_to_end_encrypt_upload_download_decrypt(storage_client, tmp_path):
    """Verify complete Phase 3A pipeline: encrypt -> chunk -> upload -> download -> reassemble -> decrypt -> byte match."""
    original_file = tmp_path / "original_photo.bin"
    original_data = os.urandom(128 * 1024)  # 128 KB test file
    original_file.write_bytes(original_data)

    class TestClientAdapter(ExpoClient):
        def __init__(self, tc):
            super().__init__(node_url="http://testserver")
            self.tc = tc

        def node_info(self):
            return {"node_id": "NODE-test-3a"}

        def upload_chunk_bytes(self, chunk_bytes: bytes, filename: str):
            local_sha = compute_sha256(chunk_bytes)
            headers = {"X-SHA256-Checksum": local_sha}
            res = self.tc.post("/files", files={"file": (filename, chunk_bytes, "application/octet-stream")}, headers=headers)
            assert res.status_code == 201
            return res.json()

        def download_chunk_bytes(self, file_id: str) -> bytes:
            res = self.tc.get(f"/files/{file_id}")
            assert res.status_code == 200
            return res.content

    client = TestClientAdapter(storage_client)

    # 1. Encrypt and Upload
    manifest, dek = client.encrypt_and_upload_file(original_file, chunk_size=32 * 1024)
    assert manifest.chunk_count == 5  # 128 KB + 16-byte GCM tag = 5 chunks (4*32KB + 16B)
    assert manifest.original_size == len(original_data)
    assert manifest.original_sha256 == compute_sha256(original_data)


    # 2. Download and Decrypt
    output_file = tmp_path / "recovered_photo.bin"
    recovered_path = client.download_and_decrypt_file(manifest, dek, output_file)

    # 3. Verify byte-for-byte equality
    assert recovered_path.is_file()
    recovered_data = recovered_path.read_bytes()
    assert recovered_data == original_data
    assert compute_sha256(recovered_data) == manifest.original_sha256


def test_11_corrupted_chunk_hash_fails_verification(storage_client, tmp_path):
    """Verify corrupted chunk payload fails SHA-256 hash verification during download."""
    original_file = tmp_path / "test_doc.txt"
    original_file.write_bytes(b"Data for corruption verification.")

    class TestClientAdapter(ExpoClient):
        def __init__(self, tc):
            super().__init__(node_url="http://testserver")
            self.tc = tc

        def upload_chunk_bytes(self, chunk_bytes: bytes, filename: str):
            res = self.tc.post("/files", files={"file": (filename, chunk_bytes, "application/octet-stream")})
            return res.json()

        def download_chunk_bytes(self, file_id: str) -> bytes:
            res = self.tc.get(f"/files/{file_id}")
            # Corrupt chunk bytes intentionally
            return res.content + b"CORRUPTED_BYTES"

    client = TestClientAdapter(storage_client)
    manifest, dek = client.encrypt_and_upload_file(original_file, chunk_size=10)

    output_file = tmp_path / "corrupted_output.txt"
    with pytest.raises(IntegrityVerificationError):
        client.download_and_decrypt_file(manifest, dek, output_file)


def test_12_quota_enforcement_on_chunks(tmp_path):
    """Verify existing Storage Node quota still applies to chunk uploads."""
    settings = StorageSettings(
        storage_root=tmp_path / "storage_quota_test",
        storage_quota_gb=0.000001,  # Tiny quota (~1 KB)
    )
    manager = StorageManager(settings)

    # Exceed quota attempt
    payload = b"X" * 2000
    with pytest.raises(QuotaExceededError):
        manager.save_file(io.BytesIO(payload), original_filename="chunk_large.dat")

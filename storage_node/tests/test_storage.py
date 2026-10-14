"""
Unit and functional tests for StorageManager (Sandbox security, quota enforcement, and I/O).
"""

from __future__ import annotations

import io
import os
from pathlib import Path
import pytest

from storage_node.app.config import Settings
from storage_node.app.storage_manager import (
    StorageManager,
    QuotaExceededError,
    SecurityError,
    StorageFileNotFoundError,
)


@pytest.fixture
def temp_storage_root(tmp_path: Path) -> Settings:
    """Fixture returning Settings pointing to an isolated temporary storage sandbox."""
    sandbox_dir = tmp_path / "sandbox"
    return Settings(
        storage_root=sandbox_dir,
        storage_quota_gb=0.001  # 1 MB quota for fast quota test assertions (1048576 bytes)
    )


@pytest.fixture
def storage_manager(temp_storage_root: Settings) -> StorageManager:
    """Fixture initializing StorageManager with temporary sandbox settings."""
    return StorageManager(temp_storage_root)


# 1. Storage directory creation
def test_storage_directory_creation(storage_manager: StorageManager):
    assert storage_manager.storage_root.exists()
    assert storage_manager.files_dir.exists()
    assert storage_manager.temp_dir.exists()
    assert storage_manager.metadata_dir.exists()
    assert storage_manager.db_path.exists()


# 2. Storage information
def test_storage_info(storage_manager: StorageManager):
    info = storage_manager.get_storage_info()
    assert info.quota_bytes == int(0.001 * 1024 * 1024 * 1024)
    assert info.used_bytes == 0
    assert info.available_bytes == info.quota_bytes


# 3. Successful upload
def test_successful_upload(storage_manager: StorageManager):
    content = b"Hello, Expo Storage Node!"
    file_obj = io.BytesIO(content)
    metadata = storage_manager.save_file(file_obj, "hello.txt", "text/plain")

    assert metadata.file_id is not None
    assert metadata.original_filename == "hello.txt"
    assert metadata.size == len(content)
    assert metadata.content_type == "text/plain"

    # Verify stored file on disk
    retrieved_meta, file_path = storage_manager.get_file(metadata.file_id)
    assert file_path.read_bytes() == content


# 4. Successful file listing
def test_file_listing(storage_manager: StorageManager):
    file1 = storage_manager.save_file(io.BytesIO(b"Data 1"), "file1.txt")
    file2 = storage_manager.save_file(io.BytesIO(b"Data 2"), "file2.txt")

    listing = storage_manager.list_files()
    assert listing.count == 2
    ids = [f.file_id for f in listing.files]
    assert file1.file_id in ids
    assert file2.file_id in ids


# 5. Successful file retrieval
def test_file_retrieval(storage_manager: StorageManager):
    content = b"Binary retrieval test content"
    meta = storage_manager.save_file(io.BytesIO(content), "doc.bin", "application/octet-stream")

    retrieved_meta, path = storage_manager.get_file(meta.file_id)
    assert retrieved_meta.file_id == meta.file_id
    assert path.is_file()
    assert path.read_bytes() == content


# 6. Successful deletion
def test_file_deletion(storage_manager: StorageManager):
    meta = storage_manager.save_file(io.BytesIO(b"To be deleted"), "delete_me.txt")
    assert storage_manager.delete_file(meta.file_id) is True

    # Verify lookup raises FileNotFoundError
    with pytest.raises(StorageFileNotFoundError):
        storage_manager.get_file(meta.file_id)

    # Verify listing is empty
    assert storage_manager.list_files().count == 0


# 7. Quota enforcement
def test_quota_enforcement(storage_manager: StorageManager):
    quota_bytes = storage_manager.settings.storage_quota_bytes
    # Attempt to upload data exceeding total quota in a single file
    oversized_data = b"X" * (quota_bytes + 100)
    
    with pytest.raises(QuotaExceededError):
        storage_manager.save_file(io.BytesIO(oversized_data), "oversized.dat")

    # Verify used bytes remains 0
    assert storage_manager.get_used_bytes() == 0


# 8. Upload larger than remaining quota
def test_upload_exceeds_remaining_quota(storage_manager: StorageManager):
    quota_bytes = storage_manager.settings.storage_quota_bytes
    
    # Fill up 80% of quota
    first_size = int(quota_bytes * 0.8)
    storage_manager.save_file(io.BytesIO(b"A" * first_size), "part1.dat")

    # Attempt to upload remaining 30% (would total 110%)
    second_size = int(quota_bytes * 0.3)
    with pytest.raises(QuotaExceededError):
        storage_manager.save_file(io.BytesIO(b"B" * second_size), "part2.dat")

    # First file should still be present
    assert storage_manager.list_files().count == 1


# 9. Path traversal attempts
@pytest.mark.parametrize(
    "bad_id",
    [
        "../test.txt",
        "..\\test.txt",
        "C:\\Windows\\test.txt",
        "../../etc/passwd",
        "sub/../../file.txt",
        "file.txt\x00.png",
    ],
)
def test_path_traversal_attempts(storage_manager: StorageManager, bad_id: str):
    with pytest.raises(SecurityError):
        storage_manager.get_file(bad_id)

    with pytest.raises(SecurityError):
        storage_manager.delete_file(bad_id)


# 10. Absolute path attempts
@pytest.mark.parametrize(
    "abs_path",
    [
        "/etc/passwd",
        "C:\\Windows\\System32\\cmd.exe",
        "D:\\Projects\\secret.txt",
    ],
)
def test_absolute_path_attempts(storage_manager: StorageManager, abs_path: str):
    with pytest.raises(SecurityError):
        storage_manager.get_file(abs_path)


# 11. Invalid file IDs
@pytest.mark.parametrize("invalid_id", ["not-a-uuid", "12345", "", "   ", "g"*36])
def test_invalid_file_ids(storage_manager: StorageManager, invalid_id: str):
    with pytest.raises(SecurityError):
        storage_manager.get_file(invalid_id)


# 12. Multiple files
def test_multiple_files(storage_manager: StorageManager):
    files_created = []
    for i in range(10):
        meta = storage_manager.save_file(io.BytesIO(f"Content {i}".encode()), f"file_{i}.txt")
        files_created.append(meta)

    listing = storage_manager.list_files()
    assert listing.count == 10
    assert len(files_created) == 10


# 13. Empty files
def test_empty_file(storage_manager: StorageManager):
    meta = storage_manager.save_file(io.BytesIO(b""), "empty.txt", "text/plain")
    assert meta.size == 0

    retrieved_meta, path = storage_manager.get_file(meta.file_id)
    assert path.read_bytes() == b""


# 14. Binary files
def test_binary_file(storage_manager: StorageManager):
    binary_content = bytes(range(256)) * 10
    meta = storage_manager.save_file(io.BytesIO(binary_content), "data.bin")

    _, path = storage_manager.get_file(meta.file_id)
    assert path.read_bytes() == binary_content


# 15. Filename collision handling
def test_filename_collision(storage_manager: StorageManager):
    # Two files with the exact same original filename should receive different file_ids and not collide
    meta1 = storage_manager.save_file(io.BytesIO(b"First"), "same_name.txt")
    meta2 = storage_manager.save_file(io.BytesIO(b"Second"), "same_name.txt")

    assert meta1.file_id != meta2.file_id
    assert meta1.stored_filename != meta2.stored_filename

    _, path1 = storage_manager.get_file(meta1.file_id)
    _, path2 = storage_manager.get_file(meta2.file_id)

    assert path1.read_bytes() == b"First"
    assert path2.read_bytes() == b"Second"

"""
File Chunking & Manifest Management Module for Expo (Phase 3A).
Handles deterministic payload splitting, opaque chunk ID generation,
SHA-256 chunk hashing, sequence-based reassembly, and JSON manifest serialization.
"""

from __future__ import annotations

import os
import hashlib
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from pydantic import BaseModel, Field


# Default 4 MB chunk size (configurable via EXPO_CHUNK_SIZE_BYTES or CHUNK_SIZE_BYTES)
DEFAULT_CHUNK_SIZE_BYTES = int(
    os.getenv("EXPO_CHUNK_SIZE_BYTES", os.getenv("CHUNK_SIZE_BYTES", str(4 * 1024 * 1024)))
)


class ChunkPlacement(BaseModel):
    """Placement location for an encrypted chunk copy."""
    node_id: str = Field(..., description="Storage Node ID hosting this copy")
    node_endpoint: str = Field(..., description="Storage Node endpoint URL hosting this copy")
    role: str = Field(default="PRIMARY", description="Placement role ('PRIMARY' or 'REPLICA')")
    chunk_id: Optional[str] = Field(default=None, description="Storage Node local file_id for this chunk copy")


class ShardMetadata(BaseModel):
    """Metadata for an individual erasure-coded shard placement."""
    shard_id: str = Field(..., description="Unique UUID identifier for the stored shard")
    chunk_id: str = Field(..., description="Target chunk UUID identifier")
    shard_index: int = Field(..., description="0-based shard index (0..k-1 for DATA, k..k+m-1 for PARITY)")
    shard_type: str = Field(..., description="Shard type ('DATA' or 'PARITY')")
    shard_size: int = Field(..., description="Size of shard payload in bytes")
    shard_sha256: str = Field(..., description="SHA-256 integrity checksum of shard payload")
    node_id: str = Field(..., description="Storage Node ID hosting this shard")
    node_endpoint: str = Field(..., description="Storage Node endpoint URL hosting this shard")


class ChunkMetadata(BaseModel):
    """Metadata for an individual file chunk and its placements or erasure shards."""
    chunk_id: str = Field(..., description="Opaque UUID identifier for the stored chunk")
    sequence: int = Field(..., description="0-based sequence index")
    size: int = Field(..., description="Size of chunk payload in bytes")
    sha256: str = Field(..., description="SHA-256 integrity checksum of chunk payload")
    node_id: Optional[str] = Field(None, description="Primary Storage Node ID (for backward compatibility)")
    node_endpoint: Optional[str] = Field(None, description="Primary Storage Node endpoint URL (for backward compatibility)")
    placements: List[ChunkPlacement] = Field(default_factory=list, description="List of all placements (PRIMARY + REPLICAS)")

    # Phase 4C Erasure Coding Fields
    original_ciphertext_size: Optional[int] = Field(None, description="Original size of encrypted chunk payload before erasure coding")
    encoded_size: Optional[int] = Field(None, description="Padded/encoded size across data shards")
    padding_length: Optional[int] = Field(None, description="Number of zero padding bytes applied during encoding")
    data_shard_count: Optional[int] = Field(None, description="Configured data shards count (k)")
    parity_shard_count: Optional[int] = Field(None, description="Configured parity shards count (m)")
    shards: List[ShardMetadata] = Field(default_factory=list, description="List of all erasure-coded shards (DATA + PARITY)")

    def get_effective_placements(self) -> List[ChunkPlacement]:
        """Returns placements list, falling back to top-level node_id/node_endpoint if placements is empty."""
        if self.placements:
            return self.placements
        if self.node_id and self.node_endpoint:
            return [ChunkPlacement(node_id=self.node_id, node_endpoint=self.node_endpoint, role="PRIMARY")]
        return []


class FileManifest(BaseModel):
    """Manifest file structure required to reconstruct and decrypt a stored file."""
    file_id: str = Field(..., description="Unique UUID identifier for the file")
    original_filename: str = Field(..., description="Original unencrypted filename")
    original_size: int = Field(..., description="Size of unencrypted plaintext file in bytes")
    original_sha256: str = Field(..., description="SHA-256 checksum of original unencrypted file")
    encrypted_size: int = Field(..., description="Size of encrypted payload in bytes")
    chunk_size: int = Field(..., description="Configured chunk size in bytes")
    chunk_count: int = Field(..., description="Total number of chunks")
    replication_factor: int = Field(default=1, description="Configured replication factor (1 = no redundancy, 2 = 1 primary + 1 replica)")
    manifest_version: int = Field(default=2, description="Manifest schema version (Phase 4A uses version 2, Phase 4C uses version 3)")
    encryption_algorithm: str = Field(default="AES-256-GCM", description="Cipher algorithm used")
    nonce_hex: str = Field(..., description="HEX-encoded AES-GCM IV/nonce (12 bytes)")
    created_at: str = Field(..., description="ISO 8601 creation timestamp")
    chunks: List[ChunkMetadata] = Field(default_factory=list, description="Ordered list of chunk metadata")

    # Phase 4C Erasure Coding Fields
    redundancy_mode: str = Field(default="replication", description="Redundancy strategy ('replication' or 'erasure')")
    erasure_coding_algorithm: Optional[str] = Field(default=None, description="Erasure coding algorithm name (e.g. 'Reed-Solomon-ZFEC')")
    data_shards: Optional[int] = Field(default=None, description="Configured data shards count (k)")
    parity_shards: Optional[int] = Field(default=None, description="Configured parity shards count (m)")
    total_shards: Optional[int] = Field(default=None, description="Total shards count (k + m)")

    def to_json(self) -> str:
        """Serializes manifest to JSON string."""
        return self.model_dump_json(indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> FileManifest:
        """Deserializes manifest from JSON string."""
        return cls.model_validate_json(json_str)


def compute_sha256(data: bytes) -> str:
    """Computes HEX SHA-256 checksum of binary data."""
    return hashlib.sha256(data).hexdigest().lower()


def split_payload_into_chunks(
    payload: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE_BYTES,
) -> List[Tuple[int, str, bytes, str]]:
    """
    Splits payload bytes into chunks of size `chunk_size`.
    Returns list of tuples: `[(sequence, opaque_chunk_id, chunk_bytes, chunk_sha256)]`.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer greater than 0.")

    chunks: List[Tuple[int, str, bytes, str]] = []
    total_len = len(payload)

    # Empty payload handling (e.g. 0-byte file)
    if total_len == 0:
        chunk_id = f"chunk-{uuid.uuid4()}"
        chunks.append((0, chunk_id, b"", compute_sha256(b"")))
        return chunks

    seq = 0
    offset = 0
    while offset < total_len:
        chunk_bytes = payload[offset : offset + chunk_size]
        chunk_id = f"chunk-{uuid.uuid4()}"
        chunk_hash = compute_sha256(chunk_bytes)
        chunks.append((seq, chunk_id, chunk_bytes, chunk_hash))
        offset += chunk_size
        seq += 1

    return chunks


def reassemble_chunks(chunks_data: List[Tuple[int, bytes]]) -> bytes:
    """
    Sorts chunk tuples by sequence index and concatenates payload bytes.
    `chunks_data` is a list of tuples: `[(sequence, chunk_bytes)]`.
    """
    sorted_chunks = sorted(chunks_data, key=lambda c: c[0])
    return b"".join(chunk_bytes for _, chunk_bytes in sorted_chunks)

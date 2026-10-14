"""
Erasure Coding & Reed-Solomon Redundancy Module for Expo (Phase 4C).

Provides a library-agnostic abstraction over a maintained Reed-Solomon implementation
(``zfec``, GPL-2.0-or-later / TGPPL, used by Tahoe-LAFS) for encoding *encrypted*
ciphertext chunks into k data shards + m parity shards and reconstructing them from
any k valid shards.

Security boundary: this module only ever sees ciphertext produced by client/crypto.py.
It never receives plaintext or encryption keys.

Library-specific details (zfec.easyfec Encoder/Decoder, its (k, n) convention, padding
semantics) are confined to this file. The rest of Expo uses:
    encode_ciphertext_chunk(data, data_shards, parity_shards)
    reconstruct_ciphertext_chunk(available_shards, data_shards, parity_shards, padding_length, original_size)
    validate_erasure_config(data_shards, parity_shards)
    validate_erasure_manifest(manifest)
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

import zfec.easyfec

logger = logging.getLogger("expo_erasure")

# Algorithm identifier recorded in manifests. Only this exact value is accepted on download.
ERASURE_ALGORITHM_NAME = "Reed-Solomon-ZFEC"

# zfec operates over GF(2^8): total shards n = k + m must satisfy 1 <= k <= n <= 256.
ZFEC_MAX_TOTAL_SHARDS = 256

# Defensive upper bound on any single encrypted chunk referenced by an untrusted manifest.
# Prevents adversarial manifests from forcing unreasonable allocations during reconstruction.
MAX_EC_CHUNK_SIZE_BYTES = 1024 * 1024 * 1024  # 1 GiB

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class ErasureCodingError(Exception):
    """Base exception for Expo erasure coding errors."""


class InvalidCodingConfigError(ErasureCodingError):
    """Raised when erasure coding parameters (k, m) are invalid."""


class ReconstructionError(ErasureCodingError):
    """Raised when reconstruction fails due to insufficient valid shards or invalid input."""


class ManifestValidationError(ErasureCodingError):
    """Raised when an erasure-coded manifest is malformed, inconsistent, or adversarial."""


# ---------------------------------------------------------------------------
# Lightweight in-process metrics (no external monitoring platform).
# ---------------------------------------------------------------------------
class _ErasureMetrics:
    _KEYS = (
        "files_uploaded_replication",
        "files_uploaded_erasure",
        "data_shards_written",
        "parity_shards_written",
        "failed_shard_uploads",
        "corrupt_shards_rejected",
        "reconstruction_attempts",
        "reconstruction_successes",
        "reconstruction_failures",
        "shards_repaired",
        "unrecoverable_chunks",
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Dict[str, int] = {k: 0 for k in self._KEYS}
        self._repair_durations: List[float] = []

    def inc(self, key: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + amount

    def record_repair_duration(self, seconds: float) -> None:
        with self._lock:
            self._repair_durations.append(seconds)
            if len(self._repair_durations) > 1000:
                self._repair_durations = self._repair_durations[-1000:]

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            snap: Dict[str, Any] = dict(self._counters)
            durs = list(self._repair_durations)
        snap["repair_duration_avg_seconds"] = (sum(durs) / len(durs)) if durs else None
        return snap

    def reset(self) -> None:
        with self._lock:
            self._counters = {k: 0 for k in self._KEYS}
            self._repair_durations = []


METRICS = _ErasureMetrics()


@dataclass
class ShardData:
    """An encoded shard payload before placement."""
    shard_id: str
    shard_index: int
    shard_type: str  # "DATA" or "PARITY"
    payload: bytes
    sha256: str


def validate_erasure_config(data_shards: Any, parity_shards: Any) -> None:
    """
    Validates erasure coding parameters (k, m) against Expo policy and zfec limits.
    k >= 1, m >= 1 (Expo requires at least one parity shard), k + m <= 256.
    """
    if isinstance(data_shards, bool) or not isinstance(data_shards, int) or data_shards < 1:
        raise InvalidCodingConfigError(f"Data shards (k) must be a positive integer >= 1, got {data_shards!r}.")
    if isinstance(parity_shards, bool) or not isinstance(parity_shards, int) or parity_shards < 1:
        raise InvalidCodingConfigError(f"Parity shards (m) must be a positive integer >= 1, got {parity_shards!r}.")
    total = data_shards + parity_shards
    if total > ZFEC_MAX_TOTAL_SHARDS:
        raise InvalidCodingConfigError(
            f"Total shards (k + m = {total}) exceeds Reed-Solomon (zfec, GF(2^8)) maximum of {ZFEC_MAX_TOTAL_SHARDS}."
        )


def expected_shard_size(chunk_size: int, data_shards: int) -> int:
    """Shard size produced by zfec.easyfec for a chunk of `chunk_size` bytes (ceil division)."""
    if chunk_size <= 0:
        return 0
    return -(-chunk_size // data_shards)


def coding_overhead(data_shards: int, parity_shards: int) -> float:
    """Theoretical storage overhead factor (k + m) / k, before padding & metadata."""
    return (data_shards + parity_shards) / data_shards


def encode_ciphertext_chunk(
    chunk_bytes: bytes,
    data_shards: int = 4,
    parity_shards: int = 2,
) -> Tuple[List[ShardData], int, int, int]:
    """
    Encodes an encrypted ciphertext chunk into k data + m parity shards.

    Deterministic: identical ciphertext and (k, m) always produce identical shard payloads.
    (Shard *identifiers* are random UUIDs and are not part of the coded data.)

    Returns: (shards, original_ciphertext_size, encoded_size, padding_length)
    """
    validate_erasure_config(data_shards, parity_shards)

    original_size = len(chunk_bytes)
    total_shards = data_shards + parity_shards

    logger.debug("ec.encode.start size=%d k=%d m=%d", original_size, data_shards, parity_shards)

    encoder = zfec.easyfec.Encoder(data_shards, total_shards)
    raw_shards = encoder.encode(chunk_bytes)
    if not raw_shards or len(raw_shards) != total_shards:
        raise ErasureCodingError("Reed-Solomon encoding failed to produce the expected number of shards.")

    shard_len = len(raw_shards[0])
    encoded_size = shard_len * data_shards
    padding_length = encoded_size - original_size
    if padding_length < 0 or padding_length >= data_shards:
        raise ErasureCodingError(f"Unexpected padding length {padding_length} for k={data_shards}.")

    shards: List[ShardData] = []
    for idx, payload in enumerate(raw_shards):
        payload = bytes(payload)
        shards.append(
            ShardData(
                shard_id=f"shard-{uuid.uuid4()}",
                shard_index=idx,
                shard_type="DATA" if idx < data_shards else "PARITY",
                payload=payload,
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        )

    logger.debug(
        "ec.encode.done size=%d encoded=%d padding=%d shard_size=%d k=%d m=%d",
        original_size, encoded_size, padding_length, shard_len, data_shards, parity_shards,
    )
    return shards, original_size, encoded_size, padding_length


def reconstruct_ciphertext_chunk(
    available_shards: List[Tuple[int, bytes]],
    data_shards: int,
    parity_shards: int,
    padding_length: int,
    original_ciphertext_size: int,
) -> bytes:
    """
    Reconstructs the original encrypted chunk from any k valid (already hash-verified) shards.
    `available_shards` is a list of (shard_index, shard_bytes). Any mix of DATA and PARITY works.
    Padding is removed using the manifest-recorded `padding_length` only.
    """
    validate_erasure_config(data_shards, parity_shards)
    total_shards = data_shards + parity_shards
    METRICS.inc("reconstruction_attempts")

    if padding_length < 0 or original_ciphertext_size < 0:
        METRICS.inc("reconstruction_failures")
        raise ReconstructionError("Negative padding length or original size is invalid.")

    if len(available_shards) < data_shards:
        METRICS.inc("reconstruction_failures")
        raise ReconstructionError(
            f"Insufficient valid shards for reconstruction: received {len(available_shards)}, minimum required {data_shards}."
        )

    seen = set()
    deduped: List[Tuple[int, bytes]] = []
    for idx, s_bytes in available_shards:
        if isinstance(idx, int) and 0 <= idx < total_shards and idx not in seen:
            seen.add(idx)
            deduped.append((idx, s_bytes))

    if len(deduped) < data_shards:
        METRICS.inc("reconstruction_failures")
        raise ReconstructionError(
            f"Insufficient unique valid shards: only {len(deduped)} distinct shard indices available (minimum {data_shards} required)."
        )

    selected = sorted(deduped[:data_shards], key=lambda t: t[0])
    lengths = {len(b) for _, b in selected}
    if len(lengths) != 1:
        METRICS.inc("reconstruction_failures")
        raise ReconstructionError("Shards supplied for reconstruction have inconsistent sizes.")
    shard_len = lengths.pop()
    if shard_len * data_shards - padding_length != original_ciphertext_size:
        METRICS.inc("reconstruction_failures")
        raise ReconstructionError(
            "Shard size, padding length and original ciphertext size are inconsistent with the coding profile."
        )

    decoder = zfec.easyfec.Decoder(data_shards, total_shards)
    try:
        reconstructed = decoder.decode([b for _, b in selected], [i for i, _ in selected], padding_length)
    except Exception as exc:
        METRICS.inc("reconstruction_failures")
        raise ReconstructionError(f"Reed-Solomon decoding failed: {exc}") from exc

    if len(reconstructed) != original_ciphertext_size:
        METRICS.inc("reconstruction_failures")
        raise ReconstructionError(
            f"Reconstructed size mismatch: expected {original_ciphertext_size} bytes, got {len(reconstructed)} bytes."
        )

    METRICS.inc("reconstruction_successes")
    return bytes(reconstructed)


def validate_erasure_manifest(manifest: Any) -> None:
    """
    Treats an erasure-coded FileManifest as untrusted input and validates it *before*
    any network request or memory allocation driven by its contents.
    Raises ManifestValidationError on any inconsistency.
    """
    def fail(msg: str) -> None:
        raise ManifestValidationError(f"Malformed erasure-coded manifest '{getattr(manifest, 'file_id', '?')}': {msg}")

    if getattr(manifest, "redundancy_mode", None) != "erasure":
        fail("redundancy_mode is not 'erasure'.")
    if getattr(manifest, "erasure_coding_algorithm", None) != ERASURE_ALGORITHM_NAME:
        fail(f"unsupported erasure_coding_algorithm {manifest.erasure_coding_algorithm!r}.")
    if manifest.manifest_version < 3:
        fail(f"erasure coding requires manifest_version >= 3, got {manifest.manifest_version}.")

    k, m = manifest.data_shards, manifest.parity_shards
    try:
        validate_erasure_config(k, m)
    except InvalidCodingConfigError as exc:
        fail(str(exc))
    total = k + m
    if manifest.total_shards != total:
        fail(f"total_shards {manifest.total_shards} != data_shards + parity_shards ({total}).")

    if not isinstance(manifest.chunk_size, int) or not (0 < manifest.chunk_size <= MAX_EC_CHUNK_SIZE_BYTES):
        fail(f"chunk_size {manifest.chunk_size} outside allowed range (1..{MAX_EC_CHUNK_SIZE_BYTES}).")
    if manifest.encrypted_size < 0 or manifest.original_size < 0:
        fail("negative file sizes.")
    if manifest.chunk_count != len(manifest.chunks) or manifest.chunk_count < 1:
        fail(f"chunk_count {manifest.chunk_count} does not match {len(manifest.chunks)} chunk records.")
    if not _SHA256_HEX_RE.match(str(manifest.original_sha256).lower()):
        fail("original_sha256 is not a valid SHA-256 hex digest.")

    sequences = sorted(c.sequence for c in manifest.chunks)
    if sequences != list(range(len(manifest.chunks))):
        fail("chunk sequences must be unique and contiguous from 0.")

    total_ct = 0
    for c in manifest.chunks:
        cid = c.chunk_id
        if not isinstance(cid, str) or not _SAFE_ID_RE.match(cid):
            fail(f"unsafe or invalid chunk_id {cid!r}.")
        if c.data_shard_count != k or c.parity_shard_count != m:
            fail(f"chunk {cid}: shard counts ({c.data_shard_count}, {c.parity_shard_count}) differ from manifest profile ({k}, {m}).")
        osz, esz, pad = c.original_ciphertext_size, c.encoded_size, c.padding_length
        if not all(isinstance(v, int) for v in (osz, esz, pad)):
            fail(f"chunk {cid}: missing original_ciphertext_size / encoded_size / padding_length.")
        if not (0 <= osz <= manifest.chunk_size):
            fail(f"chunk {cid}: original_ciphertext_size {osz} outside 0..chunk_size.")
        if c.size != osz:
            fail(f"chunk {cid}: size {c.size} != original_ciphertext_size {osz}.")
        if not (0 <= pad < k) or esz != osz + pad or esz % k != 0:
            fail(f"chunk {cid}: invalid padding_length {pad} / encoded_size {esz} for k={k}.")
        if not _SHA256_HEX_RE.match(str(c.sha256).lower()):
            fail(f"chunk {cid}: invalid ciphertext sha256.")
        expected_shard = esz // k
        if len(c.shards) != total:
            fail(f"chunk {cid}: has {len(c.shards)} shard records, expected {total}.")
        indices = set()
        for s in c.shards:
            if not isinstance(s.shard_index, int) or not (0 <= s.shard_index < total):
                fail(f"chunk {cid}: shard_index {s.shard_index!r} out of range 0..{total - 1}.")
            if s.shard_index in indices:
                fail(f"chunk {cid}: duplicate shard_index {s.shard_index}.")
            indices.add(s.shard_index)
            expected_type = "DATA" if s.shard_index < k else "PARITY"
            if s.shard_type != expected_type:
                fail(f"chunk {cid}: shard {s.shard_index} type {s.shard_type!r}, expected {expected_type}.")
            if s.chunk_id != cid:
                fail(f"chunk {cid}: shard {s.shard_index} references chunk {s.chunk_id!r}.")
            if s.shard_size != expected_shard:
                fail(f"chunk {cid}: shard {s.shard_index} size {s.shard_size} != expected {expected_shard}.")
            if not isinstance(s.shard_id, str) or not _SAFE_ID_RE.match(s.shard_id):
                fail(f"chunk {cid}: unsafe shard_id {s.shard_id!r}.")
            if not _SHA256_HEX_RE.match(str(s.shard_sha256).lower()):
                fail(f"chunk {cid}: shard {s.shard_index} has invalid sha256.")
            if not s.node_id:
                fail(f"chunk {cid}: shard {s.shard_index} missing node_id.")
            ep = s.node_endpoint or ""
            if ep and not (ep.startswith("http://") or ep.startswith("https://")):
                fail(f"chunk {cid}: shard {s.shard_index} endpoint must be http(s), got {ep!r}.")
        total_ct += osz

    if total_ct != manifest.encrypted_size:
        fail(f"sum of chunk ciphertext sizes {total_ct} != encrypted_size {manifest.encrypted_size}.")

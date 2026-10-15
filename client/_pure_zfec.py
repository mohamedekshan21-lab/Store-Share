"""
Pure-Python fallback implementation of zfec.easyfec for environments where
the native C-extension is not available (e.g. Python 3.14 on Windows).

Implements systematic Reed-Solomon / Cauchy erasure coding over GF(2^8).
API matches zfec.easyfec:
- Encoder(k, m):
    raw_shards = encoder.encode(chunk_bytes)
- Decoder(k, m):
    reconstructed = decoder.decode(shard_bytes_list, shard_indices_list, padding_length)
"""

from __future__ import annotations
from typing import List, Sequence

# GF(2^8) with primitive polynomial 0x11d (285)
EXP = [0] * 512
LOG = [0] * 256

def _init_tables():
    x = 1
    for i in range(255):
        EXP[i] = x
        EXP[i + 255] = x
        LOG[x] = i
        x <<= 1
        if x & 256:
            x ^= 0x11d
    LOG[0] = 0

_init_tables()


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return EXP[LOG[a] + LOG[b]]


def gf_div(a: int, b: int) -> int:
    if a == 0:
        return 0
    if b == 0:
        raise ZeroDivisionError("GF(2^8) division by zero")
    return EXP[(LOG[a] - LOG[b] + 255) % 255]


def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("GF(2^8) inverse of zero")
    return EXP[255 - LOG[a]]


def _invert_matrix(matrix: List[List[int]]) -> List[List[int]]:
    """Inverts a square matrix over GF(2^8) using Gauss-Jordan elimination."""
    n = len(matrix)
    # Augment with identity matrix
    aug = [row[:] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(matrix)]

    for col in range(n):
        # Find pivot
        pivot_row = None
        for row in range(col, n):
            if aug[row][col] != 0:
                pivot_row = row
                break
        if pivot_row is None:
            raise ValueError("Matrix is singular over GF(2^8)")

        # Swap rows
        if pivot_row != col:
            aug[col], aug[pivot_row] = aug[pivot_row], aug[col]

        # Normalize pivot row
        pivot_val = aug[col][col]
        inv_pivot = gf_inv(pivot_val)
        for j in range(2 * n):
            aug[col][j] = gf_mul(aug[col][j], inv_pivot)

        # Eliminate other rows
        for row in range(n):
            if row != col and aug[row][col] != 0:
                factor = aug[row][col]
                for j in range(2 * n):
                    aug[row][j] ^= gf_mul(aug[col][j], factor)

    return [row[n:] for row in aug]


class Encoder:
    """Systematic Cauchy Reed-Solomon Encoder over GF(2^8)."""

    def __init__(self, k: int, m: int) -> None:
        if k < 1 or m < k or m > 256:
            raise ValueError(f"Invalid coding configuration: k={k}, m={m}")
        self.k = k
        self.m = m
        self.parity_count = m - k

        # Construct Cauchy generator matrix for parity rows
        # Row p (0 <= p < parity_count), Col c (0 <= c < k)
        # X_p = p, Y_c = parity_count + c
        # C[p][c] = 1 / (X_p ^ Y_c)
        self.cauchy_matrix = []
        for p in range(self.parity_count):
            row = []
            x_p = p
            for c in range(self.k):
                y_c = self.parity_count + c
                row.append(gf_inv(x_p ^ y_c))
            self.cauchy_matrix.append(row)

    def encode(self, data: bytes) -> List[bytes]:
        """Encodes data into m shards of equal length (padding data with 0s if needed)."""
        data_len = len(data)
        # Compute shard length (ceil division)
        shard_len = -(-data_len // self.k) if self.k > 0 else 0
        padded_len = shard_len * self.k
        padded_data = data + b"\x00" * (padded_len - data_len)

        # Extract systematic data shards
        data_shards: List[bytearray] = []
        for i in range(self.k):
            start = i * shard_len
            data_shards.append(bytearray(padded_data[start : start + shard_len]))

        # Generate parity shards
        parity_shards: List[bytearray] = [bytearray(shard_len) for _ in range(self.parity_count)]
        for p in range(self.parity_count):
            p_row = self.cauchy_matrix[p]
            p_buf = parity_shards[p]
            for byte_idx in range(shard_len):
                val = 0
                for c in range(self.k):
                    d_byte = data_shards[c][byte_idx]
                    if d_byte:
                        val ^= gf_mul(d_byte, p_row[c])
                p_buf[byte_idx] = val

        return [bytes(s) for s in data_shards] + [bytes(s) for s in parity_shards]


class Decoder:
    """Systematic Cauchy Reed-Solomon Decoder over GF(2^8)."""

    def __init__(self, k: int, m: int) -> None:
        if k < 1 or m < k or m > 256:
            raise ValueError(f"Invalid coding configuration: k={k}, m={m}")
        self.k = k
        self.m = m
        self.parity_count = m - k

        # Cauchy matrix for parity rows
        self.cauchy_matrix = []
        for p in range(self.parity_count):
            row = []
            x_p = p
            for c in range(self.k):
                y_c = self.parity_count + c
                row.append(gf_inv(x_p ^ y_c))
            self.cauchy_matrix.append(row)

    def _get_generator_row(self, row_idx: int) -> List[int]:
        if row_idx < self.k:
            # Identity row
            return [1 if i == row_idx else 0 for i in range(self.k)]
        else:
            # Parity row
            return self.cauchy_matrix[row_idx - self.k]

    def decode(
        self,
        shard_bytes: Sequence[bytes],
        shard_indices: Sequence[int],
        padding_length: int = 0,
    ) -> bytes:
        """Reconstructs original data from any k shards."""
        if len(shard_bytes) < self.k:
            raise ValueError(f"Need at least {self.k} shards, got {len(shard_bytes)}")

        selected_bytes = [bytearray(b) for b in shard_bytes[: self.k]]
        selected_indices = list(shard_indices[: self.k])
        shard_len = len(selected_bytes[0])

        # If we have all k systematic data shards (0..k-1)
        if selected_indices == list(range(self.k)):
            reconstructed = bytearray()
            for b in selected_bytes:
                reconstructed.extend(b)
            if padding_length > 0:
                reconstructed = reconstructed[:-padding_length]
            return bytes(reconstructed)

        # Build submatrix from the selected rows of generator matrix
        submatrix = [self._get_generator_row(idx) for idx in selected_indices]
        inv_submatrix = _invert_matrix(submatrix)

        # Multiply inv_submatrix by received shards
        data_shards: List[bytearray] = [bytearray(shard_len) for _ in range(self.k)]
        for c in range(self.k):
            inv_row = inv_submatrix[c]
            c_buf = data_shards[c]
            for byte_idx in range(shard_len):
                val = 0
                for r in range(self.k):
                    s_byte = selected_bytes[r][byte_idx]
                    if s_byte:
                        val ^= gf_mul(s_byte, inv_row[r])
                c_buf[byte_idx] = val

        reconstructed = bytearray()
        for b in data_shards:
            reconstructed.extend(b)

        if padding_length > 0:
            reconstructed = reconstructed[:-padding_length]

        return bytes(reconstructed)

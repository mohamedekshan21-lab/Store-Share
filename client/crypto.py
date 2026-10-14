"""
Client-Side Cryptography Module for Expo (Phase 3A).
Provides AES-256-GCM authenticated encryption and decryption for consumer files.
Guarantees that plaintext data and encryption keys never leave the consumer.
"""

from __future__ import annotations

import os
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoError(Exception):
    """Base exception for Expo cryptography errors."""


class DecryptionError(CryptoError):
    """Raised when AES-GCM decryption or authentication tag verification fails."""


class AESGCMCrypto:
    """Wrapper for AES-256-GCM client-side authenticated encryption."""

    KEY_SIZE_BYTES = 32   # 256 bits
    NONCE_SIZE_BYTES = 12  # 96 bits standard for GCM

    @classmethod
    def generate_key(cls) -> bytes:
        """Generates a cryptographically secure random 256-bit (32 bytes) data encryption key (DEK)."""
        return AESGCM.generate_key(bit_length=256)

    @classmethod
    def generate_nonce(cls) -> bytes:
        """Generates a cryptographically secure random 96-bit (12 bytes) initialization vector/nonce."""
        return os.urandom(cls.NONCE_SIZE_BYTES)

    @classmethod
    def encrypt(
        cls,
        plaintext: bytes,
        key: bytes,
        nonce: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """
        Encrypts plaintext bytes using AES-256-GCM.
        Returns tuple of (ciphertext, nonce).
        """
        if len(key) != cls.KEY_SIZE_BYTES:
            raise CryptoError(f"Invalid AES key length: expected {cls.KEY_SIZE_BYTES} bytes, got {len(key)}.")

        if nonce is None:
            nonce = cls.generate_nonce()

        if len(nonce) != cls.NONCE_SIZE_BYTES:
            raise CryptoError(f"Invalid AES-GCM nonce length: expected {cls.NONCE_SIZE_BYTES} bytes, got {len(nonce)}.")

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return ciphertext, nonce

    @classmethod
    def decrypt(
        cls,
        ciphertext: bytes,
        key: bytes,
        nonce: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypts ciphertext bytes using AES-256-GCM.
        Verifies authentication tag embedded in ciphertext.
        """
        if len(key) != cls.KEY_SIZE_BYTES:
            raise CryptoError(f"Invalid AES key length: expected {cls.KEY_SIZE_BYTES} bytes, got {len(key)}.")

        if len(nonce) != cls.NONCE_SIZE_BYTES:
            raise CryptoError(f"Invalid AES-GCM nonce length: expected {cls.NONCE_SIZE_BYTES} bytes, got {len(nonce)}.")

        try:
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
            return plaintext
        except Exception as exc:
            raise DecryptionError("Decryption failed: Invalid key, corrupted ciphertext, or tag mismatch.") from exc

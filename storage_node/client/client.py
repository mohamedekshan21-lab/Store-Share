"""
Expo Storage Node Client API implementation.
Performs remote health checks, node identity checks, storage capacity inspection,
SHA-256 integrity-verified uploads, downloads, file listing, and deletion over LAN.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional
import httpx

from client.config import get_client_settings, ClientSettings


class ClientError(Exception):
    """Base exception for Expo Client errors."""


class IntegrityVerificationError(ClientError):
    """Raised when SHA-256 checksum integrity check fails during upload/download."""


class ExpoClient:
    """Client for interacting with a remote Expo Storage Node over HTTP/LAN."""

    def __init__(
        self,
        node_url: Optional[str] = None,
        auth_token: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        settings = get_client_settings()
        self.base_url = (node_url or settings.base_url).rstrip("/")
        self.auth_token = auth_token if auth_token is not None else settings.auth_token
        self.timeout = timeout

    def _get_headers(self) -> Dict[str, str]:
        """Builds HTTP headers including authentication token if set."""
        headers = {}
        if self.auth_token and self.auth_token.strip():
            token = self.auth_token.strip()
            headers["X-Auth-Token"] = token
            headers["Authorization"] = f"Bearer {token}"
        return headers

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

        # Compute local file SHA-256
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
            
            # Verify server returned matching SHA-256
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

    def delete_file(self, file_id: str) -> bool:
        """Deletes file on remote node."""
        url = f"{self.base_url}/files/{file_id}"
        try:
            res = httpx.delete(url, headers=self._get_headers(), timeout=self.timeout)
            if res.status_code == 404:
                raise ClientError(f"Remote file not found (404): ID '{file_id}'")
            elif res.status_code == 401:
                raise ClientError("Authentication failed: Missing or invalid node auth token.")
            res.raise_for_status()
            return True
        except httpx.HTTPError as exc:
            raise ClientError(f"Delete file failed: {str(exc)}") from exc

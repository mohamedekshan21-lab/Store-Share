"""
Transport abstraction for Expo network communication (Phase 2B).
Provides base interface for direct connection and future relay transport implementations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
import httpx


class BaseTransport(ABC):
    """Abstract Base Class for Expo transport adapters."""

    @abstractmethod
    def connect(self) -> None:
        """Establishes transport connection."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Closes transport connection."""
        pass

    @abstractmethod
    def is_connected(self) -> bool:
        """Returns True if transport is currently connected."""
        pass


class DirectTransport(BaseTransport):
    """Direct HTTP/HTTPS transport implementation."""

    def __init__(
        self,
        base_url: str,
        verify_tls: bool = True,
        ca_cert: Optional[str] = None,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.verify_tls = verify_tls
        self.ca_cert = ca_cert
        self.timeout = timeout
        
        # Determine verify parameter for httpx
        if not verify_tls:
            self.verify: Any = False
        elif ca_cert and ca_cert.strip():
            self.verify = ca_cert.strip()
        else:
            self.verify = True

        self.client = httpx.Client(
            base_url=self.base_url,
            verify=self.verify,
            timeout=self.timeout,
        )

    def connect(self) -> None:
        """Direct HTTP/HTTPS transport is connectionless/managed per-request."""
        pass

    def close(self) -> None:
        """Closes underlying HTTP client connection pool."""
        self.client.close()

    def is_connected(self) -> bool:
        """Returns True if transport client is active."""
        return not self.client.is_closed


class RelayTransport(BaseTransport):
    """
    Authenticated Relay transport implementation (Phase 6B).
    Provides relay-mediated connectivity for Storage Nodes behind NAT, firewalls, or CGNAT.
    """

    def __init__(
        self,
        relay_server_url: str,
        target_node_id: str,
        session_id: Optional[str] = None,
        session_token: Optional[str] = None,
        auth_token: Optional[str] = None,
        verify_tls: bool = True,
        timeout: float = 10.0,
    ) -> None:
        self.relay_server_url = relay_server_url.rstrip("/")
        self.target_node_id = target_node_id
        self.session_id = session_id
        self.session_token = session_token
        self.auth_token = auth_token
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.client: Optional[httpx.Client] = None
        self._connected = False

    def connect(self) -> None:
        """Establishes authenticated relay session if not already provided, and configures transport."""
        if self.relay_server_url.startswith("ws://") or self.relay_server_url.startswith("wss://"):
            raise NotImplementedError("WebSocket relay transport is not implemented in this version")

        if not self.session_id or not self.session_token:
            # Request session from relay
            headers = {}
            if self.auth_token:
                headers["X-Auth-Token"] = self.auth_token
                headers["Authorization"] = f"Bearer {self.auth_token}"

            with httpx.Client(verify=self.verify_tls, timeout=self.timeout) as http:
                res = http.post(
                    f"{self.relay_server_url}/relay/sessions",
                    json={"target_node_id": self.target_node_id},
                    headers=headers,
                )
                res.raise_for_status()
                data = res.json()
                self.session_id = data["session_id"]
                self.session_token = data["session_token"]

        base_url = f"{self.relay_server_url}/relay/{self.session_id}"
        client_headers = {"X-Relay-Token": self.session_token}
        if self.auth_token:
            client_headers["X-Auth-Token"] = self.auth_token

        self.client = httpx.Client(
            base_url=base_url,
            headers=client_headers,
            verify=self.verify_tls,
            timeout=self.timeout,
        )
        self._connected = True

    def close(self) -> None:
        if self.client:
            self.client.close()
        self._connected = False

    def is_connected(self) -> bool:
        return self._connected and bool(self.client and not self.client.is_closed)


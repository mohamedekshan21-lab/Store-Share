"""
Configuration settings for Expo Coordinator Service (Phase 2A).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field


class CoordinatorSettings(BaseModel):
    """Coordinator configuration settings."""

    # Path to SQLite database file for node registry metadata
    db_path: Path = Field(
        default_factory=lambda: Path(
            os.getenv("COORDINATOR_DB_PATH", "./coordinator_metadata.db")
        ).resolve()
    )

    # Network host interface (e.g. 0.0.0.0 for LAN exposure)
    host: str = Field(
        default_factory=lambda: os.getenv("COORDINATOR_HOST", "0.0.0.0")
    )

    # Network listening port
    port: int = Field(
        default_factory=lambda: int(os.getenv("COORDINATOR_PORT", "9000"))
    )

    # Optional coordinator authorization token
    auth_token: Optional[str] = Field(
        default_factory=lambda: os.getenv("COORDINATOR_AUTH_TOKEN", None)
    )

    # Optional separate administrative authorization token (Phase 8B)
    admin_auth_token: Optional[str] = Field(
        default_factory=lambda: os.getenv("COORDINATOR_ADMIN_AUTH_TOKEN", None)
    )

    # Deployment environment: 'development', 'testing', or 'production'
    environment: str = Field(
        default_factory=lambda: os.getenv("COORDINATOR_ENV", "development").lower()
    )

    # Secure cookie flag (HTTPS required in production, optional in local development)
    cookie_secure: bool = Field(
        default_factory=lambda: os.getenv("COORDINATOR_COOKIE_SECURE", "false").lower() == "true"
    )

    # Configurable heartbeat timeout in seconds before marking a node as offline
    heartbeat_timeout_seconds: int = Field(
        default_factory=lambda: int(os.getenv("NODE_HEARTBEAT_TIMEOUT_SECONDS", "30"))
    )

    # JWT Authentication settings
    jwt_secret: str = Field(
        default_factory=lambda: os.getenv(
            "COORDINATOR_JWT_SECRET",
            "expo_jwt_development_secret_key_do_not_use_in_production_32chars!",
        )
    )
    jwt_algorithm: str = Field(default="HS256")
    jwt_access_token_expire_minutes: int = Field(
        default_factory=lambda: int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    )
    jwt_issuer: str = Field(default="expo-store-share")
    jwt_audience: str = Field(default="expo-store-share-api")


def get_coordinator_settings() -> CoordinatorSettings:
    """Returns initialized CoordinatorSettings instance."""
    return CoordinatorSettings()

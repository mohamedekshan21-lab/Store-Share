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

    # Optional administrator account bootstrap credentials (Phase 10A)
    admin_email: Optional[str] = Field(
        default_factory=lambda: os.getenv("COORDINATOR_ADMIN_EMAIL", None)
    )
    admin_password: Optional[str] = Field(
        default_factory=lambda: os.getenv("COORDINATOR_ADMIN_PASSWORD", None)
    )

    # Dedicated HMAC-SHA-256 Capability Secret (Phase 10B)
    capability_secret: Optional[str] = Field(
        default_factory=lambda: os.getenv("CAPABILITY_SECRET", os.getenv("COORDINATOR_CAPABILITY_SECRET", None))
    )
    capability_ttl_seconds: int = Field(
        default_factory=lambda: int(os.getenv("CAPABILITY_TTL_SECONDS", "300"))
    )

    # Phase 10C: Provider Onboarding, Node Validation, Probation and Reliability Settings
    terms_version: str = Field(
        default_factory=lambda: os.getenv("PROVIDER_TERMS_VERSION", "1.0")
    )
    probation_min_duration_seconds: int = Field(
        default_factory=lambda: int(os.getenv("NODE_PROBATION_MIN_SECONDS", "60"))
    )
    probation_min_health_checks: int = Field(
        default_factory=lambda: int(os.getenv("NODE_PROBATION_MIN_HEALTH_CHECKS", "3"))
    )
    probation_max_bytes: int = Field(
        default_factory=lambda: int(os.getenv("NODE_PROBATION_MAX_BYTES", str(50 * 1024 * 1024)))
    )
    disk_safety_buffer_bytes: int = Field(
        default_factory=lambda: int(os.getenv("NODE_DISK_SAFETY_BUFFER_BYTES", str(100 * 1024 * 1024)))
    )
    reliability_min_score: float = Field(
        default_factory=lambda: float(os.getenv("NODE_RELIABILITY_MIN_SCORE", "0.5"))
    )
    reliability_min_confidence: float = Field(
        default_factory=lambda: float(os.getenv("NODE_RELIABILITY_MIN_CONFIDENCE", "0.3"))
    )

    # Phase 10D: Account Storage Quotas and Consumer File Management Settings
    default_account_quota_bytes: int = Field(
        default_factory=lambda: int(os.getenv("DEFAULT_ACCOUNT_QUOTA_BYTES", str(10 * 1024 * 1024 * 1024)))
    )
    account_quota_policy: str = Field(
        default_factory=lambda: os.getenv("ACCOUNT_QUOTA_POLICY", "logical").lower()
    )
    account_reservation_ttl_seconds: int = Field(
        default_factory=lambda: int(os.getenv("ACCOUNT_RESERVATION_TTL_SECONDS", "300"))
    )

    # Phase 10E: Email/SMS Verification and Account Recovery Settings
    email_verification_ttl_seconds: int = Field(
        default_factory=lambda: int(os.getenv("EMAIL_VERIFICATION_TTL_SECONDS", "86400"))
    )
    password_reset_ttl_seconds: int = Field(
        default_factory=lambda: int(os.getenv("PASSWORD_RESET_TTL_SECONDS", "3600"))
    )
    sms_code_ttl_seconds: int = Field(
        default_factory=lambda: int(os.getenv("SMS_CODE_TTL_SECONDS", "600"))
    )
    verification_resend_cooldown_seconds: int = Field(
        default_factory=lambda: int(os.getenv("VERIFICATION_RESEND_COOLDOWN_SECONDS", "60"))
    )
    max_resend_per_hour: int = Field(
        default_factory=lambda: int(os.getenv("MAX_RESEND_PER_HOUR", "5"))
    )
    max_code_verification_attempts: int = Field(
        default_factory=lambda: int(os.getenv("MAX_CODE_VERIFICATION_ATTEMPTS", "5"))
    )
    require_email_verification: bool = Field(
        default_factory=lambda: os.getenv("REQUIRE_EMAIL_VERIFICATION", "false").lower() == "true"
    )
    verification_base_url: str = Field(
        default_factory=lambda: os.getenv("VERIFICATION_BASE_URL", "http://localhost:9000")
    )

    # Email Delivery Configuration (SMTP)
    smtp_host: Optional[str] = Field(
        default_factory=lambda: os.getenv("SMTP_HOST", None)
    )
    smtp_port: int = Field(
        default_factory=lambda: int(os.getenv("SMTP_PORT", "587"))
    )
    smtp_username: Optional[str] = Field(
        default_factory=lambda: os.getenv("SMTP_USERNAME", None)
    )
    smtp_password: Optional[str] = Field(
        default_factory=lambda: os.getenv("SMTP_PASSWORD", None)
    )
    smtp_from_email: str = Field(
        default_factory=lambda: os.getenv("SMTP_FROM_EMAIL", "noreply@expo.storage")
    )
    smtp_use_tls: bool = Field(
        default_factory=lambda: os.getenv("SMTP_USE_TLS", "true").lower() == "true"
    )

    # SMS Delivery Configuration (Twilio / Provider)
    sms_provider: str = Field(
        default_factory=lambda: os.getenv("SMS_PROVIDER", "none").lower()
    )
    twilio_account_sid: Optional[str] = Field(
        default_factory=lambda: os.getenv("TWILIO_ACCOUNT_SID", None)
    )
    twilio_auth_token: Optional[str] = Field(
        default_factory=lambda: os.getenv("TWILIO_AUTH_TOKEN", None)
    )
    twilio_from_number: Optional[str] = Field(
        default_factory=lambda: os.getenv("TWILIO_FROM_NUMBER", None)
    )

    @property
    def effective_capability_secret(self) -> Optional[str]:
        """Resolves capability signing secret, providing secure dev fallback in non-production."""
        if self.capability_secret and self.capability_secret.strip():
            return self.capability_secret.strip()
        if self.environment != "production":
            return "expo-dev-capability-secret-shared-key-2026!"
        return None

    @property
    def is_testing(self) -> bool:
        """Indicates whether running under automated test harness or testing environment."""
        import sys
        return self.environment in ("testing", "test") or "pytest" in sys.modules


def get_coordinator_settings() -> CoordinatorSettings:
    """Returns initialized CoordinatorSettings instance."""
    return CoordinatorSettings()

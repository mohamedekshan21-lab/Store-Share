"""
Email and SMS Delivery Subsystem for Expo Coordinator (Phase 10E).

Provides:
1. Standardized DeliveryResult dataclass tracking status and errors.
2. Abstract MailDeliveryAdapter and SmsDeliveryAdapter protocols.
3. Deterministic FakeDeliveryAdapter for unit and integration testing.
4. Production-ready SmtpMailAdapter with fail-safe error handling.
5. Production-ready TwilioSmsAdapter with fail-safe error handling.
6. DeliveryManager orchestrating notifications, verification codes, and security alerts.
"""

from __future__ import annotations

import logging
import re
import smtplib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any, Dict, List, Optional, Protocol

logger = logging.getLogger("expo_delivery")


def mask_phone_number(phone: str) -> str:
    """Masks phone number for safe logging (e.g. +1***1234)."""
    clean = re.sub(r"[^\d+]", "", phone.strip())
    if len(clean) <= 4:
        return "****"
    return clean[:2] + "*" * (len(clean) - 6) + clean[-4:]


def mask_email(email: str) -> str:
    """Masks email address for safe logging (e.g. a***e@example.com)."""
    parts = email.strip().split("@")
    if len(parts) != 2 or len(parts[0]) <= 2:
        return "***@" + (parts[1] if len(parts) == 2 else "masked")
    user, domain = parts
    return f"{user[0]}***{user[-1]}@{domain}"


@dataclass
class DeliveryResult:
    """Standardized result returned by email and SMS delivery adapters."""
    success: bool
    delivery_id: Optional[str] = None
    provider: str = "none"
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class MailDeliveryAdapter(Protocol):
    """Protocol for sending email messages."""
    def send_email(
        self,
        to_email: str,
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
    ) -> DeliveryResult:
        ...


class SmsDeliveryAdapter(Protocol):
    """Protocol for sending SMS text messages."""
    def send_sms(
        self,
        to_phone: str,
        message_text: str,
    ) -> DeliveryResult:
        ...


class FakeDeliveryAdapter:
    """
    Deterministic fake delivery adapter for automated unit & integration testing.
    Records sent emails and SMS messages in memory without external side effects.
    Can simulate delivery failure when configure_failure(True) is invoked.
    """

    def __init__(self) -> None:
        self.sent_emails: List[Dict[str, Any]] = []
        self.sent_sms: List[Dict[str, Any]] = []
        self.simulate_failure: bool = False
        self.failure_error: str = "Simulated delivery adapter network error"

    def configure_failure(self, fail: bool = True, error_msg: Optional[str] = None) -> None:
        """Configures the fake adapter to simulate downstream delivery failure."""
        self.simulate_failure = fail
        if error_msg:
            self.failure_error = error_msg

    def clear(self) -> None:
        """Clears in-memory sent delivery buffers."""
        self.sent_emails.clear()
        self.sent_sms.clear()
        self.simulate_failure = False

    def send_email(
        self,
        to_email: str,
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
    ) -> DeliveryResult:
        if self.simulate_failure:
            logger.warning("FakeDeliveryAdapter: Simulating email delivery failure to %s", mask_email(to_email))
            return DeliveryResult(
                success=False,
                provider="fake_mail",
                error=self.failure_error,
            )

        delivery_id = f"fake-mail-{len(self.sent_emails) + 1}"
        record = {
            "delivery_id": delivery_id,
            "to_email": to_email,
            "subject": subject,
            "body_text": body_text,
            "body_html": body_html,
            "sent_at": datetime.now(timezone.utc).isoformat(),
        }
        self.sent_emails.append(record)
        logger.debug("FakeDeliveryAdapter: Recorded email delivery to %s", mask_email(to_email))
        return DeliveryResult(
            success=True,
            delivery_id=delivery_id,
            provider="fake_mail",
        )

    def send_sms(
        self,
        to_phone: str,
        message_text: str,
    ) -> DeliveryResult:
        if self.simulate_failure:
            logger.warning("FakeDeliveryAdapter: Simulating SMS delivery failure to %s", mask_phone_number(to_phone))
            return DeliveryResult(
                success=False,
                provider="fake_sms",
                error=self.failure_error,
            )

        delivery_id = f"fake-sms-{len(self.sent_sms) + 1}"
        record = {
            "delivery_id": delivery_id,
            "to_phone": to_phone,
            "message_text": message_text,
            "sent_at": datetime.now(timezone.utc).isoformat(),
        }
        self.sent_sms.append(record)
        logger.debug("FakeDeliveryAdapter: Recorded SMS delivery to %s", mask_phone_number(to_phone))
        return DeliveryResult(
            success=True,
            delivery_id=delivery_id,
            provider="fake_sms",
        )


class SmtpMailAdapter:
    """Production-grade SMTP email delivery adapter with secure TLS and fail-safe handling."""

    def __init__(
        self,
        host: Optional[str],
        port: int = 587,
        username: Optional[str] = None,
        password: Optional[str] = None,
        from_email: str = "noreply@expo.storage",
        use_tls: bool = True,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.from_email = from_email
        self.use_tls = use_tls
        self.timeout_seconds = timeout_seconds

    @property
    def is_configured(self) -> bool:
        """Returns True if minimum SMTP host configuration is present."""
        return bool(self.host and self.host.strip())

    def send_email(
        self,
        to_email: str,
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
    ) -> DeliveryResult:
        if not self.is_configured:
            logger.warning("SMTP delivery requested but SMTP host is not configured.")
            return DeliveryResult(
                success=False,
                provider="smtp",
                error="SMTP host not configured.",
            )

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.from_email
        msg["To"] = to_email
        msg.set_content(body_text)

        if body_html:
            msg.add_alternative(body_html, subtype="html")

        try:
            if self.port == 465:
                # SSL directly
                with smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout_seconds) as server:
                    if self.username and self.password:
                        server.login(self.username, self.password)
                    server.send_message(msg)
            else:
                # Standard SMTP + STARTTLS
                with smtplib.SMTP(self.host, self.port, timeout=self.timeout_seconds) as server:
                    if self.use_tls:
                        server.starttls()
                    if self.username and self.password:
                        server.login(self.username, self.password)
                    server.send_message(msg)

            logger.info("Successfully dispatched email via SMTP to %s", mask_email(to_email))
            return DeliveryResult(
                success=True,
                delivery_id=f"smtp-{int(datetime.now(timezone.utc).timestamp())}",
                provider="smtp",
            )
        except smtplib.SMTPAuthenticationError as e:
            logger.error("SMTP authentication error: %s", str(e))
            return DeliveryResult(success=False, provider="smtp", error="SMTP authentication failed.")
        except Exception as e:
            logger.error("SMTP delivery failure to %s: %s", mask_email(to_email), str(e))
            return DeliveryResult(success=False, provider="smtp", error=f"SMTP delivery error: {str(e)}")


class TwilioSmsAdapter:
    """Production-grade SMS delivery adapter utilizing Twilio REST API with fail-safe handling."""

    def __init__(
        self,
        account_sid: Optional[str],
        auth_token: Optional[str],
        from_number: Optional[str],
        timeout_seconds: float = 10.0,
    ) -> None:
        self.account_sid = account_sid
        self.auth_token = auth_token
        self.from_number = from_number
        self.timeout_seconds = timeout_seconds

    @property
    def is_configured(self) -> bool:
        """Returns True if Twilio credentials and from_number are present."""
        return bool(
            self.account_sid
            and self.account_sid.strip()
            and self.auth_token
            and self.auth_token.strip()
            and self.from_number
            and self.from_number.strip()
        )

    def send_sms(
        self,
        to_phone: str,
        message_text: str,
    ) -> DeliveryResult:
        if not self.is_configured:
            logger.warning("Twilio SMS delivery requested but Twilio credentials are not configured.")
            return DeliveryResult(
                success=False,
                provider="twilio",
                error="SMS provider credentials not configured.",
            )

        try:
            import urllib.request
            import urllib.parse
            import base64
            import json

            url = f"https://api.twilio.com/2010-04-01/Accounts/{self.account_sid}/Messages.json"
            data = urllib.parse.urlencode({
                "To": to_phone.strip(),
                "From": self.from_number.strip(),
                "Body": message_text,
            }).encode("utf-8")

            auth_str = f"{self.account_sid.strip()}:{self.auth_token.strip()}"
            b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("ascii")

            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Authorization", f"Basic {b64_auth}")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")

            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                sid = resp_data.get("sid", "unknown-sid")
                logger.info("Successfully dispatched SMS via Twilio to %s (SID: %s)", mask_phone_number(to_phone), sid)
                return DeliveryResult(
                    success=True,
                    delivery_id=sid,
                    provider="twilio",
                )
        except Exception as e:
            logger.error("Twilio SMS delivery failed for %s: %s", mask_phone_number(to_phone), str(e))
            return DeliveryResult(
                success=False,
                provider="twilio",
                error=f"SMS delivery error: {str(e)}",
            )


class UnconfiguredSmsAdapter:
    """Safe fallback when no SMS provider is configured. Fails safely without simulating delivery."""

    def send_sms(self, to_phone: str, message_text: str) -> DeliveryResult:
        return DeliveryResult(
            success=False,
            provider="none",
            error="SMS provider is not configured. Real delivery requires valid credentials.",
        )


class DeliveryManager:
    """
    Central delivery orchestration manager for the Expo Coordinator.
    Provides typed methods for verification emails, SMS codes, and security notices.
    """

    def __init__(
        self,
        mail_adapter: Optional[MailDeliveryAdapter] = None,
        sms_adapter: Optional[SmsDeliveryAdapter] = None,
    ) -> None:
        self.mail_adapter: MailDeliveryAdapter = mail_adapter or SmtpMailAdapter(host=None)
        self.sms_adapter: SmsDeliveryAdapter = sms_adapter or UnconfiguredSmsAdapter()

    def set_mail_adapter(self, adapter: MailDeliveryAdapter) -> None:
        self.mail_adapter = adapter

    def set_sms_adapter(self, adapter: SmsDeliveryAdapter) -> None:
        self.sms_adapter = adapter

    def send_email_verification(
        self,
        to_email: str,
        raw_token: str,
        base_url: str = "http://localhost:9000",
    ) -> DeliveryResult:
        """Dispatches an email verification link to the target user."""
        verify_url = f"{base_url.rstrip('/')}/auth/verify-email?token={raw_token}"
        subject = "Verify your Expo Storage Account"
        body_text = (
            "Welcome to Expo Distributed Storage!\n\n"
            "Please verify your email address by visiting the following link:\n"
            f"{verify_url}\n\n"
            "If you did not create an Expo account, please disregard this email."
        )
        body_html = f"""
        <div style="font-family: sans-serif; max-width: 540px; margin: auto; padding: 20px; border: 1px solid #334155; border-radius: 8px; background: #0f172a; color: #f8fafc;">
          <h2 style="color: #38bdf8;">🪐 Expo Distributed Storage</h2>
          <p>Please verify your email address to complete your account setup and unlock full storage quotas and capabilities.</p>
          <p style="margin: 24px 0;">
            <a href="{verify_url}" style="background: #0284c7; color: #ffffff; padding: 10px 20px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">Verify Email Address</a>
          </p>
          <p style="font-size: 0.85rem; color: #94a3b8;">Or copy and paste this URL into your browser:<br><code>{verify_url}</code></p>
          <p style="font-size: 0.75rem; color: #64748b; margin-top: 24px;">If you did not request this verification, you can safely ignore this message.</p>
        </div>
        """
        return self.mail_adapter.send_email(to_email, subject, body_text, body_html)

    def send_password_reset(
        self,
        to_email: str,
        raw_token: str,
        base_url: str = "http://localhost:9000",
    ) -> DeliveryResult:
        """Dispatches a password reset link to the target user."""
        reset_url = f"{base_url.rstrip('/')}/auth/reset-password?token={raw_token}"
        subject = "Reset your Expo Storage Account Password"
        body_text = (
            "A password reset request was received for your Expo account.\n\n"
            "You can reset your password by opening the following link:\n"
            f"{reset_url}\n\n"
            "This link will expire in 1 hour and can only be used once.\n"
            "If you did not request a password reset, please secure your account immediately."
        )
        body_html = f"""
        <div style="font-family: sans-serif; max-width: 540px; margin: auto; padding: 20px; border: 1px solid #334155; border-radius: 8px; background: #0f172a; color: #f8fafc;">
          <h2 style="color: #f43f5e;">🪐 Expo Account Security</h2>
          <p>We received a request to reset your password. Click the button below to choose a new password:</p>
          <p style="margin: 24px 0;">
            <a href="{reset_url}" style="background: #e11d48; color: #ffffff; padding: 10px 20px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">Reset Password</a>
          </p>
          <p style="font-size: 0.85rem; color: #94a3b8;">This single-use link expires in 1 hour.<br>URL: <code>{reset_url}</code></p>
          <p style="font-size: 0.75rem; color: #64748b; margin-top: 24px;">If you did not request a password reset, please contact your Expo administrator.</p>
        </div>
        """
        return self.mail_adapter.send_email(to_email, subject, body_text, body_html)

    def send_security_notice(
        self,
        to_email: str,
        title: str,
        details: str,
    ) -> DeliveryResult:
        """Sends an account security change notification email."""
        subject = f"[Expo Security] {title}"
        body_text = (
            f"{title}\n\n"
            f"{details}\n\n"
            f"Timestamp: {datetime.now(timezone.utc).isoformat()}\n"
            "If you did not authorize this change, please contact support or an administrator immediately."
        )
        body_html = f"""
        <div style="font-family: sans-serif; max-width: 540px; margin: auto; padding: 20px; border: 1px solid #334155; border-radius: 8px; background: #0f172a; color: #f8fafc;">
          <h2 style="color: #fbbf24;">⚠️ Expo Security Alert</h2>
          <h3 style="color: #f8fafc;">{title}</h3>
          <p style="color: #cbd5e1;">{details}</p>
          <p style="font-size: 0.8rem; color: #94a3b8;">Timestamp: {datetime.now(timezone.utc).isoformat()}</p>
          <p style="font-size: 0.75rem; color: #ef4444; margin-top: 20px;">If this was not done by you, please revoke active sessions and contact an administrator immediately.</p>
        </div>
        """
        return self.mail_adapter.send_email(to_email, subject, body_text, body_html)

    def send_sms_verification_code(
        self,
        to_phone: str,
        verification_code: str,
    ) -> DeliveryResult:
        """Dispatches an SMS verification code."""
        message_text = f"Your Expo verification code is {verification_code}. Valid for 10 minutes. Do not share this code."
        return self.sms_adapter.send_sms(to_phone, message_text)

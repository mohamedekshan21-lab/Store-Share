"""
Expo Account Provisioning & Role Management Module.

Safely provisions initial role assignments:
- mohamedekshan21@gmail.com -> admin
- 24d128@psgitech.ac.in -> provider
- ajishadhasin@gmail.com -> consumer

Adheres to strict security principles:
1. Consistently normalizes email addresses.
2. Preserves existing accounts, passwords, and sessions without overwriting.
3. Does not falsely mark unverified email addresses as verified.
4. Generates unique cryptographically secure secrets unless explicitly provided.
5. Idempotent: repeated runs are safe and non-destructive.
6. Records durable audit events for privileged role updates.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from coordinator.app.config import get_coordinator_settings
from coordinator.app.database import get_db_connection, record_audit_event
from coordinator.app.auth import hash_password

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("expo_provisioning")

REQUIRED_ASSIGNMENTS = [
    {
        "email": "mohamedekshan21@gmail.com",
        "target_role": "admin",
        "provider_id": None,
        "capabilities": ["file:read", "file:write", "provider:host", "admin:*"],
    },
    {
        "email": "24d128@psgitech.ac.in",
        "target_role": "provider",
        "provider_id": "provider_psgitech",
        "capabilities": ["file:read", "file:write", "provider:host"],
    },
    {
        "email": "ajishadhasin@gmail.com",
        "target_role": "consumer",
        "provider_id": None,
        "capabilities": ["file:read", "file:write"],
    },
]


def generate_secure_password() -> str:
    """Generates an entropy-rich password satisfying security constraints."""
    random_part = secrets.token_urlsafe(16)
    return f"{random_part}#Expo1"


def provision_accounts(
    db_path: Path,
    custom_passwords: Optional[Dict[str, str]] = None,
    dev_verify: bool = False,
) -> List[Dict[str, Any]]:
    """
    Safely and idempotently provisions the required initial account role assignments.
    Returns a list of provisioning result records.
    """
    custom_passwords = custom_passwords or {}
    results = []
    now_str = datetime.now(timezone.utc).isoformat()

    for spec in REQUIRED_ASSIGNMENTS:
        email_normalized = spec["email"].strip().lower()
        target_role = spec["target_role"]
        provider_id = spec["provider_id"]
        capabilities_json = json.dumps(spec["capabilities"])

        audit_to_record = None

        with get_db_connection(db_path) as conn:
            existing = conn.execute(
                "SELECT * FROM accounts WHERE LOWER(email) = ?",
                (email_normalized,),
            ).fetchone()

            if existing:
                account_id = existing["account_id"]
                current_role = existing["role"]
                is_role_changed = (current_role != target_role)

                if is_role_changed:
                    logger.info(
                        "Updating existing account [%s] role: %s -> %s",
                        email_normalized,
                        current_role,
                        target_role,
                    )
                    conn.execute(
                        """
                        UPDATE accounts
                        SET role = ?, capabilities = ?, updated_at = ?
                        WHERE account_id = ?
                        """,
                        (target_role, capabilities_json, now_str, account_id),
                    )
                    conn.commit()

                    audit_to_record = (
                        "account_role_promoted" if target_role == "admin" else "account_role_updated",
                        account_id,
                        {
                            "email": email_normalized,
                            "previous_role": current_role,
                            "new_role": target_role,
                            "source": "backend_provision_accounts",
                        },
                    )

                    results.append({
                        "email": email_normalized,
                        "account_id": account_id,
                        "role": target_role,
                        "action": "role_updated",
                        "previous_role": current_role,
                        "password_generated": False,
                        "email_verified": bool(existing["email_verified"]),
                    })
                else:
                    logger.info("Account [%s] already exists with target role [%s]. Preserving credentials.", email_normalized, target_role)
                    results.append({
                        "email": email_normalized,
                        "account_id": account_id,
                        "role": target_role,
                        "action": "preserved",
                        "previous_role": current_role,
                        "password_generated": False,
                        "email_verified": bool(existing["email_verified"]),
                    })
            else:
                # Create new account
                account_id = str(uuid.uuid4())
                raw_password = custom_passwords.get(email_normalized) or generate_secure_password()
                pw_hash = hash_password(raw_password)
                quota_bytes = 10 * 1024 * 1024 * 1024

                logger.info(
                    "Creating new account [%s] with role [%s]",
                    email_normalized,
                    target_role,
                )

                conn.execute(
                    """
                    INSERT INTO accounts (
                        account_id, email, password_hash, role, capabilities,
                        status, provider_id, email_verified, email_verified_at,
                        phone_number, phone_verified, phone_verified_at,
                        quota_bytes, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, NULL, 0, NULL, ?, ?, ?)
                    """,
                    (
                        account_id,
                        email_normalized,
                        pw_hash,
                        target_role,
                        capabilities_json,
                        provider_id,
                        1 if dev_verify else 0,
                        now_str if dev_verify else None,
                        quota_bytes,
                        now_str,
                        now_str,
                    ),
                )
                conn.commit()

                audit_to_record = (
                    "account_provisioned",
                    account_id,
                    {
                        "email": email_normalized,
                        "role": target_role,
                        "source": "backend_provision_accounts",
                    },
                )

                results.append({
                    "email": email_normalized,
                    "account_id": account_id,
                    "role": target_role,
                    "action": "created",
                    "initial_password": raw_password,
                    "password_generated": (email_normalized not in custom_passwords),
                    "email_verified": dev_verify,
                })

        if audit_to_record:
            action, target_id, details = audit_to_record
            record_audit_event(
                db_path=db_path,
                admin_account_id="system_bootstrap",
                admin_email="system@expo.internal",
                action=action,
                target_type="account",
                target_id=target_id,
                details=details,
            )

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Expo Initial Accounts Provisioning CLI")
    parser.add_argument("--db-path", type=str, default=None, help="Path to coordinator SQLite database")
    parser.add_argument("--provider-password", type=str, default=os.getenv("EXPO_PROVIDER_PASSWORD"), help="Password for 24d128@psgitech.ac.in if created")
    parser.add_argument("--consumer-password", type=str, default=os.getenv("EXPO_CONSUMER_PASSWORD"), help="Password for ajishadhasin@gmail.com if created")
    parser.add_argument("--admin-password", type=str, default=os.getenv("EXPO_ADMIN_PASSWORD"), help="Password for mohamedekshan21@gmail.com if created")
    parser.add_argument("--dev-verify", action="store_true", help="Mark new development accounts as verified (do not use in production)")
    args = parser.parse_args()

    settings = get_coordinator_settings()
    db_path = Path(args.db_path) if args.db_path else Path(settings.db_path)

    custom_passwords = {}
    if args.admin_password:
        custom_passwords["mohamedekshan21@gmail.com"] = args.admin_password
    if args.provider_password:
        custom_passwords["24d128@psgitech.ac.in"] = args.provider_password
    if args.consumer_password:
        custom_passwords["ajishadhasin@gmail.com"] = args.consumer_password

    logger.info("Running account provisioning on database: %s", db_path)
    results = provision_accounts(db_path, custom_passwords=custom_passwords, dev_verify=args.dev_verify)

    print("\n" + "=" * 70)
    print("EXPO INITIAL ACCOUNTS PROVISIONING REPORT")
    print("=" * 70)
    for res in results:
        status_line = f"[{res['role'].upper()}] {res['email']} -> Action: {res['action']} (ID: {res['account_id']})"
        print(status_line)
        if "initial_password" in res:
            print(f"   Initial Password: {res['initial_password']}")
        print(f"   Email Verified:   {res['email_verified']}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()

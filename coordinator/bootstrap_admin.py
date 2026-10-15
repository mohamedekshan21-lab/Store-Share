"""
Bootstrap CLI tool for securely initializing the initial Store-Share Administrator account.

Usage:
    python -m coordinator.bootstrap_admin --username admin --email admin@expo.net
    (Prompts for password securely without echoing)

Or using environment variables:
    INITIAL_ADMIN_USERNAME=admin INITIAL_ADMIN_EMAIL=admin@expo.net INITIAL_ADMIN_PASSWORD=secret python -m coordinator.bootstrap_admin
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from coordinator.app.config import get_coordinator_settings
from coordinator.app.database import init_db
from coordinator.app.user_auth import UserManager, Role


def bootstrap_admin(
    username: str,
    email: str,
    password: str,
    db_path: Optional[Path] = None,
    settings: Optional[CoordinatorSettings] = None,
):
    """Initializes database and provisions the initial administrator account."""
    resolved_settings = settings or get_coordinator_settings()
    if db_path:
        resolved_settings.db_path = db_path
    init_db(resolved_settings.db_path)
    user_manager = UserManager(resolved_settings)

    clean_user = username.strip().lower()
    clean_email = email.strip().lower()

    existing = user_manager.get_user_by_username(clean_user)
    if existing:
        raise ValueError(f"Administrator account '{clean_user}' already exists (ID: {existing.user_id}).")

    admin_user = user_manager.create_user(
        username=clean_user,
        email=clean_email,
        password=password,
        role=Role.ADMIN.value,
        provider_id=None,
        is_active=True,
    )
    print(f"Successfully provisioned Administrator account '{admin_user.username}' (ID: {admin_user.user_id}, Email: {admin_user.email}).")
    return admin_user


def main() -> None:
    parser = argparse.ArgumentParser(description="Provision initial Store-Share Administrator account.")
    parser.add_argument("--username", default=os.getenv("INITIAL_ADMIN_USERNAME"), help="Administrator username")
    parser.add_argument("--email", default=os.getenv("INITIAL_ADMIN_EMAIL"), help="Administrator email address")
    parser.add_argument("--password", default=os.getenv("INITIAL_ADMIN_PASSWORD"), help="Administrator password")
    parser.add_argument("--db-path", default=os.getenv("COORDINATOR_DB_PATH"), help="Path to SQLite database file")

    args = parser.parse_args()

    settings = get_coordinator_settings()
    db_path = Path(args.db_path).resolve() if args.db_path else settings.db_path

    username = args.username
    if not username:
        username = input("Enter admin username [default: admin]: ").strip() or "admin"

    email = args.email
    if not email:
        email = input("Enter admin email [default: admin@expo.net]: ").strip() or "admin@expo.net"

    password = args.password
    if not password:
        password = getpass.getpass("Enter secure admin password (min 8 characters): ")
        if not password or len(password) < 8:
            print("Error: Password must be at least 8 characters.", file=sys.stderr)
            sys.exit(1)
        confirm = getpass.getpass("Confirm admin password: ")
        if password != confirm:
            print("Error: Passwords do not match.", file=sys.stderr)
            sys.exit(1)

    try:
        bootstrap_admin(username, email, password, db_path)
    except Exception as exc:
        print(f"Error provisioning administrator: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

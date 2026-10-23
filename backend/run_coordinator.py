"""
Runner script for the Expo Coordinator service (Backend Service 1).
Listens on http://127.0.0.1:8000 by default.
"""

import os
import sys

# Ensure root directory is in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Set standard coordinator environment variables
os.environ.setdefault("COORDINATOR_PORT", "8000")
os.environ.setdefault("COORDINATOR_HOST", "127.0.0.1")
os.environ.setdefault("COORDINATOR_DB_PATH", os.path.join(ROOT_DIR, "coordinator_metadata.db"))
os.environ.setdefault("COORDINATOR_ENV", "development")
os.environ.setdefault("CAPABILITY_SECRET", "expo_test_secret_for_local_nodes_32bytes_long!")
os.environ.setdefault("COORDINATOR_COOKIE_SECURE", "false")
os.environ.setdefault("COORDINATOR_ADMIN_EMAIL", "admin_audit_10@expo.internal")
os.environ.setdefault("COORDINATOR_ADMIN_PASSWORD", "SuperAdminAuditPassword123!")

if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("COORDINATOR_HOST", "127.0.0.1")
    port = int(os.environ.get("COORDINATOR_PORT", "8000"))
    print("=============================================================")
    print(f"🪐 Starting Expo Coordinator Service on http://{host}:{port}/")
    print(f"📁 Database: {os.environ.get('COORDINATOR_DB_PATH')}")
    print("=============================================================")
    uvicorn.run("coordinator.app.main:app", host=host, port=port, reload=False)

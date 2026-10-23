"""
Runner script for the Expo Storage Node daemon (Backend Service 2).
Listens on http://127.0.0.1:8001 by default.
"""

import os
import sys

# Ensure root directory is in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Set standard storage node environment variables
os.environ.setdefault("PORT", "8001")
os.environ.setdefault("NODE_PORT", "8001")
os.environ.setdefault("HOST", "127.0.0.1")
os.environ.setdefault("NODE_ID", "node_local_01")
os.environ.setdefault("PROVIDER_ID", "provider_audit_10")
os.environ.setdefault("STORAGE_ROOT", os.path.join(ROOT_DIR, "storage", "node_01"))
os.environ.setdefault("CAPABILITY_SECRET", "expo_test_secret_for_local_nodes_32bytes_long!")
os.environ.setdefault("COORDINATOR_URL", "http://127.0.0.1:8000")
os.environ.setdefault("COORDINATOR_ENABLED", "true")
os.environ.setdefault("HEARTBEAT_INTERVAL_SECONDS", "5")
os.environ.setdefault("EXPO_ENV", "development")

if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8001"))
    print("=============================================================")
    print(f"📦 Starting Expo Storage Node '{os.environ.get('NODE_ID')}' on http://{host}:{port}/")
    print(f"📁 Storage Sandbox: {os.environ.get('STORAGE_ROOT')}")
    print(f"📡 Coordinator: {os.environ.get('COORDINATOR_URL')}")
    print("=============================================================")
    uvicorn.run("storage_node.app.main:app", host=host, port=port, reload=False)

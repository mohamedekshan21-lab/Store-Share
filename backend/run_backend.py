"""
Expo Distributed Storage — Unified Backend Orchestrator.
Spawns and manages both:
  1. Coordinator Service (http://127.0.0.1:8000)
  2. Local Storage Node Daemon (http://127.0.0.1:8001)
"""

import os
import sys
import time
import subprocess
import signal
import urllib.request
import json

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYTHON_EXE = sys.executable

def check_health(url, timeout=2.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            if response.status == 200:
                return json.loads(response.read().decode('utf-8'))
    except Exception:
        return None

def start_backend():
    print("=============================================================")
    print("🚀 Expo Distributed Storage — Starting Full Backend Suite")
    print("=============================================================")

    # 1. Start Coordinator
    coord_script = os.path.join(ROOT_DIR, "backend", "run_coordinator.py")
    print(f"[1/2] Launching Coordinator ({coord_script})...")
    coord_proc = subprocess.Popen([PYTHON_EXE, coord_script], cwd=ROOT_DIR)

    # Wait for coordinator health
    print("      Waiting for Coordinator to become healthy at http://127.0.0.1:8000/health...")
    for _ in range(30):
        time.sleep(0.5)
        health = check_health("http://127.0.0.1:8000/health")
        if health and health.get("status") == "online":
            print("      ✅ Coordinator is online and healthy!")
            break
    else:
        print("      ⚠️ Warning: Coordinator health check timed out. Proceeding...")

    # 2. Start Storage Node
    storage_script = os.path.join(ROOT_DIR, "backend", "run_storage_node.py")
    print(f"[2/2] Launching Storage Node ({storage_script})...")
    storage_proc = subprocess.Popen([PYTHON_EXE, storage_script], cwd=ROOT_DIR)

    # Wait for storage node health
    print("      Waiting for Storage Node to become healthy at http://127.0.0.1:8001/health...")
    for _ in range(30):
        time.sleep(0.5)
        health = check_health("http://127.0.0.1:8001/health")
        if health and health.get("status") == "online":
            print("      ✅ Storage Node is online and healthy!")
            break
    else:
        print("      ⚠️ Warning: Storage Node health check timed out. Proceeding...")

    print("=============================================================")
    print("🎉 Backend Services Running:")
    print("   • Coordinator API:   http://127.0.0.1:8000/")
    print("   • Storage Node API:  http://127.0.0.1:8001/")
    print("   • Readiness Probe:   http://127.0.0.1:8000/health/ready")
    print("   • Metrics Endpoint:  http://127.0.0.1:8000/observability/metrics")
    print("Press Ctrl+C to terminate all backend services.")
    print("=============================================================")

    def shutdown(sig, frame):
        print("\n🛑 Shutting down backend processes...")
        for proc, name in [(storage_proc, "Storage Node"), (coord_proc, "Coordinator")]:
            try:
                proc.terminate()
                proc.wait(timeout=5)
                print(f"   • Stopped {name}")
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Monitor both processes
    try:
        while True:
            time.sleep(1)
            if coord_proc.poll() is not None:
                print("❌ Coordinator exited unexpectedly.")
                break
            if storage_proc.poll() is not None:
                print("❌ Storage Node exited unexpectedly.")
                break
    except KeyboardInterrupt:
        shutdown(None, None)

if __name__ == "__main__":
    start_backend()

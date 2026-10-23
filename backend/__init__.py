"""
Expo Distributed Storage — Backend Package.
Provides unified path resolution and orchestration for Coordinator and Storage Node services.
"""

import os
import sys

# Ensure root workspace directory is on sys.path for coordinator, storage_node, and client
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

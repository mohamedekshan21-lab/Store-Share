"""
Command-Line Interface (CLI) for Expo Storage Node Client & Phase 3B Multi-Node Distributed Encryption Pipeline.

Usage examples:
    python -m client.cli health
    python -m client.cli node
    python -m client.cli storage
    python -m client.cli upload sample.txt
    python -m client.cli list
    python -m client.cli download <file_id> output.txt
    python -m client.cli delete <file_id>
    python -m client.cli nodes [--coordinator-url <url>]
    python -m client.cli select-node --min-bytes <bytes>
    python -m client.cli encrypt-upload <file> [--key-out <key.hex>] [--manifest-out <manifest.json>] [--nodes 3] [--coordinator-url <url>]
    python -m client.cli download-decrypt <manifest.json> <key_hex_or_keyfile> <output_path> [--coordinator-url <url>]

Options:
    --host <ip/hostname>   Target node host (default: NODE_HOST or 127.0.0.1)
    --port <port>          Target node port (default: NODE_PORT or 8000)
    --token <auth_token>   Authentication token (default: AUTH_TOKEN)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from client.client import ExpoClient, ClientError, IntegrityVerificationError
from client.chunker import FileManifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="expo-client",
        description="Expo Storage Node Remote CLI Client, Discovery & Multi-Node Distributed AES-256-GCM Pipeline",
    )
    parser.add_argument("--host", help="Storage Node host (overrides NODE_HOST)")
    parser.add_argument("--port", type=int, help="Storage Node port (overrides NODE_PORT)")
    parser.add_argument("--token", help="Storage Node authentication token (overrides AUTH_TOKEN)")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # health
    subparsers.add_parser("health", help="Check remote node health")

    # node
    subparsers.add_parser("node", help="Query node identity, status, and capacity")

    # storage
    subparsers.add_parser("storage", help="Query node storage quota and usage")

    # upload <filepath>
    upload_parser = subparsers.add_parser("upload", help="Upload a file to remote storage node")
    upload_parser.add_argument("file_path", help="Local file path to upload")

    # list
    subparsers.add_parser("list", help="List stored files on remote node")

    # download <file_id> <output_path>
    download_parser = subparsers.add_parser("download", help="Download a file and verify SHA-256 integrity")
    download_parser.add_argument("file_id", help="Remote file_id")
    download_parser.add_argument("output_path", help="Destination path for downloaded file")

    # delete <file_id>
    delete_parser = subparsers.add_parser("delete", help="Delete a file on remote node")
    delete_parser.add_argument("file_id", help="Remote file_id to delete")

    # nodes
    nodes_parser = subparsers.add_parser("nodes", help="Discover registered Storage Nodes via Coordinator")
    nodes_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")
    nodes_parser.add_argument("--status", help="Filter nodes by status (e.g. online, offline)")
    nodes_parser.add_argument("--connectivity", help="Filter nodes by connectivity capability (LAN, DIRECT, RELAY)")
    nodes_parser.add_argument("--min-bytes", type=int, help="Minimum available storage in bytes")

    # select-node
    select_parser = subparsers.add_parser("select-node", help="Smart node selection query via Coordinator")
    select_parser.add_argument("--min-bytes", type=int, required=True, help="Required available capacity in bytes")
    select_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")
    select_parser.add_argument("--connectivity", help="Preferred connectivity mode (LAN, DIRECT, RELAY)")

    # encrypt-upload <file> [--redundancy-mode erasure|replication] [--data-shards 4] [--parity-shards 2] [--key-out <key.hex>] [--manifest-out <manifest.json>] [--nodes 3] [--replication-factor 2] [--coordinator-url <url>] [--require-reachable]
    enc_up_parser = subparsers.add_parser("encrypt-upload", help="Client-side encrypt (AES-256-GCM), chunk, and distribute across Storage Nodes with replication or erasure coding")
    enc_up_parser.add_argument("file_path", help="Local file to encrypt and upload")
    enc_up_parser.add_argument("--key-out", help="Optional output path to save hex-encoded DEK encryption key")
    enc_up_parser.add_argument("--manifest-out", help="Optional output path to save JSON manifest file")
    enc_up_parser.add_argument("--chunk-size", type=int, help="Optional chunk size in bytes")
    enc_up_parser.add_argument("--redundancy-mode", choices=["replication", "erasure"], help="Storage redundancy mode ('replication' or 'erasure')")
    enc_up_parser.add_argument("--data-shards", "-k", type=int, help="Number of Reed-Solomon data shards (k) for erasure coding")
    enc_up_parser.add_argument("--parity-shards", "-m", type=int, help="Number of Reed-Solomon parity shards (m) for erasure coding")
    enc_up_parser.add_argument("--nodes", type=int, default=3, help="Desired number of Storage Nodes for multi-node placement (default: 3)")
    enc_up_parser.add_argument("--replication-factor", "-r", type=int, default=2, help="Replication factor for chunk redundancy (default: 2)")
    enc_up_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL for node discovery & placement")
    enc_up_parser.add_argument("--connectivity", help="Preferred connectivity mode (LAN, DIRECT, RELAY)")
    enc_up_parser.add_argument("--require-reachable", action="store_true", help="Perform real-time reachability probes and require reachable nodes")

    # download-decrypt <manifest.json> <key_or_keyfile> <output_path> [--coordinator-url <url>]
    dl_dec_parser = subparsers.add_parser("download-decrypt", help="Download chunks from assigned nodes, reassemble, and decrypt file")
    dl_dec_parser.add_argument("manifest_path", help="Path to JSON file manifest")
    dl_dec_parser.add_argument("key_or_keyfile", help="HEX encryption key string or path to key file")
    dl_dec_parser.add_argument("output_path", help="Destination path for decrypted file")
    dl_dec_parser.add_argument("--coordinator-url", help="Optional Coordinator URL to resolve node endpoints if needed")

    # check-node <node_id_or_endpoint> [--coordinator-url <url>]
    chk_node_parser = subparsers.add_parser("check-node", help="Run consumer-side connectivity check on a Storage Node")
    chk_node_parser.add_argument("node_target", help="Storage Node ID (e.g. NODE-A) or endpoint URL (e.g. http://10.0.0.1:8001)")
    chk_node_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")
    chk_node_parser.add_argument("--timeout", type=float, default=5.0, help="Timeout in seconds")

    # check-nodes [--coordinator-url <url>]
    chk_nodes_parser = subparsers.add_parser("check-nodes", help="Perform reachability diagnostic report for all discovered Storage Nodes")
    chk_nodes_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")
    chk_nodes_parser.add_argument("--status", help="Filter by Coordinator liveness status (e.g. online)")
    chk_nodes_parser.add_argument("--timeout", type=float, default=5.0, help="Timeout per node in seconds")

    # Phase 4B Repair CLI commands
    # repair-status [--coordinator-url <url>] [--file-id <id>]
    rep_stat_parser = subparsers.add_parser("repair-status", help="Query Phase 4B automatic repair job statuses via Coordinator")
    rep_stat_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")
    rep_stat_parser.add_argument("--file-id", help="Filter jobs by file_id")
    rep_stat_parser.add_argument("--state", help="Filter jobs by state (SUCCEEDED, REPAIRING, REPAIR_FAILED, UNRECOVERABLE)")

    # repair-file <manifest_path> [--coordinator-url <url>] [--manifest-out <out.json>]
    rep_file_parser = subparsers.add_parser("repair-file", help="Inspect and automatically repair all under-replicated chunks in a manifest")
    rep_file_parser.add_argument("manifest_path", help="Path to JSON file manifest")
    rep_file_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")
    rep_file_parser.add_argument("--manifest-out", help="Path to save updated manifest JSON after repair")

    # repair-chunk <manifest_path> <chunk_id> [--coordinator-url <url>] [--manifest-out <out.json>]
    rep_chunk_parser = subparsers.add_parser("repair-chunk", help="Repair a specific under-replicated chunk in a manifest")
    rep_chunk_parser.add_argument("manifest_path", help="Path to JSON file manifest")
    rep_chunk_parser.add_argument("chunk_id", help="Target chunk UUID to repair")
    rep_chunk_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")
    rep_chunk_parser.add_argument("--manifest-out", help="Path to save updated manifest JSON after repair")

    # Phase 5B Unified Operations
    
    # logical-upload <file> [--coordinator-url <url>]
    lu_parser = subparsers.add_parser("logical-upload", help="Unified upload: encrypt, distribute chunks, and register to Coordinator catalog")
    lu_parser.add_argument("file_path", help="Local file to encrypt and upload")
    lu_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")
    lu_parser.add_argument("--redundancy-mode", choices=["replication", "erasure"], default="replication", help="Storage redundancy mode")
    lu_parser.add_argument("--key", help="Optional hex string DEK to force specific encryption key")

    # logical-list [--coordinator-url <url>]
    ll_parser = subparsers.add_parser("logical-list", help="List logical files in Coordinator catalog")
    ll_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")

    # logical-download <file_id> <key_hex> <output_path> [--coordinator-url <url>]
    ld_parser = subparsers.add_parser("logical-download", help="Unified download: fetch manifest from catalog, download chunks, decrypt")
    ld_parser.add_argument("file_id", help="Logical File ID")
    ld_parser.add_argument("key_hex", help="HEX string of the DEK encryption key")
    ld_parser.add_argument("output_path", help="Output destination path")
    ld_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")

    # logical-delete <file_id> [--coordinator-url <url>]
    ldel_parser = subparsers.add_parser("logical-delete", help="Unified delete: remove physical chunks and transition catalog state")
    ldel_parser.add_argument("file_id", help="Logical File ID")
    ldel_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")

    # Phase 7B: Credits, Reputation & Accounting
    # credits-balance <node_id> [--coordinator-url <url>]
    cb_parser = subparsers.add_parser("credits-balance", help="Display a storage node's current non-monetary ECC credit balance")
    cb_parser.add_argument("node_id", help="Storage Node ID")
    cb_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")

    # credits-ledger <node_id> [--coordinator-url <url>] [--limit 50] [--offset 0] [--category CAT]
    cl_parser = subparsers.add_parser("credits-ledger", help="View a paginated contribution credit ledger for a node")
    cl_parser.add_argument("node_id", help="Storage Node ID")
    cl_parser.add_argument("--limit", type=int, default=50, help="Maximum entries to display")
    cl_parser.add_argument("--offset", type=int, default=0, help="Pagination offset")
    cl_parser.add_argument("--category", help="Filter by category ('storage', 'transfer_upload', 'transfer_download', 'replication', 'repair', 'reversal')")
    cl_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")

    # credits-summary <node_id> [--coordinator-url <url>]
    cs_parser = subparsers.add_parser("credits-summary", help="Display categorized contribution credit summaries for a node")
    cs_parser.add_argument("node_id", help="Storage Node ID")
    cs_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")

    # reputation-show <node_id> [--coordinator-url <url>] [--window-hours 168.0]
    rs_parser = subparsers.add_parser("reputation-show", help="Inspect a node's reputation score (0-100) and confidence indicator")
    rs_parser.add_argument("node_id", help="Storage Node ID")
    rs_parser.add_argument("--window-hours", type=float, default=168.0, help="Evaluation rolling window in hours")
    rs_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")

    # reputation-list [--coordinator-url <url>] [--window-hours 168.0]
    rl_parser = subparsers.add_parser("reputation-list", help="List reputation scores and confidence for all cluster nodes")
    rl_parser.add_argument("--window-hours", type=float, default=168.0, help="Evaluation rolling window in hours")
    rl_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")

    # accounting-policy [--coordinator-url <url>]
    ap_parser = subparsers.add_parser("accounting-policy", help="View the active versioned contribution and reputation policy")
    ap_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")

    # accounting-summary [--coordinator-url <url>]
    as_parser = subparsers.add_parser("accounting-summary", help="Display cluster-wide contribution credit and reputation totals")
    as_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")

    # Phase 8A: Provider Monitoring & Management CLI
    # provider-overview [--coordinator-url <url>] [--provider-id <id>] [--window-hours 24.0]
    po_parser = subparsers.add_parser("provider-overview", help="Display aggregated provider storage quota, bandwidth, credits, and reputation")
    po_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")
    po_parser.add_argument("--provider-id", help="Target provider ID (defaults to default_provider)")
    po_parser.add_argument("--window-hours", type=float, default=24.0, help="Monitoring activity window in hours")

    # provider-nodes [--coordinator-url <url>] [--provider-id <id>]
    pn_parser = subparsers.add_parser("provider-nodes", help="List all Storage Nodes registered to the provider")
    pn_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")
    pn_parser.add_argument("--provider-id", help="Target provider ID (defaults to default_provider)")

    # provider-node <node_id> [--coordinator-url <url>] [--provider-id <id>] [--window-hours 24.0]
    pnd_parser = subparsers.add_parser("provider-node", help="Inspect diagnostic details, transfer stats, and repairs for a provider node")
    pnd_parser.add_argument("node_id", help="Storage Node ID")
    pnd_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")
    pnd_parser.add_argument("--provider-id", help="Target provider ID (defaults to default_provider)")
    pnd_parser.add_argument("--window-hours", type=float, default=24.0, help="Diagnostic activity window in hours")

    # provider-scheduling <node_id> [--disable] [--reason <msg>] [--coordinator-url <url>] [--provider-id <id>]
    psc_parser = subparsers.add_parser("provider-scheduling", help="Enable or disable new chunk placement scheduling on a provider node")
    psc_parser.add_argument("node_id", help="Storage Node ID")
    psc_parser.add_argument("--disable", action="store_true", help="Disable placement scheduling (default enables)")
    psc_parser.add_argument("--reason", help="Optional operational reason for scheduling state change")
    psc_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")
    psc_parser.add_argument("--provider-id", help="Target provider ID (defaults to default_provider)")

    # provider-shutdown <node_id> [--reason <msg>] [--coordinator-url <url>] [--provider-id <id>]
    psh_parser = subparsers.add_parser("provider-shutdown", help="Gracefully drain and shutdown a provider node for maintenance")
    psh_parser.add_argument("node_id", help="Storage Node ID")
    psh_parser.add_argument("--reason", help="Optional operational reason for node shutdown")
    psh_parser.add_argument("--coordinator-url", default="http://127.0.0.1:9000", help="Coordinator URL")
    psh_parser.add_argument("--provider-id", help="Target provider ID (defaults to default_provider)")

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    node_url = None
    if args.host:
        port = args.port or 8000
        node_url = f"http://{args.host}:{port}"
    elif args.port:
        node_url = f"http://127.0.0.1:{args.port}"

    client = ExpoClient(node_url=node_url, auth_token=args.token)

    try:
        if args.command == "health":
            result = client.health()
            print("Status:", result.get("status", "unknown"))

        elif args.command == "node":
            info = client.node_info()
            print(f"Node ID     : {info.get('node_id')}")
            print(f"Status      : {info.get('status')}")
            print(f"Last Seen   : {info.get('last_seen')}")
            if info.get("storage"):
                s = info["storage"]
                print(f"Quota Bytes : {s.get('quota_bytes')}")
                print(f"Used Bytes  : {s.get('used_bytes')}")
                print(f"Avail Bytes : {s.get('available_bytes')}")

        elif args.command == "storage":
            s = client.storage_info()
            print(f"Quota Bytes : {s.get('quota_bytes')}")
            print(f"Used Bytes  : {s.get('used_bytes')}")
            print(f"Avail Bytes : {s.get('available_bytes')}")

        elif args.command == "upload":
            result = client.upload_file(args.file_path)
            print("Upload Successful!")
            print(f"File ID     : {result.get('file_id')}")
            print(f"Filename    : {result.get('original_filename')}")
            print(f"Size Bytes  : {result.get('size')}")
            print(f"SHA-256     : {result.get('sha256')}")
            print(f"Integrity   : VERIFIED (SHA-256 match)")

        elif args.command == "list":
            files = client.list_files()
            print(f"Total Stored Files: {len(files)}")
            for f in files:
                print(f" - ID: {f.get('file_id')} | Name: {f.get('original_filename')} | Size: {f.get('size')}B | SHA256: {f.get('sha256')[:12]}...")

        elif args.command == "download":
            result = client.download_file(args.file_id, args.output_path)
            print("Download Successful!")
            print(f"Output Path : {result.get('output_path')}")
            print(f"SHA-256     : {result.get('sha256')}")
            print(f"Integrity   : VERIFIED")

        elif args.command == "delete":
            client.delete_file(args.file_id)
            print(f"Successfully deleted file '{args.file_id}' from remote node.")

        elif args.command == "nodes":
            nodes = client.list_coordinator_nodes(
                coordinator_url=args.coordinator_url,
                status=args.status,
                connectivity_mode=args.connectivity,
                min_available_bytes=args.min_bytes,
            )
            print(f"Discovered {len(nodes)} Storage Node(s) via Coordinator:")
            for n in nodes:
                print(f" - Node ID: {n.get('node_id')} | Status: {n.get('status')} | Mode: {n.get('connectivity_mode')} | Avail: {n.get('available_capacity_bytes')}B | Endpoint: {n.get('advertised_endpoint') or n.get('endpoint')}")

        elif args.command == "select-node":
            selected = client.select_storage_node(
                coordinator_url=args.coordinator_url,
                required_bytes=args.min_bytes,
                preferred_connectivity=args.connectivity,
            )
            print("Smart Node Selection Result:")
            print(f"Selected Node ID : {selected.get('node_id')}")
            print(f"Status           : {selected.get('status')}")
            print(f"Connectivity     : {selected.get('connectivity_mode')}")
            print(f"Available Bytes  : {selected.get('available_capacity_bytes')}")
            print(f"Endpoint URL     : {selected.get('advertised_endpoint') or selected.get('endpoint')}")

        elif args.command == "encrypt-upload":
            manifest, dek = client.encrypt_and_upload_file(
                file_path=args.file_path,
                chunk_size=args.chunk_size,
                coordinator_url=args.coordinator_url,
                target_node_count=args.nodes,
                preferred_connectivity=args.connectivity,
                require_reachable=args.require_reachable,
                replication_factor=args.replication_factor,
                redundancy_mode=args.redundancy_mode,
                data_shards=args.data_shards,
                parity_shards=args.parity_shards,
            )
            key_hex = dek.hex()
            print(f"Multi-Node Distributed Encryption & Upload Successful ({manifest.redundancy_mode.upper()} mode)!")
            print(f"File ID         : {manifest.file_id}")
            print(f"Original Name   : {manifest.original_filename}")
            print(f"Original Size   : {manifest.original_size} bytes")
            print(f"Encrypted Size  : {manifest.encrypted_size} bytes")
            print(f"Chunk Count     : {manifest.chunk_count} (Chunk size: {manifest.chunk_size} bytes)")
            print(f"Redundancy Mode : {manifest.redundancy_mode.upper()}")
            if manifest.redundancy_mode == "erasure":
                print(f"Erasure Profile : Reed-Solomon (k={manifest.data_shards} data, m={manifest.parity_shards} parity -> {manifest.total_shards} total shards)")
            else:
                print(f"Replication Factor: {manifest.replication_factor} (1 Primary + {manifest.replication_factor - 1} Replica(s) per chunk)")
            print(f"Cipher Scheme   : {manifest.encryption_algorithm}")

            # Display Node placement mapping summary
            if manifest.redundancy_mode == "erasure":
                all_node_ids = {s.node_id for c in manifest.chunks for s in c.shards}
            else:
                all_placements = [p for c in manifest.chunks for p in c.get_effective_placements()]
                all_node_ids = {p.node_id for p in all_placements}
            print(f"Target Nodes    : Distributed across {len(all_node_ids)} Storage Node(s)")

            if args.key_out:
                Path(args.key_out).write_text(key_hex, encoding="utf-8")
                print(f"Encryption Key  : Saved to '{args.key_out}'")
            else:
                print(f"Encryption Key  : (HEX) {key_hex}")

            if args.manifest_out:
                Path(args.manifest_out).write_text(manifest.to_json(), encoding="utf-8")
                print(f"Manifest JSON   : Saved to '{args.manifest_out}'")

        elif args.command == "download-decrypt":
            manifest_p = Path(args.manifest_path)
            if not manifest_p.is_file():
                print(f"ERROR: Manifest file not found: '{args.manifest_path}'", file=sys.stderr)
                return 1

            manifest_json = manifest_p.read_text(encoding="utf-8")

            # Key resolution
            key_val = args.key_or_keyfile.strip()
            key_p = Path(key_val)
            if key_p.is_file():
                key_hex_str = key_p.read_text(encoding="utf-8").strip()
            else:
                key_hex_str = key_val

            out_path = client.download_and_decrypt_file(
                manifest_input=manifest_json,
                key_input=key_hex_str,
                output_path=args.output_path,
                coordinator_url=args.coordinator_url,
            )
            print("Distributed Download & Decryption Successful!")
            print(f"Output File     : {out_path}")
            print(f"Integrity       : VERIFIED (Byte-for-byte SHA-256 match)")

        elif args.command == "check-node":
            res = client.check_node_connectivity(
                node_id_or_endpoint=args.node_target,
                coordinator_url=args.coordinator_url,
                timeout=args.timeout,
            )
            print("Storage Node Connectivity Diagnostic:")
            print(f"Node ID      : {res.node_id}")
            print(f"Endpoint     : {res.endpoint}")
            print(f"Reachability : {res.reachability}")
            if res.reachability == "REACHABLE":
                print(f"Latency      : {res.latency_ms} ms")
                print(f"Protocol     : {res.protocol_version}")
            else:
                print(f"Reason       : {res.reason}")

        elif args.command == "check-nodes":
            results = client.check_all_nodes_connectivity(
                coordinator_url=args.coordinator_url,
                status_filter=args.status,
                timeout=args.timeout,
            )
            print(f"Expo Node Connectivity Report via Coordinator ({args.coordinator_url}):")
            print("-" * 80)
            print(f"{'NODE ID':<16} {'REACHABILITY':<14} {'LATENCY':<10} {'ENDPOINT'}")
            print("-" * 80)
            for r in results:
                lat_str = f"{r.latency_ms} ms" if r.latency_ms is not None else (r.reason[:10] if r.reason else "N/A")
                print(f"{r.node_id:<16} {r.reachability:<14} {lat_str:<10} {r.endpoint}")
            print("-" * 80)

        elif args.command == "repair-status":
            from coordinator.coordinator_client import CoordinatorClient
            coord_c = CoordinatorClient(coordinator_url=args.coordinator_url)
            jobs = coord_c.list_repair_jobs(state=args.state, file_id=args.file_id)
            print(f"Phase 4B Repair Jobs ({len(jobs)} total):")
            print("-" * 85)
            print(f"{'JOB ID':<12} {'CHUNK ID':<18} {'STATE':<14} {'SOURCE':<12} {'DESTINATION'}")
            print("-" * 85)
            for j in jobs:
                src = j.get('source_node_id') or 'N/A'
                dest = j.get('destination_node_id') or 'N/A'
                print(f"{j.get('job_id')[:10]:<12} {j.get('chunk_id')[:16]:<18} {j.get('state'):<14} {src:<12} {dest}")
            print("-" * 85)

        elif args.command == "repair-file":
            m_path = Path(args.manifest_path)
            if not m_path.is_file():
                print(f"ERROR: Manifest file not found: '{args.manifest_path}'", file=sys.stderr)
                return 1
            manifest = FileManifest.from_json(m_path.read_text(encoding="utf-8"))

            from client.repair import RepairEngine
            engine = RepairEngine()
            updated_manifest, jobs = engine.repair_manifest(
                manifest=manifest,
                client=client,
                coordinator_url=args.coordinator_url,
            )

            out_p = Path(args.manifest_out) if args.manifest_out else m_path
            out_p.write_text(updated_manifest.to_json(), encoding="utf-8")
            print(f"Phase 4B File Repair Completed for File '{manifest.file_id}'!")
            print(f"Total Jobs Run : {len(jobs)}")
            print(f"Manifest Saved : '{out_p}'")

        elif args.command == "repair-chunk":
            m_path = Path(args.manifest_path)
            if not m_path.is_file():
                print(f"ERROR: Manifest file not found: '{args.manifest_path}'", file=sys.stderr)
                return 1
            manifest = FileManifest.from_json(m_path.read_text(encoding="utf-8"))

            chunk_meta = next((c for c in manifest.chunks if c.chunk_id == args.chunk_id), None)
            if not chunk_meta:
                print(f"ERROR: Chunk ID '{args.chunk_id}' not found in manifest.", file=sys.stderr)
                return 1

            from client.repair import RepairEngine
            engine = RepairEngine()
            updated_meta, job = engine.repair_under_replicated_chunk(
                manifest=manifest,
                chunk_meta=chunk_meta,
                client=client,
                coordinator_url=args.coordinator_url,
            )

            out_p = Path(args.manifest_out) if args.manifest_out else m_path
            out_p.write_text(manifest.to_json(), encoding="utf-8")
            print(f"Phase 4B Chunk Repair Completed for Chunk '{args.chunk_id}'!")
            print(f"Job Status     : {job.state}")
            if job.destination_node_id:
                print(f"New Placement  : Node '{job.destination_node_id}' ({job.destination_node_endpoint})")
            print(f"Manifest Saved : '{out_p}'")

        # --- Phase 5B ---
        elif args.command == "logical-upload":
            key_bytes = bytes.fromhex(args.key.strip()) if args.key else None
            res = client.upload_logical_file(
                file_path=args.file_path,
                coordinator_url=args.coordinator_url,
                key=key_bytes,
                redundancy_mode=args.redundancy_mode
            )
            print("Logical Upload Successful!")
            print(f"File ID   : {res['file_id']}")
            print(f"Key (Hex) : {res['key_hex']}")
            print(f"Status    : {res['status']}")

        elif args.command == "logical-list":
            files = client.list_logical_files(coordinator_url=args.coordinator_url)
            print(f"Logical Files Found: {len(files)}")
            for f in files:
                print(f" - ID: {f.get('file_id')} | Name: {f.get('original_filename')} | Status: {f.get('status')} | Mode: {f.get('redundancy_mode')}")

        elif args.command == "logical-download":
            res = client.download_logical_file(
                file_id=args.file_id,
                output_path=args.output_path,
                key_input=args.key_hex,
                coordinator_url=args.coordinator_url
            )
            print("Logical Download Successful!")
            print(f"Output Path : {res['output_path']}")
            print(f"SHA-256     : {res['sha256']}")

        elif args.command == "logical-delete":
            res = client.delete_logical_file(
                file_id=args.file_id,
                coordinator_url=args.coordinator_url
            )
            print(f"Logical Deletion Complete for {res['file_id']}!")
            print(f"Physical Cleanup : {res['physical_success_count']} succeeded, {res['physical_failure_count']} failed")
            print(f"Final Status     : {res['status']}")

        # Phase 7B: Credits, Reputation & Accounting
        elif args.command == "credits-balance":
            from coordinator.coordinator_client import CoordinatorClient
            coord_c = CoordinatorClient(coordinator_url=args.coordinator_url)
            bal = coord_c.get_credit_balance(args.node_id)
            print(f"Expo Contribution Credits (ECC) for Node '{args.node_id}':")
            print(f"Current Balance     : {bal['total_credits']:.4f} ECC (non-monetary accounting units)")
            print(f"Lifetime Earned     : {bal['lifetime_earned']:.4f} ECC")
            print(f"Lifetime Reversed   : {bal['lifetime_reversed']:.4f} ECC")
            print(f"Last Reconciled At  : {bal['last_reconciled_at']}")

        elif args.command == "credits-ledger":
            from coordinator.coordinator_client import CoordinatorClient
            coord_c = CoordinatorClient(coordinator_url=args.coordinator_url)
            res = coord_c.get_credit_ledger(
                node_id=args.node_id,
                limit=args.limit,
                offset=args.offset,
                category=args.category,
            )
            print(f"Contribution Credit Ledger for Node '{args.node_id}' ({res['count']} entries on page):")
            print("-" * 90)
            print(f"{'ENTRY ID':<14} {'CATEGORY':<18} {'DELTA (ECC)':<14} {'TIMESTAMP':<22} {'REASON'}")
            print("-" * 90)
            for e in res["entries"]:
                delta_str = f"{e['credit_delta']:+.4f} ECC"
                print(f"{e['entry_id'][:12]:<14} {e['category']:<18} {delta_str:<14} {e['timestamp'][:19]:<22} {e['reason'][:40]}")
            print("-" * 90)
            print(f"Page Net Delta: {res['total_credits_in_page']:+.4f} ECC")

        elif args.command == "credits-summary":
            from coordinator.coordinator_client import CoordinatorClient
            coord_c = CoordinatorClient(coordinator_url=args.coordinator_url)
            summ = coord_c.get_credit_summary(args.node_id)
            print(f"Categorized Contribution Summary for Node '{args.node_id}':")
            print(f"Current ECC Balance     : {summ['current_balance']:.4f} ECC")
            print(f"Storage Contribution    : {summ['storage_credits']:.4f} ECC")
            print(f"Upload Ingress          : {summ['upload_credits']:.4f} ECC")
            print(f"Download Egress         : {summ['download_credits']:.4f} ECC")
            print(f"Replication Operations  : {summ['replication_credits']:.4f} ECC")
            print(f"Repair Operations       : {summ['repair_credits']:.4f} ECC")
            print(f"Administrative Reversals: {summ['reversal_credits']:.4f} ECC")
            print(f"Total Ledger Entries    : {summ['entry_count']}")

        elif args.command == "reputation-show":
            from coordinator.coordinator_client import CoordinatorClient
            coord_c = CoordinatorClient(coordinator_url=args.coordinator_url)
            rep = coord_c.get_node_reputation(args.node_id, window_hours=args.window_hours)
            print(f"Node Reputation & Trust Score for '{args.node_id}':")
            print(f"Reputation Score      : {rep['reputation_score']:.2f} / 100.00")
            print(f"Availability Score    : {rep['availability_score']:.2f} / 100.00")
            print(f"Integrity Score       : {rep['integrity_score']:.2f} / 100.00")
            print(f"Recovery Score        : {rep['recovery_score']:.2f} / 100.00")
            print(f"Confidence Indicator  : {rep['confidence_indicator']:.2f} / 1.00 ({rep['data_sufficiency_status']})")
            print(f"Policy Version        : {rep['policy_version']}")
            print(f"Evaluated At          : {rep['calculated_at']}")

        elif args.command == "reputation-list":
            from coordinator.coordinator_client import CoordinatorClient
            coord_c = CoordinatorClient(coordinator_url=args.coordinator_url)
            res = coord_c.list_node_reputations(window_hours=args.window_hours)
            print(f"Cluster Node Reputations ({res['count']} nodes evaluated over {args.window_hours}h window):")
            print("-" * 80)
            print(f"{'NODE ID':<16} {'SCORE':<10} {'AVAIL':<10} {'INTEG':<10} {'RECOV':<10} {'CONFIDENCE':<12} {'STATUS'}")
            print("-" * 80)
            for n in res["nodes"]:
                print(f"{n['node_id']:<16} {n['reputation_score']:<10.2f} {n['availability_score']:<10.2f} {n['integrity_score']:<10.2f} {n['recovery_score']:<10.2f} {n['confidence_indicator']:<12.2f} {n['data_sufficiency_status']}")
            print("-" * 80)

        elif args.command == "accounting-policy":
            from coordinator.coordinator_client import CoordinatorClient
            coord_c = CoordinatorClient(coordinator_url=args.coordinator_url)
            pol = coord_c.get_accounting_policy()
            print(f"Active Expo Accounting & Reputation Policy (Version: {pol['policy_version']}):")
            print("Contribution Weights:")
            print(f"  Storage Rate (GB-day)   : {pol['storage_weight_per_gb_day']} ECC")
            print(f"  Upload Ingress Rate (GB): {pol['upload_weight_per_gb']} ECC")
            print(f"  Download Egress Rate (GB): {pol['download_weight_per_gb']} ECC")
            print(f"  Replication Op Base     : {pol['replication_op_weight']} ECC (plus {pol['replication_weight_per_gb']} ECC/GB)")
            print(f"  Repair Op Base          : {pol['repair_op_weight']} ECC (plus {pol['repair_weight_per_gb']} ECC/GB)")
            print("Reputation Weights:")
            print(f"  Availability Weight     : {pol['availability_weight'] * 100:.0f}%")
            print(f"  Integrity Weight        : {pol['integrity_weight'] * 100:.0f}%")
            print(f"  Recovery Weight         : {pol['recovery_weight'] * 100:.0f}%")

        elif args.command == "accounting-summary":
            from coordinator.coordinator_client import CoordinatorClient
            coord_c = CoordinatorClient(coordinator_url=args.coordinator_url)
            summ = coord_c.get_accounting_cluster_summary()
            print(f"Cluster Contribution Accounting Summary (Policy: {summ['policy_version']}):")
            print(f"Nodes Evaluated       : {summ['total_nodes_evaluated']}")
            print(f"Total ECC Issued      : {summ['total_credits_issued']:.4f} ECC")
            print(f"Total ECC Reversed    : {summ['total_credits_reversed']:.4f} ECC")
            print(f"Net Cluster Credits   : {summ['net_cluster_credits']:.4f} ECC")
            print(f"Average Reputation    : {summ['average_reputation_score']:.2f} / 100.00")
            print(f"High-Confidence Nodes : {summ['high_confidence_nodes_count']}")

        elif args.command == "provider-overview":
            from coordinator.coordinator_client import CoordinatorClient
            coord_c = CoordinatorClient(coordinator_url=args.coordinator_url, auth_token=args.token)
            ov = coord_c.get_provider_overview(window_hours=args.window_hours, provider_id=args.provider_id)
            phys_disk = ov.get("total_physical_disk_bytes") or 0
            offline_count = ov.get("total_nodes_count", 0) - ov.get("online_nodes_count", 0)
            print(f"=== Expo Provider Overview ({ov['provider_id']}) ===")
            print(f"Nodes Registered      : {ov['total_nodes_count']} ({ov['online_nodes_count']} online, {offline_count} offline)")
            print(f"Configured Quota      : {ov['total_configured_quota_bytes'] / (1024**3):.2f} GiB ({ov['total_configured_quota_bytes']:,} B)")
            print(f"Verified Stored Data  : {ov['total_verified_stored_bytes'] / (1024**3):.2f} GiB ({ov['total_verified_stored_bytes']:,} B)")
            print(f"Physical Host Disk    : {phys_disk / (1024**3):.2f} GiB ({phys_disk:,} B)")
            print(f"Remaining Expo Quota  : {ov['total_remaining_quota_bytes'] / (1024**3):.2f} GiB ({ov['total_remaining_quota_bytes']:,} B)")
            print(f"Recent Ingress (Upload): {ov['total_ingress_bytes'] / (1024**2):.2f} MiB ({ov['total_ingress_bytes']:,} B)")
            print(f"Recent Egress (Download): {ov['total_egress_bytes'] / (1024**2):.2f} MiB ({ov['total_egress_bytes']:,} B)")
            print(f"Total ECC Balance     : {ov['total_credit_balance']:.4f} ECC")
            print(f"Avg Reputation Score  : {ov['average_reputation_score']:.2f} / 100.00")
            print(f"Repairs (Succ/Fail)   : {ov['recent_successful_repairs']} / {ov['recent_failed_repairs']}")

        elif args.command == "provider-nodes":
            from coordinator.coordinator_client import CoordinatorClient
            coord_c = CoordinatorClient(coordinator_url=args.coordinator_url, auth_token=args.token)
            nodes = coord_c.get_provider_nodes(provider_id=args.provider_id)
            print(f"=== Registered Provider Nodes ({len(nodes)}) ===")
            print("-" * 90)
            print(f"{'NODE ID':<16} {'STATUS':<10} {'SCHED':<8} {'CONN':<8} {'VERIFIED / QUOTA':<24} {'REPUTATION':<10} {'LAST SEEN'}")
            print("-" * 90)
            for n in nodes:
                sched_str = "YES" if n.get("is_schedulable") else "NO"
                used_gb = n.get("verified_stored_bytes", 0) / (1024**3)
                quota_gb = n.get("total_configured_quota_bytes", 0) / (1024**3)
                cap_str = f"{used_gb:.2f} / {quota_gb:.2f} GiB"
                last_seen = n.get("last_seen") or "Never"
                if len(last_seen) > 19:
                    last_seen = last_seen[:19]
                print(f"{n['node_id']:<16} {n['status']:<10} {sched_str:<8} {n['connectivity_mode']:<8} {cap_str:<24} {n['reputation_score']:<10.1f} {last_seen}")
            print("-" * 90)

        elif args.command == "provider-node":
            from coordinator.coordinator_client import CoordinatorClient
            coord_c = CoordinatorClient(coordinator_url=args.coordinator_url, auth_token=args.token)
            nd = coord_c.get_provider_node_detail(args.node_id, window_hours=args.window_hours, provider_id=args.provider_id)
            phys_cap = nd.get("physical_disk_total_bytes") or 0
            print(f"=== Node Diagnostic Detail: {nd['node_id']} ===")
            print(f"Status                : {nd['status']} (Schedulable: {nd['is_schedulable']})")
            print(f"Endpoint              : {nd['endpoint']} ({nd['connectivity_mode']})")
            print(f"Configured Quota      : {nd['total_configured_quota_bytes'] / (1024**3):.2f} GiB")
            print(f"Verified Stored Data  : {nd['verified_stored_bytes'] / (1024**3):.2f} GiB")
            print(f"Physical Host Capacity: {phys_cap / (1024**3):.2f} GiB")
            print(f"Remaining Node Quota  : {nd['remaining_quota_bytes'] / (1024**3):.2f} GiB")
            print(f"Last Seen             : {nd['last_seen'] or 'Never'}")
            print(f"Availability          : {nd['observed_availability_percentage']:.2f}%")
            print(f"ECC Credit Balance    : {nd['credit_balance']:.4f} ECC")
            print(f"Reputation Score      : {nd['reputation_score']:.2f} / 100.00 (Confidence: {nd['confidence_indicator']:.2f})")
            print(f"Window Ingress/Egress : {nd['total_ingress_bytes'] / (1024**2):.2f} MiB / {nd['total_egress_bytes'] / (1024**2):.2f} MiB")
            print(f"Repairs (Succ/Fail)   : {nd['recent_repairs_count']} / {nd['recent_failed_repairs_count']}")


        elif args.command == "provider-scheduling":
            from coordinator.coordinator_client import CoordinatorClient
            coord_c = CoordinatorClient(coordinator_url=args.coordinator_url, auth_token=args.token)
            new_sched = not args.disable
            res = coord_c.set_node_scheduling(args.node_id, is_schedulable=new_sched, reason=args.reason, provider_id=args.provider_id)
            state_str = "ENABLED" if res.get("is_schedulable") else "DISABLED"
            print(f"Node '{args.node_id}' placement scheduling set to: {state_str}")
            if res.get("reason"):
                print(f"Reason: {res['reason']}")

        elif args.command == "provider-shutdown":
            from coordinator.coordinator_client import CoordinatorClient
            coord_c = CoordinatorClient(coordinator_url=args.coordinator_url, auth_token=args.token)
            res = coord_c.initiate_node_shutdown(args.node_id, reason=args.reason, provider_id=args.provider_id)
            print(f"Node '{args.node_id}' shutdown initiated. Status: {res.get('status')}")
            if res.get("reason"):
                print(f"Reason: {res['reason']}")



        return 0

    except Exception as exc:
        print(f"ERROR: {str(exc)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

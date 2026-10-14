"""
Command-Line Interface (CLI) for Expo Storage Node Client.

Usage examples:
    python -m client.cli health
    python -m client.cli node
    python -m client.cli storage
    python -m client.cli upload sample.txt
    python -m client.cli list
    python -m client.cli download <file_id> output.txt
    python -m client.cli delete <file_id>

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="expo-client",
        description="Expo Storage Node Remote CLI Client",
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

        return 0

    except (ClientError, IntegrityVerificationError) as exc:
        print(f"ERROR: {str(exc)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

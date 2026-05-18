#!/usr/bin/env python3
"""
Create a Treeship action attestation.

Usage:
    python attest_action.py --actor "agent://my-agent" --action "tool.call" [--meta '{"key": "val"}']

Environment:
    TREESHIP_API_KEY - API key for Hub operations (optional)
"""

import argparse
import json
import os
import sys

def main():
    parser = argparse.ArgumentParser(description="Create a Treeship action attestation")
    parser.add_argument("--actor", required=True, help="Actor URI (e.g., agent://my-agent)")
    parser.add_argument("--action", required=True, help="Action description")
    parser.add_argument("--parent-id", help="Parent artifact ID for chain linking")
    parser.add_argument("--approval-nonce", help="Approval nonce to bind")
    parser.add_argument("--meta", help="Metadata as JSON string")
    parser.add_argument("--push", action="store_true", help="Push to Hub after attestation")
    args = parser.parse_args()

    try:
        from treeship_sdk import Treeship
    except ImportError:
        print("Error: treeship-sdk not installed. Run: pip install treeship-sdk")
        sys.exit(1)

    ts = Treeship()

    meta = None
    if args.meta:
        try:
            meta = json.loads(args.meta)
        except json.JSONDecodeError as e:
            print(f"Error: invalid JSON metadata: {e}")
            sys.exit(1)

    try:
        result = ts.attest_action(
            actor=args.actor,
            action=args.action,
            parent_id=args.parent_id,
            approval_nonce=args.approval_nonce,
            meta=meta
        )
        print(f"artifact_id: {result.artifact_id}")

        if args.push:
            push = ts.dock_push(result.artifact_id)
            print(f"hub_url: {push.hub_url}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

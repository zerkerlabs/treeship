#!/usr/bin/env python3
"""
Verify a Treeship artifact and walk its chain.

Usage:
    python verify_artifact.py <artifact_id>
    python verify_artifact.py last          # verify most recent

Environment:
    TREESHIP_API_KEY - API key for Hub verification (optional, local works offline)
"""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description="Verify a Treeship artifact")
    parser.add_argument("artifact_id", help="Artifact ID to verify, or 'last' for most recent")
    parser.add_argument("--json", action="store_true", help="Output JSON format")
    args = parser.parse_args()

    try:
        from treeship_sdk import Treeship
    except ImportError:
        print("Error: treeship-sdk not installed. Run: pip install treeship-sdk")
        sys.exit(1)

    ts = Treeship()

    try:
        result = ts.verify(args.artifact_id)

        if args.json:
            import json
            print(json.dumps({
                "outcome": result.outcome,
                "chain_length": result.chain,
                "target": result.target
            }))
        else:
            status_icon = "✓" if result.outcome == "pass" else "✗"
            print(f"{status_icon} Verification {result.outcome}")
            print(f"  Target:   {result.target}")
            print(f"  Chain:    {result.chain} artifact(s)")

        sys.exit(0 if result.outcome == "pass" else 1)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

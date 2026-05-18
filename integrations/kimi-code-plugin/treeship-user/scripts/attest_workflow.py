#!/usr/bin/env python3
"""
Create chained Treeship attestations for multi-step agent workflows.

Usage:
    python attest_workflow.py --config workflow.json

workflow.json format:
    {
        "steps": [
            {"actor": "agent://researcher", "action": "search.web", "meta": {"query": "AI safety"}},
            {"actor": "agent://analyst", "action": "analyze.data", "meta": {"dataset": "papers.json"}},
            {"actor": "agent://writer", "action": "generate.report", "meta": {"format": "markdown"}}
        ]
    }

Options:
    --push       Push final artifact to Hub
    --verify     Verify the chain after creation
"""

import argparse
import json
import sys


def main():
    parser = argparse.ArgumentParser(description="Create chained Treeship attestations")
    parser.add_argument("--config", required=True, help="Path to workflow config JSON")
    parser.add_argument("--push", action="store_true", help="Push final artifact to Hub")
    parser.add_argument("--verify", action="store_true", help="Verify chain after creation")
    args = parser.parse_args()

    try:
        from treeship_sdk import Treeship
    except ImportError:
        print("Error: treeship-sdk not installed. Run: pip install treeship-sdk")
        sys.exit(1)

    with open(args.config) as f:
        config = json.load(f)

    steps = config.get("steps", [])
    if not steps:
        print("Error: no steps defined in config")
        sys.exit(1)

    ts = Treeship()
    prev_id = config.get("parent_id")
    artifact_ids = []

    for i, step in enumerate(steps):
        print(f"Step {i + 1}/{len(steps)}: {step['actor']} → {step['action']}")

        result = ts.attest_action(
            actor=step["actor"],
            action=step["action"],
            parent_id=prev_id,
            approval_nonce=step.get("approval_nonce"),
            meta=step.get("meta")
        )

        artifact_ids.append(result.artifact_id)
        prev_id = result.artifact_id
        print(f"  → {result.artifact_id}")

    print(f"\nChain complete: {len(artifact_ids)} artifact(s)")
    print(f"Final artifact: {artifact_ids[-1]}")

    if args.verify:
        print("\nVerifying chain...")
        verify_result = ts.verify(artifact_ids[-1])
        status = "✓" if verify_result.outcome == "pass" else "✗"
        print(f"{status} {verify_result.outcome} ({verify_result.chain} artifacts)")

    if args.push:
        print("\nPushing to Hub...")
        push_result = ts.dock_push(artifact_ids[-1])
        print(f"  → {push_result.hub_url}")

    # Output summary
    summary = {
        "chain_length": len(artifact_ids),
        "artifact_ids": artifact_ids,
        "final_artifact": artifact_ids[-1]
    }
    if args.push:
        summary["hub_url"] = push_result.hub_url

    print("\n" + json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

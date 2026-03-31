"""Treeship SDK client. Wraps the treeship CLI binary."""

import json
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


class TreeshipError(Exception):
    """Error from the treeship CLI."""

    def __init__(self, message: str, args: List[str]):
        super().__init__(message)
        self.args_used = args


@dataclass
class ActionResult:
    artifact_id: str


@dataclass
class ApprovalResult:
    artifact_id: str
    nonce: str


@dataclass
class VerifyResult:
    outcome: str  # "pass", "fail", "error"
    chain: int
    target: str


@dataclass
class PushResult:
    hub_url: str
    rekor_index: Optional[int] = None


def _run(args: List[str], timeout: int = 10) -> Dict[str, Any]:
    """Run a treeship CLI command and return parsed JSON."""
    try:
        result = subprocess.run(
            ["treeship"] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            raise TreeshipError(
                f"treeship {' '.join(args[:2])} failed: {result.stderr.strip()}",
                args,
            )
        return json.loads(result.stdout)
    except FileNotFoundError:
        raise TreeshipError(
            "treeship CLI not found. Install: curl -fsSL treeship.dev/install | sh",
            args,
        )
    except json.JSONDecodeError:
        raise TreeshipError(
            f"treeship returned invalid JSON: {result.stdout[:200]}",
            args,
        )


class Treeship:
    """
    Treeship SDK client.

    Wraps the treeship CLI binary for signing, verification, and Hub operations.
    Requires the treeship binary in PATH.

    Usage:
        ts = Treeship()
        result = ts.attest_action(actor="agent://my-agent", action="tool.call")
        print(result.artifact_id)
    """

    def attest_action(
        self,
        actor: str,
        action: str,
        parent_id: Optional[str] = None,
        approval_nonce: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> ActionResult:
        """Create a signed action receipt."""
        args = ["attest", "action", "--actor", actor, "--action", action, "--format", "json"]
        if parent_id:
            args += ["--parent", parent_id]
        if approval_nonce:
            args += ["--approval-nonce", approval_nonce]
        if meta:
            args += ["--meta", json.dumps(meta)]
        result = _run(args)
        return ActionResult(artifact_id=result.get("id") or result.get("artifact_id", ""))

    def attest_approval(
        self,
        approver: str,
        description: str,
        expires_in: Optional[str] = None,
    ) -> ApprovalResult:
        """Create a signed approval receipt with a single-use nonce."""
        args = ["attest", "approval", "--approver", approver, "--description", description, "--format", "json"]
        if expires_in:
            args += ["--expires", expires_in]
        result = _run(args)
        return ApprovalResult(
            artifact_id=result.get("id") or result.get("artifact_id", ""),
            nonce=result.get("nonce", ""),
        )

    def attest_handoff(
        self,
        from_actor: str,
        to_actor: str,
        artifacts: List[str],
        approvals: Optional[List[str]] = None,
    ) -> ActionResult:
        """Create a signed handoff receipt between agents."""
        args = [
            "attest", "handoff",
            "--from", from_actor,
            "--to", to_actor,
            "--artifacts", ",".join(artifacts),
            "--format", "json",
        ]
        if approvals:
            args += ["--approvals", ",".join(approvals)]
        result = _run(args)
        return ActionResult(artifact_id=result.get("id") or result.get("artifact_id", ""))

    def attest_decision(
        self,
        actor: str,
        model: Optional[str] = None,
        tokens_in: Optional[int] = None,
        tokens_out: Optional[int] = None,
        summary: Optional[str] = None,
        confidence: Optional[float] = None,
        parent_id: Optional[str] = None,
    ) -> ActionResult:
        """Create a signed decision receipt (LLM reasoning context)."""
        args = ["attest", "decision", "--actor", actor, "--format", "json"]
        if model:
            args += ["--model", model]
        if tokens_in is not None:
            args += ["--tokens-in", str(tokens_in)]
        if tokens_out is not None:
            args += ["--tokens-out", str(tokens_out)]
        if summary:
            args += ["--summary", summary]
        if confidence is not None:
            args += ["--confidence", str(confidence)]
        if parent_id:
            args += ["--parent", parent_id]
        result = _run(args)
        return ActionResult(artifact_id=result.get("id") or result.get("artifact_id", ""))

    def verify(self, artifact_id: str) -> VerifyResult:
        """Verify an artifact and its chain."""
        result = _run(["verify", artifact_id, "--format", "json"])
        return VerifyResult(
            outcome=result.get("outcome", "error"),
            chain=result.get("total", result.get("chain", 1)),
            target=artifact_id,
        )

    def dock_push(self, artifact_id: str) -> PushResult:
        """Push an artifact to Hub."""
        result = _run(["dock", "push", artifact_id, "--format", "json"])
        return PushResult(
            hub_url=result.get("hub_url", result.get("url", "")),
            rekor_index=result.get("rekor_index"),
        )

    def wrap(self, command: str, actor: Optional[str] = None) -> ActionResult:
        """Wrap a shell command with a signed receipt."""
        args = ["wrap"]
        if actor:
            args += ["--actor", actor]
        args += ["--format", "json", "--"] + command.split()
        result = _run(args, timeout=300)  # longer timeout for wrapped commands
        return ActionResult(artifact_id=result.get("id") or result.get("artifact_id", ""))

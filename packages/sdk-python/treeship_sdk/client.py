"""Treeship SDK client. Wraps the treeship CLI binary."""

import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from treeship_sdk.bootstrap import (
    BootstrapResult,
    TreeshipBootstrapError,
    ensure_cli,
)


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


@dataclass
class SessionReportResult:
    """Result of uploading a session receipt to the configured hub.

    session_id  -- the session whose receipt was uploaded
    receipt_url -- the permanent public URL where the receipt is served;
                   safe to share, no auth required to fetch
    agents      -- number of distinct agents the hub extracted from the
                   receipt's agent_graph.nodes
    events      -- number of timeline events in the receipt
    """

    session_id: str
    receipt_url: str
    agents: int = 0
    events: int = 0


def _run(args: List[str], timeout: int = 10, *, binary: str = "treeship") -> Dict[str, Any]:
    """Run a treeship CLI command and return parsed JSON.

    `binary` lets the caller override which executable is invoked --
    used by the agent-native bootstrap path (Treeship(bot_mode=True))
    so the SDK can shell out to a CLI it resolved itself rather than
    relying on PATH.
    """
    try:
        result = subprocess.run(
            [binary] + args,
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
            "treeship CLI not found. Install: curl -fsSL treeship.dev/install | sh\n"
            "  Or in a Python program: ts = Treeship(bot_mode=True)  # auto-resolves the CLI",
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

    Two construction modes:

      Treeship()
        Default — assumes ``treeship`` is on PATH. Raises
        :class:`TreeshipError` if the binary isn't found at call time.

      Treeship(bot_mode=True)
        Agent-native — calls :func:`ensure_cli` at construction time to
        resolve the binary via env / PATH / cache / npm / GitHub Release
        in that order. AI agents on a fresh machine should use this so
        they don't have to ask a human "is the CLI installed?".

    Usage::

        # default
        ts = Treeship()
        result = ts.attest_action(actor="agent://my-agent", action="tool.call")

        # agent-native bootstrap
        ts = Treeship(bot_mode=True)
        # CLI resolved + ready, even on a fresh sandbox
    """

    def __init__(self, *, bot_mode: bool = False) -> None:
        # Default: use whatever's on PATH. The CLI lookup happens at
        # call time inside _run(), so an unresolved binary fails on the
        # first method call (with a recovery hint pointing at bot_mode).
        self._binary: str = "treeship"
        self._bootstrap: Optional[BootstrapResult] = None
        if bot_mode:
            try:
                self._bootstrap = ensure_cli()
                self._binary = self._bootstrap.binary
            except TreeshipBootstrapError as exc:
                raise TreeshipError(
                    f"agent-native bootstrap failed: {exc} (reason={exc.reason})",
                    [],
                ) from exc

    @classmethod
    def ensure_cli(cls) -> BootstrapResult:
        """Resolve a working CLI binary without instantiating the SDK.

        Sugar around :func:`treeship_sdk.bootstrap.ensure_cli` so a
        caller can do::

            from treeship_sdk import Treeship
            Treeship.ensure_cli()

        without importing the bootstrap submodule.
        """
        return ensure_cli()

    @property
    def binary(self) -> str:
        """Path to the resolved CLI binary. ``"treeship"`` when not bot-mode."""
        return self._binary

    @property
    def bootstrap(self) -> Optional[BootstrapResult]:
        """The resolution result when bot_mode=True; ``None`` otherwise."""
        return self._bootstrap

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
        """Create a signed approval receipt with a binding nonce.

        v0.9.6 enforces binding + scope (when set on the underlying CLI)
        statelessly; replay enforcement is package-local. Cross-package
        and distributed replay enforcement land in v0.10 (local
        Approval Use Journal) and v0.11+ (Hub-backed checkpoints).
        """
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
        """Verify an artifact and its chain.

        A verify failure (outcome=fail) is a STRUCTURED result, not an
        exception. The CLI exits non-zero on a failed verification but
        still emits valid JSON with the failure detail; we mirror that
        here -- callers get a VerifyResult with outcome="fail" instead
        of a TreeshipError. This matches the TypeScript SDK's
        ship().verify.verify() shape, so cross-SDK callers see the same
        contract regardless of language.

        TreeshipError is reserved for cases where verification couldn't
        even be attempted: missing CLI binary, malformed JSON output,
        keystore inaccessible.
        """
        try:
            result = subprocess.run(
                ["treeship", "verify", artifact_id, "--format", "json"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except FileNotFoundError:
            raise TreeshipError(
                "treeship CLI not found. Install: curl -fsSL treeship.dev/install | sh",
                ["verify", artifact_id],
            )

        # Empty stdout means the binary couldn't even attempt verification
        # (config missing, keystore broken, etc.) -- that's a real error.
        if not result.stdout.strip():
            raise TreeshipError(
                f"treeship verify produced no output (exit={result.returncode}): "
                f"{result.stderr.strip() or '<empty stderr>'}",
                ["verify", artifact_id],
            )

        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError:
            raise TreeshipError(
                f"treeship verify returned invalid JSON: {result.stdout[:200]}",
                ["verify", artifact_id],
            )

        # `chain` semantics match the TypeScript SDK contract:
        #   - on outcome=pass: number of artifacts that passed (== total)
        #   - on outcome=fail: number of artifacts that failed
        # The two SDKs MUST agree here -- the cross-SDK contract suite
        # asserts equality on every vector.
        outcome = parsed.get("outcome", "error")
        if outcome == "pass":
            chain = parsed.get("passed") or parsed.get("total") or 1
        elif outcome == "fail":
            chain = parsed.get("failed", 0)
        else:
            chain = parsed.get("total", 0)

        return VerifyResult(outcome=outcome, chain=chain, target=artifact_id)

    def hub_push(self, artifact_id: str) -> PushResult:
        """Push an artifact to Hub.

        Returns the public URL where the artifact can be fetched and
        verified. The CLI subcommand is `treeship hub push` -- prior
        versions of this SDK called the now-removed `treeship dock`
        subcommand, which silently failed against any v0.7+ binary.
        """
        result = _run(["hub", "push", artifact_id, "--format", "json"])
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

    def session_report(
        self,
        session_id: Optional[str] = None,
    ) -> SessionReportResult:
        """Upload a closed session's receipt to the configured hub.

        Reads the .treeship package generated by `treeship session close`
        and PUTs the receipt to the configured hub. Prints the permanent
        public URL where anyone can fetch the receipt without auth.

        If session_id is None, the most recently closed session is used.

        Usage:
            ts = Treeship()
            result = ts.session_report()
            print(result.receipt_url)
        """
        args = ["session", "report"]
        if session_id:
            args.append(session_id)

        try:
            result = subprocess.run(
                ["treeship"] + args,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except FileNotFoundError:
            raise TreeshipError(
                "treeship CLI not found. Install: curl -fsSL treeship.dev/install | sh",
                args,
            )

        if result.returncode != 0:
            err = result.stderr.strip() or result.stdout.strip()
            raise TreeshipError(
                f"treeship session report failed: {err}",
                args,
            )

        # session report prints a text summary, not JSON. Pull the
        # session_id, receipt URL, and counts out of the stdout block.
        stdout = result.stdout
        url_match = re.search(r"receipt:\s*(https?://\S+)", stdout)
        if not url_match:
            raise TreeshipError(
                f"could not parse receipt URL from session report output",
                args,
            )

        session_match = re.search(r"session:\s*(\S+)", stdout)
        agents_match = re.search(r"agents:\s*(\d+)", stdout)
        events_match = re.search(r"events:\s*(\d+)", stdout)

        return SessionReportResult(
            session_id=session_match.group(1) if session_match else (session_id or ""),
            receipt_url=url_match.group(1),
            agents=int(agents_match.group(1)) if agents_match else 0,
            events=int(events_match.group(1)) if events_match else 0,
        )

"""Treeship SDK client. Wraps the treeship CLI binary."""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

from treeship_sdk.bootstrap import (
    BootstrapResult,
    TreeshipBootstrapError,
    ensure_cli,
)


class TreeshipError(Exception):
    """Error from the treeship CLI."""

    def __init__(self, message: str, args: Sequence[str]):
        super().__init__(message)
        self.args_used = list(args)


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
                   receipt's agent_graph.nodes (0 if not reported by CLI)
    events      -- number of timeline events in the receipt (0 if not
                   reported by CLI)
    """

    session_id: str
    receipt_url: str
    agents: int = 0
    events: int = 0


# Single source of truth for option-injection rejection. Any user-facing
# argument that becomes a CLI value must clear this. The SDK never
# enables shell expansion (subprocess shell=False), so the only attack
# surface is option *parsing* -- a value like "--format" or "--config"
# that the CLI would interpret as a flag instead of a value.
_OPTION_LIKE = re.compile(r"^-{1,2}[A-Za-z0-9]")

# Length limits at the SDK boundary. Numbers chosen to fit comfortably
# inside the CLI's own caps and to keep receipts human-readable. Any
# breach raises in the SDK so the caller sees the failure at the call
# site, not as a confusing CLI parse error.
_MAX_ACTOR_LEN = 256        # actor URIs are short identifiers
_MAX_ACTION_LEN = 256       # action labels (e.g., mcp.tool.read.intent)
_MAX_DESCRIPTION_LEN = 4096 # human-readable approval description
_MAX_SUMMARY_LEN = 4096     # decision summary (LLM reasoning blurb)
_MAX_MODEL_LEN = 256        # model identifier
_MAX_NONCE_LEN = 256        # approval nonce
_MAX_ARTIFACT_ID_LEN = 256  # art_<hex>
_MAX_TOKEN_COUNT = 100_000_000  # 100M tokens — well past any single decision


def _check_length(name: str, value: str, limit: int) -> str:
    if len(value) > limit:
        raise TreeshipError(
            f"{name} is {len(value)} chars; max is {limit}. "
            f"Trim the value before passing it to the SDK.",
            [name],
        )
    return value


def _check_int_range(name: str, value: int, low: int, high: int) -> int:
    if value < low or value > high:
        raise TreeshipError(
            f"{name}={value} is outside the allowed range [{low}, {high}]",
            [name],
        )
    return value


def _check_float_range(name: str, value: float, low: float, high: float) -> float:
    # NaN check first — NaN compares False to everything, so a naive
    # range check would pass it through.
    if value != value:  # NaN
        raise TreeshipError(f"{name}={value} is NaN", [name])
    if value < low or value > high:
        raise TreeshipError(
            f"{name}={value} is outside the allowed range [{low}, {high}]",
            [name],
        )
    return value


def _reject_option_like(name: str, value: str) -> str:
    """Raise TreeshipError if `value` could be parsed as a CLI option.

    Treeship's argument parser is strict (clap), so a value beginning
    with `-` or `--` followed by a letter would silently be claimed as a
    flag. This guard catches that at the SDK boundary so the error
    appears at the SDK call site, not as a confusing CLI-side parse
    failure.
    """
    if not isinstance(value, str):
        return value
    if _OPTION_LIKE.match(value):
        raise TreeshipError(
            f"{name}={value!r} looks like a CLI option; refusing to pass it. "
            f"This guards against option-injection in user-facing values.",
            [value],
        )
    return value


class Treeship:
    """
    Treeship SDK client.

    Wraps the treeship CLI binary for signing, verification, and Hub operations.

    Construction modes::

        Treeship()
            Default — assumes ``treeship`` is on ``PATH``. Raises
            :class:`TreeshipError` if the binary isn't found at call time.

        Treeship(bot_mode=True)
            Agent-native — calls :func:`ensure_cli` at construction time
            to resolve the binary via ``$TREESHIP_BIN`` / ``PATH`` /
            cache / npm / GitHub Release in that order. AI agents on a
            fresh machine should use this so they don't have to ask a
            human "is the CLI installed?".

        Treeship(cli_path="/path/to/treeship", timeout=30, cwd=..., env={...})
            Fully explicit. ``cli_path`` overrides PATH lookup; ``timeout``
            becomes the default per-call timeout in seconds; ``cwd`` is
            the subprocess working directory; ``env`` is the full
            subprocess environment (or pass ``env={"FOO": "bar"}`` to
            extend the inherited environment).

    Usage::

        # default
        ts = Treeship()
        result = ts.attest_action(actor="agent://my-agent", action="tool.call")

        # agent-native bootstrap
        ts = Treeship(bot_mode=True)

        # explicit config
        ts = Treeship(cli_path="/opt/treeship/bin/treeship", timeout=30)
    """

    DEFAULT_TIMEOUT_S: int = 10
    WRAP_DEFAULT_TIMEOUT_S: int = 300
    SESSION_REPORT_DEFAULT_TIMEOUT_S: int = 60

    def __init__(
        self,
        *,
        bot_mode: bool = False,
        cli_path: Optional[Union[str, Path]] = None,
        timeout: Optional[int] = None,
        cwd: Optional[Union[str, Path]] = None,
        env: Optional[Mapping[str, str]] = None,
    ) -> None:
        # Resolve the binary in priority order:
        #   explicit cli_path > bot_mode bootstrap > PATH ("treeship")
        #
        # Prior versions resolved a path in bot_mode but never threaded
        # it through to subprocess calls -- bot_mode silently dropped
        # back to PATH. The fix: store the resolved path and require
        # every subprocess invocation to go through `_run_cli`.
        self._bootstrap: Optional[BootstrapResult] = None

        if cli_path is not None:
            self._binary: str = str(cli_path)
        elif bot_mode:
            try:
                self._bootstrap = ensure_cli()
                self._binary = self._bootstrap.binary
            except TreeshipBootstrapError as exc:
                raise TreeshipError(
                    f"agent-native bootstrap failed: {exc} (reason={exc.reason})",
                    [],
                ) from exc
        else:
            self._binary = "treeship"

        self._timeout: int = timeout if timeout is not None else self.DEFAULT_TIMEOUT_S
        self._cwd: Optional[str] = str(cwd) if cwd is not None else None
        self._env: Optional[Dict[str, str]] = dict(env) if env is not None else None

    @classmethod
    def ensure_cli(cls) -> BootstrapResult:
        """Resolve a working CLI binary without instantiating the SDK."""
        return ensure_cli()

    @property
    def binary(self) -> str:
        """Path to the resolved CLI binary."""
        return self._binary

    @property
    def bootstrap(self) -> Optional[BootstrapResult]:
        """The resolution result when bot_mode=True; ``None`` otherwise."""
        return self._bootstrap

    # ---- subprocess helpers --------------------------------------------------

    def _run_cli_raw(
        self,
        args: Sequence[str],
        *,
        timeout: Optional[int] = None,
    ) -> "subprocess.CompletedProcess[str]":
        """Invoke the CLI without parsing output. Returns the
        CompletedProcess so callers can inspect returncode + stdout +
        stderr independently.

        Raises :class:`TreeshipError` only when the binary is missing
        (FileNotFoundError) or the call times out -- structured CLI
        errors (non-zero exit with content) are returned as-is for the
        caller to interpret.
        """
        env: Optional[Dict[str, str]] = None
        if self._env is not None:
            env = {**os.environ, **self._env} if self._env_is_extension() else dict(self._env)

        try:
            return subprocess.run(
                [self._binary, *args],
                capture_output=True,
                text=True,
                timeout=timeout if timeout is not None else self._timeout,
                cwd=self._cwd,
                env=env,
            )
        except FileNotFoundError as exc:
            raise TreeshipError(
                f"treeship CLI not found at {self._binary!r}. "
                f"Install: curl -fsSL treeship.dev/install | sh\n"
                f"  Or in a Python program: ts = Treeship(bot_mode=True)  # auto-resolves the CLI\n"
                f"  Or pass cli_path explicitly: Treeship(cli_path=...)",
                args,
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise TreeshipError(
                f"treeship {' '.join(args[:2])} timed out after {exc.timeout}s",
                args,
            ) from exc

    def _env_is_extension(self) -> bool:
        # Heuristic: callers passing a tiny env dict almost always mean
        # "extend the inherited env." Callers passing a full env (PATH +
        # HOME + ...) mean "replace." 5 keys is the cutoff -- a real
        # full env has dozens.
        return self._env is not None and len(self._env) <= 5

    def _run_cli_json(
        self,
        args: Sequence[str],
        *,
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Run the CLI and parse stdout as JSON. Raises on non-zero exit
        or unparseable output."""
        result = self._run_cli_raw(args, timeout=timeout)
        if result.returncode != 0:
            raise TreeshipError(
                f"treeship {' '.join(args[:2])} failed (exit={result.returncode}): "
                f"{result.stderr.strip() or result.stdout.strip() or '<no output>'}",
                args,
            )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise TreeshipError(
                f"treeship {' '.join(args[:2])} returned invalid JSON: "
                f"{result.stdout[:200]}",
                args,
            ) from exc

    @staticmethod
    def _artifact_id(payload: Mapping[str, Any], args: Sequence[str]) -> str:
        """Pull `id` or `artifact_id` out of a CLI JSON payload.

        Raises :class:`TreeshipError` when both are missing or empty —
        prior versions silently returned ``""``, which masked CLI
        regressions and produced confusing downstream NoneType-style
        errors when a caller fed the empty id back into ``parent_id``.
        """
        raw = payload.get("id") or payload.get("artifact_id")
        if not raw or not isinstance(raw, str):
            raise TreeshipError(
                f"treeship returned no artifact id (keys: {sorted(payload.keys())}); "
                f"the CLI may have changed shape — file an issue with the args.",
                args,
            )
        return raw

    # ---- attestations --------------------------------------------------------

    def attest_action(
        self,
        actor: str,
        action: str,
        parent_id: Optional[str] = None,
        approval_nonce: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> ActionResult:
        """Create a signed action receipt."""
        _reject_option_like("actor", actor)
        _check_length("actor", actor, _MAX_ACTOR_LEN)
        _reject_option_like("action", action)
        _check_length("action", action, _MAX_ACTION_LEN)
        if parent_id is not None:
            _reject_option_like("parent_id", parent_id)
            _check_length("parent_id", parent_id, _MAX_ARTIFACT_ID_LEN)
        if approval_nonce is not None:
            _reject_option_like("approval_nonce", approval_nonce)
            _check_length("approval_nonce", approval_nonce, _MAX_NONCE_LEN)

        args: List[str] = [
            "attest", "action",
            "--actor", actor,
            "--action", action,
            "--format", "json",
        ]
        if parent_id is not None:
            args += ["--parent", parent_id]
        if approval_nonce is not None:
            args += ["--approval-nonce", approval_nonce]
        if meta is not None:
            args += ["--meta", json.dumps(meta)]
        result = self._run_cli_json(args)
        return ActionResult(artifact_id=self._artifact_id(result, args))

    def attest_approval(
        self,
        approver: str,
        description: str,
        expires_in: Optional[str] = None,
    ) -> ApprovalResult:
        """Create a signed approval receipt with a binding nonce."""
        _reject_option_like("approver", approver)
        _check_length("approver", approver, _MAX_ACTOR_LEN)
        _check_length("description", description, _MAX_DESCRIPTION_LEN)
        if expires_in is not None:
            _reject_option_like("expires_in", expires_in)

        args: List[str] = [
            "attest", "approval",
            "--approver", approver,
            "--description", description,
            "--format", "json",
        ]
        if expires_in is not None:
            args += ["--expires", expires_in]
        result = self._run_cli_json(args)
        return ApprovalResult(
            artifact_id=self._artifact_id(result, args),
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
        _reject_option_like("from_actor", from_actor)
        _check_length("from_actor", from_actor, _MAX_ACTOR_LEN)
        _reject_option_like("to_actor", to_actor)
        _check_length("to_actor", to_actor, _MAX_ACTOR_LEN)
        for a in artifacts:
            _reject_option_like("artifact_id", a)
            _check_length("artifact_id", a, _MAX_ARTIFACT_ID_LEN)
        for a in approvals or []:
            _reject_option_like("approval_id", a)
            _check_length("approval_id", a, _MAX_ARTIFACT_ID_LEN)

        args: List[str] = [
            "attest", "handoff",
            "--from", from_actor,
            "--to", to_actor,
            "--artifacts", ",".join(artifacts),
            "--format", "json",
        ]
        if approvals:
            args += ["--approvals", ",".join(approvals)]
        result = self._run_cli_json(args)
        return ActionResult(artifact_id=self._artifact_id(result, args))

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
        _reject_option_like("actor", actor)
        _check_length("actor", actor, _MAX_ACTOR_LEN)
        if model is not None:
            _reject_option_like("model", model)
            _check_length("model", model, _MAX_MODEL_LEN)
        if parent_id is not None:
            _reject_option_like("parent_id", parent_id)
            _check_length("parent_id", parent_id, _MAX_ARTIFACT_ID_LEN)
        if tokens_in is not None:
            _check_int_range("tokens_in", tokens_in, 0, _MAX_TOKEN_COUNT)
        if tokens_out is not None:
            _check_int_range("tokens_out", tokens_out, 0, _MAX_TOKEN_COUNT)
        if summary is not None:
            _check_length("summary", summary, _MAX_SUMMARY_LEN)
        if confidence is not None:
            _check_float_range("confidence", confidence, 0.0, 1.0)

        args: List[str] = ["attest", "decision", "--actor", actor, "--format", "json"]
        if model is not None:
            args += ["--model", model]
        if tokens_in is not None:
            args += ["--tokens-in", str(tokens_in)]
        if tokens_out is not None:
            args += ["--tokens-out", str(tokens_out)]
        if summary is not None:
            args += ["--summary", summary]
        if confidence is not None:
            args += ["--confidence", str(confidence)]
        if parent_id is not None:
            args += ["--parent", parent_id]
        result = self._run_cli_json(args)
        return ActionResult(artifact_id=self._artifact_id(result, args))

    # ---- verification --------------------------------------------------------

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
        _reject_option_like("artifact_id", artifact_id)
        _check_length("artifact_id", artifact_id, _MAX_ARTIFACT_ID_LEN)

        args: List[str] = ["verify", artifact_id, "--format", "json"]
        result = self._run_cli_raw(args)

        # Empty stdout means the binary couldn't even attempt verification
        # (config missing, keystore broken, etc.) -- that's a real error.
        if not result.stdout.strip():
            raise TreeshipError(
                f"treeship verify produced no output (exit={result.returncode}): "
                f"{result.stderr.strip() or '<empty stderr>'}",
                args,
            )

        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise TreeshipError(
                f"treeship verify returned invalid JSON (exit={result.returncode}): "
                f"{result.stdout[:200]}",
                args,
            ) from exc

        # `chain` semantics match the TypeScript SDK contract:
        #   - on outcome=pass: number of artifacts that passed (== total)
        #   - on outcome=fail: number of artifacts that failed
        outcome = parsed.get("outcome", "error")
        if outcome == "pass":
            chain = parsed.get("passed") or parsed.get("total") or 1
        elif outcome == "fail":
            chain = parsed.get("failed", 0)
        else:
            chain = parsed.get("total", 0)

        return VerifyResult(outcome=outcome, chain=chain, target=artifact_id)

    # ---- hub -----------------------------------------------------------------

    def hub_push(self, artifact_id: str) -> PushResult:
        """Push an artifact to Hub."""
        _reject_option_like("artifact_id", artifact_id)
        _check_length("artifact_id", artifact_id, _MAX_ARTIFACT_ID_LEN)

        args: List[str] = ["hub", "push", artifact_id, "--format", "json"]
        result = self._run_cli_json(args)
        return PushResult(
            hub_url=result.get("hub_url", result.get("url", "")),
            rekor_index=result.get("rekor_index"),
        )

    # ---- wrap ----------------------------------------------------------------

    def wrap(
        self,
        command: Union[str, Sequence[str]],
        actor: Optional[str] = None,
        *,
        timeout: Optional[int] = None,
    ) -> ActionResult:
        """Wrap a shell command with a signed receipt.

        ``command`` accepts either:

        * **Sequence[str]** (preferred): exact argv. Quoted arguments
          and embedded spaces are preserved without ambiguity.
          Example: ``ts.wrap(["python", "-c", "print('hi mom')"])``
        * **str** (legacy): split with :func:`shlex.split` so quoted
          arguments survive. Earlier versions of this SDK used naive
          ``str.split()``, which silently broke commands like
          ``python -c 'print(1)'``.

        ``timeout`` overrides the SDK's default wrap timeout (5 minutes)
        for this single call.
        """
        if actor is not None:
            _reject_option_like("actor", actor)

        if isinstance(command, str):
            argv = shlex.split(command)
        else:
            argv = list(command)

        if not argv:
            raise TreeshipError(
                "wrap() requires a non-empty command",
                ["wrap"],
            )

        args: List[str] = ["wrap"]
        if actor is not None:
            args += ["--actor", actor]
        args += ["--format", "json", "--", *argv]
        result = self._run_cli_json(
            args,
            timeout=timeout if timeout is not None else self.WRAP_DEFAULT_TIMEOUT_S,
        )
        return ActionResult(artifact_id=self._artifact_id(result, args))

    # ---- sessions ------------------------------------------------------------

    def session_report(
        self,
        session_id: Optional[str] = None,
        *,
        timeout: Optional[int] = None,
    ) -> SessionReportResult:
        """Upload a closed session's receipt to the configured hub.

        Reads the .treeship package generated by ``treeship session
        close`` and PUTs the receipt to the configured hub. Returns the
        permanent public URL where anyone can fetch the receipt without
        auth.

        If ``session_id`` is None, the most recently closed session is used.

        Uses ``--format json`` (CLI schema ``treeship/share-result/v1``)
        so URL/session_id/digests come from a stable JSON contract,
        not regex-parsed text. The text-output regex path was a
        repeated source of release-time breakage when the text format
        was tweaked.
        """
        if session_id is not None:
            _reject_option_like("session_id", session_id)

        args: List[str] = ["session", "report", "--format", "json"]
        if session_id is not None:
            args.append(session_id)

        try:
            parsed = self._run_cli_json(
                args,
                timeout=timeout if timeout is not None else self.SESSION_REPORT_DEFAULT_TIMEOUT_S,
            )
        except TreeshipError:
            # Older CLIs (pre-0.10.x) may not emit JSON for session
            # report. Fall back to the text-parse path so existing
            # users don't break on SDK upgrade.
            return self._session_report_text_fallback(session_id, args[:2], timeout)

        receipt_url = parsed.get("receipt_url") or ""
        sid = parsed.get("session_id") or session_id or ""
        if not receipt_url:
            raise TreeshipError(
                f"session report JSON missing receipt_url "
                f"(keys: {sorted(parsed.keys())}); error={parsed.get('error')!r}",
                args,
            )

        # agents/events counts aren't in the share-result/v1 JSON schema
        # today. Default to 0; a future schema bump can populate them.
        return SessionReportResult(
            session_id=sid,
            receipt_url=receipt_url,
            agents=int(parsed.get("agents", 0) or 0),
            events=int(parsed.get("events", 0) or 0),
        )

    def _session_report_text_fallback(
        self,
        session_id: Optional[str],
        args_for_error: Sequence[str],
        timeout: Optional[int],
    ) -> SessionReportResult:
        # Pre-JSON path: parse the text output. Kept for compatibility
        # with CLIs older than v0.10.x.
        text_args: List[str] = ["session", "report"]
        if session_id is not None:
            text_args.append(session_id)
        result = self._run_cli_raw(
            text_args,
            timeout=timeout if timeout is not None else self.SESSION_REPORT_DEFAULT_TIMEOUT_S,
        )
        if result.returncode != 0:
            raise TreeshipError(
                f"treeship session report failed (exit={result.returncode}): "
                f"{result.stderr.strip() or result.stdout.strip()}",
                args_for_error,
            )

        stdout = result.stdout
        url_match = re.search(r"receipt:\s*(https?://\S+)", stdout)
        if not url_match:
            raise TreeshipError(
                "could not parse receipt URL from session report output "
                "(neither --format json nor text-format matched)",
                args_for_error,
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

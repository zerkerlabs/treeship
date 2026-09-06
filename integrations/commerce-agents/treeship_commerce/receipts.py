"""Signed receipts for every commerce-agents tool call.

Where this plugs in
-------------------
``commerce_common.execution.BaseToolExecutor.execute`` is the one method every
tool call passes through on all three runtimes; the reference's own gates rely
on that. :class:`TreeshipExecutorMixin` overrides it: a signed **intent**
receipt before dispatch, the tool, then a signed **result** receipt. Each
receipt names its parent, so the session's chain reads intent → result →
intent → result … from the session-start root, and ``treeship verify`` walks
it as one chain.

What a receipt carries, and what it never carries
-------------------------------------------------
The reference fences third-party content and logs only a *digest* of the
session id, because the id is also the request credential. A receipt keeps
that discipline: the tool name, a SHA-256 of the canonical arguments, a
SHA-256 of the result text, the outcome (``ok`` / ``blocked`` with the gate's
name / ``error``), event types, timing, and the same twelve-hex session tag
the reference's own log lines use. Never the arguments, never the result text,
never the session id.

Recording never breaks the agent path
-------------------------------------
This module records; it does not gate. A tool runs whether or not its receipt
could be written, and a failure to record warns once and moves on -- the same
rule the reference applies to its own attestation-shaped concerns and the rule
``@treeship/mcp`` follows. The one thing it will not do is invent: a missing
intent is recorded as ``intent_recorded: false`` on the result, never as a
fabricated id. ``TREESHIP_DISABLE=1`` turns recording off entirely.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from typing import Any, Callable, Mapping, Sequence

from treeship_sdk import Treeship

try:  # The reference's own helper, so tags line up with its log lines.
    from commerce_common.turn import session_tag as _session_tag
except ImportError:  # pragma: no cover - only when commerce-agents is absent

    def _session_tag(session_id: str | None) -> str:
        return hashlib.sha256(session_id.encode()).hexdigest()[:12] if session_id else "-"


logger = logging.getLogger("treeship_commerce")

INTENT_ACTION = "commerce.tool.{name}.intent"
RESULT_ACTION = "commerce.tool.{name}.result"

# Exit codes the timeline event carries. Blocked is distinct from error on
# purpose: a held call is the gate working, not the tool failing.
_EXIT_CODES = {"ok": 0, "error": 1, "blocked": 2}


def _canonical(tool_input: Mapping[str, Any] | None) -> bytes:
    return json.dumps(
        dict(tool_input or {}), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def args_digest(tool_input: Mapping[str, Any] | None) -> str:
    """``sha256:<hex>`` over the canonical JSON of the tool's arguments.

    Canonical means sorted keys, no whitespace, UTF-8: the same arguments
    always produce the same digest, so a holder of the arguments can check
    the receipt, and a holder of the receipt learns nothing about them.
    """
    return "sha256:" + hashlib.sha256(_canonical(tool_input)).hexdigest()


def text_digest(text: str) -> str:
    """``sha256:<hex>`` of a result text. The text itself is fenced third-party
    content on the reference and stays out of the receipt."""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def outcome_status(outcome: Any) -> str:
    """``blocked`` when a gate held the call, else ``error`` or ``ok``."""
    if getattr(outcome, "blocked", None):
        return "blocked"
    if getattr(outcome, "is_error", False):
        return "error"
    return "ok"


class TreeshipReceipts:
    """The recorder one executor instance carries.

    ``client`` is a configured :class:`treeship_sdk.Treeship`. ``actor`` is the
    URI the receipts name (``agent://shopping`` or ``agent://merchant`` by
    convention). ``session_id`` is the *commerce* session id; only its tag is
    ever written. ``parent_id`` seeds the chain -- pass the Treeship session's
    ``root_artifact_id`` so the tool receipts count into that session.
    """

    def __init__(
        self,
        client: Treeship,
        *,
        actor: str,
        session_id: str | None = None,
        role: str = "shopping",
        parent_id: str | None = None,
        timeline: bool = True,
    ) -> None:
        self.client = client
        self.actor = actor
        self.role = role
        self.session_tag = _session_tag(session_id)
        self.timeline = timeline
        self._head: str | None = parent_id
        self._lock = asyncio.Lock()
        self._warned = False
        self._timeline_unavailable_warned = False
        self.recorded: list[str] = []
        """Artifact ids written by this recorder, in chain order."""
        self.dropped = 0
        """Receipts that could not be written. Non-zero means the chain has
        gaps that ``intent_recorded: false`` on later results points at."""

    @property
    def disabled(self) -> bool:
        return os.environ.get("TREESHIP_DISABLE") == "1"

    @property
    def head(self) -> str | None:
        """The most recent artifact in the chain, or the seed parent."""
        return self._head

    def _warn(self, context: str, err: BaseException) -> None:
        self.dropped += 1
        if not self._warned:
            self._warned = True
            logger.warning(
                "treeship receipt not written (%s): %s. Tool calls continue; later "
                "results record intent_recorded=false where the intent is missing. "
                "Set TREESHIP_DISABLE=1 to silence recording entirely.",
                context,
                err,
            )
        elif os.environ.get("TREESHIP_DEBUG") == "1":
            logger.warning("treeship receipt not written (%s): %s", context, err)

    async def _attest(self, action: str, meta: dict[str, Any], parent: str | None) -> str | None:
        if self.disabled:
            return None
        try:
            result = await asyncio.to_thread(
                self.client.attest_action, self.actor, action, parent, None, meta
            )
        except Exception as err:  # noqa: BLE001 -- a recorder must never break the tool
            self._warn(action, err)
            return None
        async with self._lock:
            self._head = result.artifact_id
            self.recorded.append(result.artifact_id)
        return result.artifact_id

    async def intent(self, name: str, tool_input: Mapping[str, Any] | None) -> str | None:
        """Sign that ``name`` is about to run with these (digested) arguments."""
        async with self._lock:
            parent = self._head
        return await self._attest(
            INTENT_ACTION.format(name=name),
            {
                "tool": name,
                "role": self.role,
                "args_digest": args_digest(tool_input),
                "session_tag": self.session_tag,
            },
            parent,
        )

    async def result(
        self,
        name: str,
        outcome: Any,
        *,
        intent_id: str | None,
        elapsed_ms: int,
    ) -> str | None:
        """Sign what ``name`` produced: status, gate, digests, events, timing."""
        status = outcome_status(outcome)
        meta: dict[str, Any] = {
            "tool": name,
            "role": self.role,
            "status": status,
            "result_digest": text_digest(getattr(outcome, "result_text", "") or ""),
            "events": [getattr(e, "type", str(e)) for e in getattr(outcome, "events", ())],
            "elapsed_ms": int(elapsed_ms),
            "session_tag": self.session_tag,
            # False is a statement, not a default: this result's parent is then
            # the previous chain head, and a reader can see the intent is missing.
            "intent_recorded": intent_id is not None,
        }
        if status == "blocked":
            meta["gate"] = outcome.blocked
        async with self._lock:
            parent = self._head
        artifact_id = await self._attest(RESULT_ACTION.format(name=name), meta, parent)
        if self.timeline:
            await self._event(name, status, elapsed_ms)
        return artifact_id

    async def _event(self, name: str, status: str, elapsed_ms: int) -> None:
        """Append the call to the Treeship session timeline (unsigned; it is what
        the receipt page renders). The signed receipts are the evidence."""
        if self.disabled:
            return
        session_event = getattr(self.client, "session_event", None)
        if session_event is None:
            # treeship-sdk < 0.28 has no session_event. The signed receipts are
            # the evidence; the timeline is a rendering convenience. Say so
            # once rather than raise into the tool call.
            if not self._timeline_unavailable_warned:
                self._timeline_unavailable_warned = True
                logger.warning(
                    "treeship-sdk %s has no session_event(); timeline events are skipped "
                    "(signed receipts are still written). Upgrade treeship-sdk to restore them.",
                    getattr(self.client, "__module__", "?"),
                )
            return
        try:
            await asyncio.to_thread(
                session_event,
                "agent.called_tool",
                tool=name,
                actor=self.actor,
                exit_code=_EXIT_CODES[status],
                duration_ms=int(elapsed_ms),
            )
        except Exception as err:  # noqa: BLE001 -- a recorder must never break the tool
            self._warn(f"session event {name}", err)


class TreeshipExecutorMixin:
    """Put this first in the bases of a commerce-agents executor class::

        class ReceiptedShoppingToolExecutor(TreeshipExecutorMixin, ShoppingToolExecutor):
            pass

    or let :func:`receipted` build that class. Give the instance its recorder
    with :func:`attach`, or give the class a ``recorder`` factory through
    :func:`receipted` so every runtime that constructs executors itself (all
    three of the reference's do, through ``executor_class``) gets one per
    executor on first use. Without either, the executor behaves exactly as
    the reference does.
    """

    treeship_receipts: TreeshipReceipts | None = None
    treeship_recorder_factory: Callable[[Any], TreeshipReceipts] | None = None

    def _treeship_recorder(self) -> TreeshipReceipts | None:
        if self.treeship_receipts is None and self.treeship_recorder_factory is not None:
            # One recorder per executor. The reference builds one executor per
            # session (Messages API), per toolset (Agent SDK), or per MCP
            # connection (Managed Agents), so this is one chain per session.
            self.treeship_receipts = self.treeship_recorder_factory(self)
        return self.treeship_receipts

    async def execute(self, name: str, tool_input: dict[str, Any] | None) -> Any:
        receipts = self._treeship_recorder()
        if receipts is None:
            return await super().execute(name, tool_input)  # type: ignore[misc]
        intent_id = await receipts.intent(name, tool_input)
        started = time.monotonic()
        outcome = await super().execute(name, tool_input)  # type: ignore[misc]
        elapsed_ms = int((time.monotonic() - started) * 1000)
        await receipts.result(name, outcome, intent_id=intent_id, elapsed_ms=elapsed_ms)
        return outcome


def receipted(
    executor_cls: type,
    *,
    recorder: Callable[[Any], TreeshipReceipts] | None = None,
) -> type:
    """``ShoppingToolExecutor`` in, ``ReceiptedShoppingToolExecutor`` out.

    All three of the reference's runtimes take an ``executor_class``
    (``ShoppingAgent(executor_class=)``, ``ShoppingToolset(executor_class=)``,
    ``build_server(executor_class=)``) and construct executors themselves, so
    there is no instance to :func:`attach` to. Pass ``recorder``, a callable
    from the executor to its :class:`TreeshipReceipts`, and each executor gets
    one on its first tool call. The executor's ``_session`` carries the
    commerce session id the recorder should tag::

        receipted(ShoppingToolExecutor, recorder=lambda ex: TreeshipReceipts(
            ts, actor="agent://shopping", session_id=ex._session.session_id, parent_id=root))
    """
    if issubclass(executor_cls, TreeshipExecutorMixin) and recorder is None:
        return executor_cls
    body: dict[str, Any] = {}
    if recorder is not None:
        body["treeship_recorder_factory"] = staticmethod(recorder)
    bases = (
        (executor_cls,)
        if issubclass(executor_cls, TreeshipExecutorMixin)
        else (
            TreeshipExecutorMixin,
            executor_cls,
        )
    )
    return type(f"Receipted{executor_cls.__name__.removeprefix('Receipted')}", bases, body)


def attach(executor: Any, receipts: TreeshipReceipts) -> Any:
    """Give an executor instance its recorder. The executor's class must carry
    :class:`TreeshipExecutorMixin`; attaching to a plain reference executor
    would record nothing and say nothing, which is the failure this refuses."""
    if not isinstance(executor, TreeshipExecutorMixin):
        raise TypeError(
            f"{type(executor).__name__} does not carry TreeshipExecutorMixin; build it from "
            f"receipted({type(executor).__name__}) so execute() actually records."
        )
    executor.treeship_receipts = receipts
    return executor


def event_types(outcome: Any) -> Sequence[str]:
    """The event types a tool outcome emitted, as recorded on its receipt."""
    return [getattr(e, "type", str(e)) for e in getattr(outcome, "events", ())]

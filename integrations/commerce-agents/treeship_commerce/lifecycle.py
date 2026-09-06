"""Treeship session lifecycle around a commerce session.

The per-call receipts live in ``receipts.py``. These helpers open and seal the
Treeship session that contains them, so a host can do::

    ts = Treeship(env=env)
    root = start_session(ts, name="storefront:retail", actor="agent://shopping")
    receipts = TreeshipReceipts(ts, actor="agent://shopping", session_id=sid, parent_id=root)
    ...
    package = close_session(ts, summary="12 tool calls, 1 held by the provenance gate")

They shell out to the CLI the same way the SDK does and parse the last JSON
document on stdout, because ``attest`` may print a warning object first.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Mapping, Sequence

from treeship_sdk import Treeship, TreeshipError


def _run_json(
    client: Treeship,
    args: Sequence[str],
    *,
    env: Mapping[str, str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Run one CLI command. ``cwd`` matters: ``session start`` and ``session
    event`` find the workspace by walking up from the working directory, so a
    host that runs elsewhere would start a session in the wrong tree."""
    merged = {**os.environ, **(env or {})}
    proc = subprocess.run(
        [client.binary, *args, "--format", "json"],
        capture_output=True,
        text=True,
        env=merged,
        cwd=cwd,
        timeout=60,
    )
    if proc.returncode != 0:
        raise TreeshipError(
            f"treeship {' '.join(args[:2])} failed (exit={proc.returncode}): "
            f"{proc.stderr.strip() or proc.stdout.strip() or '<no output>'}",
            list(args),
        )
    docs = [
        json.loads(chunk)
        for chunk in proc.stdout.replace("}\n{", "}\n\x00{").split("\x00")
        if chunk.strip()
    ]
    if not docs:
        raise TreeshipError(f"treeship {' '.join(args[:2])} printed no JSON", list(args))
    return docs[-1]


def start_session(
    client: Treeship,
    *,
    name: str,
    actor: str,
    env: Mapping[str, str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> str:
    """Start a Treeship session in the workspace at ``cwd`` (the working
    directory by default) and return its ``root_artifact_id`` -- the parent
    every tool receipt chains from."""
    _run_json(client, ["session", "start", "--name", name, "--actor", actor], env=env, cwd=cwd)
    status = _run_json(client, ["session", "status"], env=env, cwd=cwd)
    root = status.get("root_artifact_id")
    if not isinstance(root, str) or not root:
        raise TreeshipError("session start left no root_artifact_id", ["session", "status"])
    return root


def session_status(
    client: Treeship,
    *,
    env: Mapping[str, str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    return _run_json(client, ["session", "status"], env=env, cwd=cwd)


def close_session(
    client: Treeship,
    *,
    summary: str,
    headline: str | None = None,
    env: Mapping[str, str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Seal the session into a ``.treeship`` package. Returns the CLI's document
    (``session_id``, ``receipts``, ``events``, ``package``)."""
    args = ["session", "close", "--summary", summary]
    if headline:
        args += ["--headline", headline]
    return _run_json(client, args, env=env, cwd=cwd)

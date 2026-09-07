# Fixtures: an isolated Treeship ship with an open session, and a real
# commerce-agents shopping executor over the retail mock backend, wrapped
# with receipts. No model, no API key: the executor is driven directly, the
# way the reference's own executor tests drive it.

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
from treeship_sdk import Treeship

from treeship_commerce import TreeshipReceipts, attach, receipted
from treeship_commerce.lifecycle import start_session


def _binary() -> str | None:
    explicit = os.environ.get("TREESHIP_BIN")
    if explicit and Path(explicit).exists():
        return explicit
    return shutil.which("treeship")


BIN = _binary()
needs_cli = pytest.mark.skipif(BIN is None, reason="treeship CLI not found (set TREESHIP_BIN)")


@dataclass
class Ship:
    client: Treeship
    env: dict[str, str]
    root: Path
    config: Path
    session_root: str

    @property
    def artifacts_dir(self) -> Path:
        return self.root / ".treeship" / "artifacts"

    def artifacts(self) -> dict[str, dict]:
        """Every stored artifact, keyed by id, with its DSSE payload decoded."""
        out: dict[str, dict] = {}
        for path in self.artifacts_dir.glob("art_*.json"):
            record = json.loads(path.read_text())
            payload = record["envelope"]["payload"]
            padded = payload + "=" * (-len(payload) % 4)
            statement = json.loads(base64.urlsafe_b64decode(padded))
            out[record["artifact_id"]] = {
                "record": record,
                "statement": statement,
                "raw": path.read_text(),
            }
        return out

    def chain(self, head: str) -> list[dict]:
        """Walk parent links from ``head`` back to the root, root first."""
        arts = self.artifacts()
        walked: list[dict] = []
        cursor: str | None = head
        while cursor is not None:
            entry = arts[cursor]
            walked.append(entry)
            cursor = entry["statement"].get("parentId")
        walked.reverse()
        return walked

    def cli_json(self, *args: str) -> dict:
        proc = subprocess.run(
            [BIN, *args, "--format", "json"],
            capture_output=True,
            text=True,
            env={**os.environ, **self.env},
            cwd=self.root,
            check=False,
        )
        docs = [
            json.loads(chunk)
            for chunk in proc.stdout.replace("}\n{", "}\n\x00{").split("\x00")
            if chunk.strip()
        ]
        assert docs, f"no JSON from treeship {args}: {proc.stderr}"
        return docs[-1]


@pytest.fixture
def ship(tmp_path: Path) -> Ship:
    if BIN is None:
        pytest.skip("treeship CLI not found (set TREESHIP_BIN)")
    root = tmp_path / "ship"
    root.mkdir()
    config = root / ".treeship" / "config.json"
    env = {
        "HOME": str(root),
        "TREESHIP_CONFIG": str(config),
        "TREESHIP_ALLOW_INSECURE_KEY_PERMS": "1",
    }
    subprocess.run(
        [BIN, "init", "--name", "commerce-test", "--config", str(config)],
        check=True,
        capture_output=True,
        env={**os.environ, **env},
        cwd=root,
    )
    client = Treeship(cli_path=BIN, env=env, cwd=root)
    session_root = start_session(
        client, name="commerce:test", actor="agent://shopping", env=env, cwd=root
    )
    return Ship(client=client, env=env, root=root, config=config, session_root=session_root)


COMMERCE_SESSION_ID = "s-secret-session-9f2a"


@pytest.fixture
def executor(ship: Ship):
    """A receipted ``ShoppingToolExecutor`` over the retail mock backend."""
    from commerce_common.memory import InMemoryMemoryStore
    from commerce_common.skills import SkillRegistry
    from shopping_agent import ShoppingAgentConfig, ShoppingSessionContext, ShoppingSessionState
    from shopping_agent.executor import ShoppingToolExecutor, build_memory
    from shopping_agent_sdk import load_mock_backend

    config = ShoppingAgentConfig(brand_name="ACME")
    cls = receipted(ShoppingToolExecutor)
    ex = cls(
        backend=load_mock_backend(),
        config=config,
        skills=SkillRegistry([]),
        session=ShoppingSessionContext(session_id=COMMERCE_SESSION_ID, user_id="u-1"),
        state=ShoppingSessionState(),
        memory=build_memory(config, InMemoryMemoryStore()),
        inline_context=True,
    )
    receipts = TreeshipReceipts(
        ship.client,
        actor="agent://shopping",
        session_id=COMMERCE_SESSION_ID,
        parent_id=ship.session_root,
    )
    return attach(ex, receipts)


MERCHANT_SESSION_ID = "m-secret-session-3d81"


def _merchant_executor(ship: Ship, *, enforce: bool):
    """A receipted merchant executor over the ACME mock, with a signed
    approval surface bound to its apply tool."""
    from commerce_common.memory import InMemoryMemoryStore
    from commerce_common.skills import SkillRegistry
    from merchant_agent import MerchantAgentConfig, MerchantSessionContext, MerchantSessionState
    from merchant_agent.executor import MerchantToolExecutor, build_memory
    from merchant_agent_sdk import load_mock_backend

    from treeship_commerce import MerchantApprovals, approved

    config = MerchantAgentConfig()
    approvals = MerchantApprovals(
        ship.client, approver="human://operator", actor="agent://merchant"
    )
    cls = approved(receipted(MerchantToolExecutor), approvals, enforce=enforce)
    ex = cls(
        backend=load_mock_backend(),
        config=config,
        skills=SkillRegistry([]),
        session=MerchantSessionContext(
            session_id=MERCHANT_SESSION_ID, merchant_id="m-1", operator="human://operator"
        ),
        state=MerchantSessionState(),
        memory=build_memory(config, InMemoryMemoryStore()),
    )
    attach(
        ex,
        TreeshipReceipts(
            ship.client,
            actor="agent://merchant",
            session_id=MERCHANT_SESSION_ID,
            role="merchant",
            parent_id=ship.session_root,
        ),
    )
    return ex, approvals


@pytest.fixture
def merchant(ship: Ship):
    return _merchant_executor(ship, enforce=False)


@pytest.fixture
def merchant_enforcing(ship: Ship):
    return _merchant_executor(ship, enforce=True)

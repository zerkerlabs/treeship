# The docs say one wrapper covers all three of the reference's runtimes
# through `executor_class`. Each test here drives a runtime the way the
# reference's own tests drive it and checks that receipts were written, so
# that claim is tested, not inferred from reading the source.

from __future__ import annotations

import sys

from treeship_commerce import TreeshipReceipts, receipted

from .conftest import Ship, needs_cli

pytestmark = needs_cli


def _factory(ship: Ship, made: list[TreeshipReceipts]):
    def make(executor) -> TreeshipReceipts:
        r = TreeshipReceipts(
            ship.client,
            actor="agent://shopping",
            session_id=executor._session.session_id,
            parent_id=ship.session_root,
        )
        made.append(r)
        return r

    return make


def _receipted_shopping(ship: Ship, made: list[TreeshipReceipts]):
    from shopping_agent.executor import ShoppingToolExecutor

    return receipted(ShoppingToolExecutor, recorder=_factory(ship, made))


async def test_messages_api_runtime_records_through_executor_class(ship: Ship):
    from commerce_common.skills import SkillRegistry
    from commerce_common.testing import FakeClient, text_message, tool_use_message
    from shopping_agent import ShoppingSessionContext, ShoppingSessionState
    from shopping_agent_runtime import ShoppingAgent
    from shopping_agent_sdk import load_mock_backend

    made: list[TreeshipReceipts] = []
    # A scripted model: one tool call, then a text answer. No API key.
    client = FakeClient(
        [tool_use_message("search_products", {"query": "tent"}), text_message("Here.")]
    )
    agent = ShoppingAgent(
        backend=load_mock_backend(),
        skills=SkillRegistry([]),
        client=client,
        executor_class=_receipted_shopping(ship, made),
    )
    session = ShoppingSessionContext(session_id="messages-api-session", user_id="u-1")
    state = ShoppingSessionState()
    events = [
        e async for e in agent.stream_turn([{"role": "user", "content": "a tent"}], session, state)
    ]
    assert any(e.type == "tool_call" for e in events), [e.type for e in events]
    assert len(made) == 1, "one executor per turn, one recorder"
    assert [a.split(".")[-1] for a in _actions(ship, made[0])] == ["intent", "result"]
    assert ship.cli_json("verify", made[0].head)["outcome"] == "pass"


async def test_agent_sdk_toolset_records_through_executor_class(ship: Ship):
    from shopping_agent_sdk import (
        ShoppingToolset,
        build_shopping_sdk_tools,
        default_config,
        load_mock_backend,
    )

    made: list[TreeshipReceipts] = []
    toolset = ShoppingToolset(
        backend=load_mock_backend(),
        config=default_config(),
        executor_class=_receipted_shopping(ship, made),
    )
    handlers = {t.name: t for t in build_shopping_sdk_tools(toolset)}
    await handlers["search_products"].handler({"query": "headphones"})
    held = await handlers["add_to_cart"].handler(
        {"product_id": "AR-0000-never-seen", "quantity": 1}
    )
    assert held is not None
    assert len(made) == 1
    actions = [a.split(".")[-1] for a in _actions(ship, made[0])]
    assert actions == ["intent", "result", "intent", "result"]
    last = ship.artifacts()[made[0].head]["statement"]["meta"]
    assert last["status"] == "blocked" and last["gate"] == "provenance"
    assert ship.cli_json("verify", made[0].head)["outcome"] == "pass"


async def test_managed_agents_mcp_server_records_through_executor_class(ship: Ship):
    from commerce_common.memory import InMemoryMemoryStore
    from mcp.shared.memory import create_connected_server_and_client_session
    from shopping_agent_sdk import REPO_ROOT

    sys.path.insert(
        0, str(REPO_ROOT / "shopping-agent" / "managed-agents" / "storefront-mcp-server")
    )
    from storefront_mcp_server import build_server

    made: list[TreeshipReceipts] = []
    server = build_server(
        memory_store=InMemoryMemoryStore(), executor_class=_receipted_shopping(ship, made)
    )
    async with create_connected_server_and_client_session(server._mcp_server) as client:
        await client.call_tool("search_products", {"query": "yoga mat"})
        await client.call_tool("search_products", {"query": "headphones"})
    assert len(made) == 1, "one executor, and so one recorder, per MCP connection"
    assert len(made[0].recorded) == 4
    assert ship.cli_json("verify", made[0].head)["outcome"] == "pass"


def _actions(ship: Ship, receipts: TreeshipReceipts) -> list[str]:
    arts = ship.artifacts()
    return [arts[i]["statement"]["action"] for i in receipts.recorded]

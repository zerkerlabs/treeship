# The merchant side on all three of the reference's runtimes, through the
# `executor_class` seam each one exposes -- the path a deployment actually
# uses, where the runtime constructs the executor and there is nothing to
# attach() to. Each test drives the runtime the way the reference's own tests
# do and reads the receipts back, so the approval story is tested per runtime
# rather than inferred from the hand-built executor in test_approvals.py.

from __future__ import annotations

import sys

import pytest

from treeship_commerce import MerchantApprovals, TreeshipReceipts, approved, approving, receipted
from treeship_commerce.receipts import sdk_supports_subject

from .conftest import Ship, needs_cli

pytestmark = [
    needs_cli,
    pytest.mark.skipif(
        not sdk_supports_subject(),
        reason="installed treeship-sdk cannot name an action subject",
    ),
]

HEADPHONES_ID = "AR-1105"  # returned by a "headphones" search of the retail fixture
RESTOCK = {"items": [{"listing_id": HEADPHONES_ID, "action": "restock", "quantity": 24}]}


def _recorder(ship: Ship, made: list[TreeshipReceipts], executors: list | None = None):
    def make(executor) -> TreeshipReceipts:
        r = TreeshipReceipts(
            ship.client,
            actor="agent://merchant",
            session_id=executor._session.session_id,
            role="merchant",
            parent_id=ship.session_root,
        )
        made.append(r)
        if executors is not None:
            executors.append(executor)
        return r

    return make


def _executor_class(
    ship: Ship,
    made: list[TreeshipReceipts],
    approvals: MerchantApprovals,
    executors: list | None = None,
):
    from merchant_agent.executor import MerchantToolExecutor

    return approved(
        receipted(MerchantToolExecutor, recorder=_recorder(ship, made, executors)), approvals
    )


def _apply_intents(ship: Ship, receipts: TreeshipReceipts) -> list[dict]:
    arts = ship.artifacts()
    return [
        arts[i]["statement"]["meta"]
        for i in receipts.recorded
        if arts[i]["statement"]["action"] == "commerce.tool.apply_change.intent"
    ]


async def test_agent_sdk_toolset_signs_the_consoles_yes_through_approving(ship: Ship):
    """The reference console calls host_approve / host_clear and nothing else.
    approving() makes those two calls mint and forget the grant, so the
    console's loop is unchanged and the apply's receipt still proves the
    approval."""
    from merchant_agent_sdk import MerchantToolset, build_merchant_sdk_tools, load_mock_backend

    made: list[TreeshipReceipts] = []
    approvals = MerchantApprovals(ship.client, approver="human://operator")
    toolset = approving(
        MerchantToolset(
            backend=load_mock_backend(),
            executor_class=_executor_class(ship, made, approvals),
        ),
        approvals,
    )
    toolset.config.require_host_approval = True
    handlers = {t.name: t for t in build_merchant_sdk_tools(toolset)}

    await handlers["search_listings"].handler({"query": "headphones"})
    await handlers["stage_inventory_action"].handler(RESTOCK)
    change_id = next(iter(toolset.state.seen_changes))
    assert [c.change_id for c in toolset.pending_host_approvals()] == [change_id]

    # Exactly the reference's own sequence, from its test of this API.
    held = await handlers["apply_change"].handler({"change_id": change_id})
    assert toolset.config.approval_surface in _text(held)
    assert approvals.minted == [], "no yes yet, so nothing signed"

    toolset.host_approve(change_id)
    assert len(approvals.minted) == 1, "the console's yes minted the grant"
    grant_id = approvals.minted[0]
    applied = await handlers["apply_change"].handler({"change_id": change_id})
    assert "is_error" not in applied, _text(applied)
    toolset.host_clear(change_id)
    assert approvals.get(change_id) is None, "host_clear dropped the grant handle"

    assert len(made) == 1, "one executor per toolset, one recorder"
    intents = _apply_intents(ship, made[0])
    assert [i.get("approval") for i in intents] == [None, "proven"]
    assert intents[1]["approval_grant"] == grant_id
    assert ship.cli_json("approval", "uses", grant_id)["uses"]
    assert ship.cli_json("verify", made[0].head)["outcome"] == "pass"


async def test_agent_sdk_toolset_a_cleared_mark_offers_no_nonce(ship: Ship):
    """The reference's rule: a cleared mark approves nothing. Ours matches --
    after host_clear the grant handle is gone, so a later apply cannot even
    offer the nonce, and its receipt carries no approval claim."""
    from merchant_agent_sdk import MerchantToolset, build_merchant_sdk_tools, load_mock_backend

    made: list[TreeshipReceipts] = []
    approvals = MerchantApprovals(ship.client)
    toolset = approving(
        MerchantToolset(
            backend=load_mock_backend(), executor_class=_executor_class(ship, made, approvals)
        ),
        approvals,
    )
    toolset.config.require_host_approval = True
    handlers = {t.name: t for t in build_merchant_sdk_tools(toolset)}
    await handlers["search_listings"].handler({"query": "headphones"})
    await handlers["stage_inventory_action"].handler(RESTOCK)
    change_id = next(iter(toolset.state.seen_changes))

    toolset.host_approve(change_id)
    toolset.host_clear(change_id)
    held = await handlers["apply_change"].handler({"change_id": change_id})
    assert toolset.config.approval_surface in _text(held)

    (intent,) = _apply_intents(ship, made[0])
    assert "approval" not in intent
    # The grant was minted and never spent; the journal agrees.
    assert ship.cli_json("approval", "uses", approvals.minted[0])["uses"] == []


async def test_messages_api_orchestrator_records_the_hosts_grant(ship: Ship):
    """The Messages API runtime leaves the approval mark to the host. A host
    that also calls grant() gets a proven apply receipt out of an executor the
    orchestrator built itself, with a scripted model and no API key."""
    from commerce_common.skills import SkillRegistry
    from commerce_common.testing import FakeClient, text_message, tool_use_message
    from merchant_agent import MerchantSessionContext, MerchantSessionState
    from merchant_agent_runtime import MerchantAgent
    from merchant_agent_sdk import load_mock_backend

    made: list[TreeshipReceipts] = []
    approvals = MerchantApprovals(ship.client, approver="human://operator")
    session = MerchantSessionContext(
        session_id="messages-api-merchant", merchant_id="m-1", operator="human://operator"
    )
    state = MerchantSessionState()

    # Turn 1: the model reads and stages. Turn 2: the host approved; the model applies.
    agent = MerchantAgent(
        backend=load_mock_backend(),
        skills=SkillRegistry([]),
        client=FakeClient(
            [
                tool_use_message("search_listings", {"query": "headphones"}),
                tool_use_message("stage_inventory_action", RESTOCK),
                text_message("Staged; approve it on the card."),
            ]
        ),
        executor_class=_executor_class(ship, made, approvals),
    )
    agent.config = agent.config.model_copy(update={"require_host_approval": True})
    async for _ in agent.stream_turn(
        [{"role": "user", "content": "Restock the headphones by 24"}], session, state
    ):
        pass
    change_id = next(iter(state.seen_changes))
    assert not state.approved_change_ids

    # The host's yes: its own mark, and the signed grant.
    state.approved_change_ids.add(change_id)
    grant = approvals.grant(change_id, summary=state.seen_changes[change_id].summary)
    assert grant is not None

    agent.client = FakeClient(
        [tool_use_message("apply_change", {"change_id": change_id}), text_message("Applied.")]
    )
    async for _ in agent.stream_turn(
        [{"role": "user", "content": f"Approved {change_id}; apply it."}], session, state
    ):
        pass

    assert len(made) == 2, "the orchestrator builds one executor per turn"
    intents = _apply_intents(ship, made[1])
    assert [i["approval"] for i in intents] == ["proven"]
    assert intents[0]["approval_grant"] == grant.artifact_id
    assert state.seen_changes[change_id].status.value == "applied"
    for r in made:
        assert ship.cli_json("verify", r.head)["outcome"] == "pass"


async def test_managed_agents_mcp_server_records_and_never_invents_an_approval(ship: Ship):
    """On Managed Agents the platform's own prompt is the approval surface and
    the click happens outside this process, so the reference runs the server
    with require_host_approval off. Nothing here can sign that click: the
    apply is receipted, and its receipt carries no approval claim at all --
    not a fabricated one."""
    from commerce_common.memory import InMemoryMemoryStore
    from mcp.shared.memory import create_connected_server_and_client_session
    from merchant_agent_sdk import REPO_ROOT

    sys.path.insert(0, str(REPO_ROOT / "merchant-agent" / "managed-agents" / "merchant-mcp-server"))
    from merchant_mcp_server import build_server

    made: list[TreeshipReceipts] = []
    executors: list = []  # the server builds one per connection; the recorder sees it
    approvals = MerchantApprovals(ship.client)
    server = build_server(
        memory_store=InMemoryMemoryStore(),
        executor_class=_executor_class(ship, made, approvals, executors),
    )
    async with create_connected_server_and_client_session(server._mcp_server) as client:
        await client.call_tool("search_listings", {"query": "headphones"})
        await client.call_tool("stage_inventory_action", RESTOCK)
        (executor,) = executors
        change_id = next(iter(executor._state.seen_changes))
        result = await client.call_tool("apply_change", {"change_id": change_id})
    assert not result.isError, result
    assert len(made) == 1, "one executor, one recorder, per MCP connection"
    (intent,) = _apply_intents(ship, made[0])
    assert "approval" not in intent and "approval_grant" not in intent
    assert approvals.minted == []
    assert ship.cli_json("verify", made[0].head)["outcome"] == "pass"


def _text(result: dict) -> str:
    from commerce_common.testing import result_text

    return result_text(result)


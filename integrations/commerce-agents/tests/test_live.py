# One real model turn through the reference's Messages API runtime with
# receipts on. Everything else in this suite scripts the model; this is the
# check that a real Claude, deciding for itself which tools to call, still
# leaves a chain a stranger can verify. It costs an API call, so it runs only
# when ANTHROPIC_API_KEY is set:
#
#     ANTHROPIC_API_KEY=... TREESHIP_BIN=... python -m pytest tests/test_live.py -v
#
# It asserts on structure, never on the model's wording: that every tool the
# model chose has an intent and a result, in that order, chained, verified.

from __future__ import annotations

import os

import pytest

from treeship_commerce import TreeshipReceipts, receipted

from .conftest import Ship, needs_cli

pytestmark = [
    needs_cli,
    pytest.mark.skipif(
        not os.environ.get("ANTHROPIC_API_KEY"),
        reason="live turn needs ANTHROPIC_API_KEY (costs one API call)",
    ),
]


async def test_a_real_turn_leaves_a_verifiable_chain(ship: Ship):
    from commerce_common.skills import SkillRegistry
    from shopping_agent import ShoppingSessionContext, ShoppingSessionState
    from shopping_agent.executor import ShoppingToolExecutor
    from shopping_agent_runtime import ShoppingAgent
    from shopping_agent_sdk import load_mock_backend

    made: list[TreeshipReceipts] = []

    def recorder(executor) -> TreeshipReceipts:
        r = TreeshipReceipts(
            ship.client,
            actor="agent://shopping",
            session_id=executor._session.session_id,
            parent_id=ship.session_root,
        )
        made.append(r)
        return r

    agent = ShoppingAgent(
        backend=load_mock_backend(),
        skills=SkillRegistry([]),
        executor_class=receipted(ShoppingToolExecutor, recorder=recorder),
    )
    session = ShoppingSessionContext(session_id="live-turn", user_id="u-live")
    state = ShoppingSessionState()
    events = [
        e
        async for e in agent.stream_turn(
            [{"role": "user", "content": "Find me a tent for two people and show the options."}],
            session,
            state,
        )
    ]

    calls = [e.data["tool"] for e in events if e.type == "tool_call"]
    assert calls, f"the model called no tools; events: {[e.type for e in events]}"
    assert made, "the runtime built an executor and the factory gave it a recorder"
    receipts = made[0]
    assert receipts.dropped == 0
    assert len(receipts.recorded) == 2 * len(calls), (calls, receipts.recorded)

    arts = ship.artifacts()
    actions = [arts[i]["statement"]["action"] for i in receipts.recorded]
    for tool, intent, result in zip(calls, actions[0::2], actions[1::2], strict=True):
        assert intent == f"commerce.tool.{tool}.intent"
        assert result == f"commerce.tool.{tool}.result"
    # The model's own words never reach a receipt: only digests and types.
    raw = "".join(arts[i]["raw"] for i in receipts.recorded)
    for text in (e.data.get("text", "") for e in events if e.type == "text_delta"):
        if len(text.strip()) > 12:
            assert text not in raw

    verdict = ship.cli_json("verify", receipts.head)
    assert verdict["outcome"] == "pass", verdict
    assert verdict["chain_linkage_ok"] is True

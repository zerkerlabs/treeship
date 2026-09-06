# Every test here would pass for the wrong reason if it only checked that
# execute() returned. Each one names the receipt property it exists for.

from __future__ import annotations

import json

import pytest
from treeship_sdk import Treeship

from treeship_commerce import TreeshipReceipts, args_digest, attach, receipted
from treeship_commerce.receipts import TreeshipExecutorMixin

from .conftest import COMMERCE_SESSION_ID, Ship, needs_cli

pytestmark = needs_cli


async def _first_product(executor) -> str:
    outcome = await executor.execute("search_products", {"query": "tent"})
    assert not outcome.refused, outcome.result_text
    seen = list(executor._state.seen_products)
    assert seen, "the retail mock returned no products for 'tent'"
    return seen[0]


async def test_intent_precedes_result_and_chains_from_the_session_root(ship: Ship, executor):
    product = await _first_product(executor)
    outcome = await executor.execute("add_to_cart", {"product_id": product, "quantity": 1})
    assert not outcome.refused, outcome.result_text

    receipts: TreeshipReceipts = executor.treeship_receipts
    assert receipts.dropped == 0
    assert len(receipts.recorded) == 4  # intent, result, intent, result

    chain = ship.chain(receipts.head)
    actions = [c["statement"]["action"] for c in chain]
    assert (
        actions[0].startswith("session.start")
        or chain[0]["record"]["artifact_id"] == ship.session_root
    )
    assert actions[1:] == [
        "commerce.tool.search_products.intent",
        "commerce.tool.search_products.result",
        "commerce.tool.add_to_cart.intent",
        "commerce.tool.add_to_cart.result",
    ]
    # Each result's parent is its own intent, so a result can never be read as
    # belonging to a different call.
    for intent, result in zip(chain[1::2], chain[2::2], strict=True):
        assert result["statement"]["parentId"] == intent["record"]["artifact_id"]

    verdict = ship.cli_json("verify", receipts.head)
    assert verdict["outcome"] == "pass", verdict
    assert verdict["chain_linkage_ok"] is True
    assert verdict["total"] == 5  # root + 4

    status = ship.cli_json("session", "status")
    assert status["receipts"] == 4
    assert status["events"] >= 2  # one timeline event per tool call


async def test_a_held_call_is_signed_as_blocked_with_the_gate_named(ship: Ship, executor):
    from shopping_agent.gates import PROVENANCE_GATE

    outcome = await executor.execute("add_to_cart", {"product_id": "p-never-seen", "quantity": 1})
    assert outcome.blocked == PROVENANCE_GATE  # the reference's gate did its job

    receipts: TreeshipReceipts = executor.treeship_receipts
    result = ship.artifacts()[receipts.head]["statement"]
    assert result["action"] == "commerce.tool.add_to_cart.result"
    meta = result["meta"]
    assert meta["status"] == "blocked"
    assert meta["gate"] == PROVENANCE_GATE
    assert meta["intent_recorded"] is True
    # Blocked is still a pass for the signature: the receipt is authentic
    # evidence of a refusal, not a failed receipt.
    assert ship.cli_json("verify", receipts.head)["outcome"] == "pass"


async def test_receipts_carry_digests_never_arguments_results_or_the_session_id(
    ship: Ship, executor
):
    product = await _first_product(executor)
    await executor.execute("get_product_details", {"product_id": product})
    receipts: TreeshipReceipts = executor.treeship_receipts

    arts = ship.artifacts()
    for artifact_id in receipts.recorded:
        raw = arts[artifact_id]["raw"]
        statement = arts[artifact_id]["statement"]
        assert COMMERCE_SESSION_ID not in raw, "the commerce session id is a credential"
        assert '"tent"' not in raw, "raw arguments must not appear in a receipt"
        assert "storefront_data" not in raw, "fenced result text must not appear in a receipt"
        meta = statement["meta"]
        assert (
            meta["session_tag"]
            == __import__("hashlib").sha256(COMMERCE_SESSION_ID.encode()).hexdigest()[:12]
        )

    intent = arts[receipts.recorded[0]]["statement"]
    assert intent["meta"]["args_digest"] == args_digest({"query": "tent"})
    details_result = arts[receipts.recorded[-1]]["statement"]
    assert details_result["meta"]["result_digest"].startswith("sha256:")
    assert details_result["meta"]["events"] == []


async def test_recording_failure_never_breaks_the_tool_and_is_counted(ship: Ship, executor):
    # Point the recorder at a binary that does not exist. The tool must still
    # run and return its real outcome; the recorder must count what it lost
    # rather than pretend.
    broken = Treeship(cli_path=str(ship.root / "no-such-treeship"), env=ship.env, cwd=ship.root)
    attach(
        executor,
        TreeshipReceipts(
            broken,
            actor="agent://shopping",
            session_id=COMMERCE_SESSION_ID,
            parent_id=ship.session_root,
        ),
    )
    outcome = await executor.execute("search_products", {"query": "tent"})
    assert not outcome.refused
    assert "tent" in outcome.result_text.lower() or executor._state.seen_products
    receipts: TreeshipReceipts = executor.treeship_receipts
    assert receipts.recorded == []
    assert receipts.dropped >= 2  # intent + result (+ timeline event)
    assert receipts.head == ship.session_root  # the chain head never moved to a phantom id


async def test_disabled_records_nothing_and_changes_nothing(ship: Ship, executor, monkeypatch):
    monkeypatch.setenv("TREESHIP_DISABLE", "1")
    before = set(ship.artifacts())
    outcome = await executor.execute("search_products", {"query": "tent"})
    assert not outcome.refused
    assert set(ship.artifacts()) == before
    assert executor.treeship_receipts.recorded == []
    assert executor.treeship_receipts.dropped == 0


async def test_attach_refuses_an_executor_that_would_record_nothing(ship: Ship):
    from commerce_common.memory import InMemoryMemoryStore
    from commerce_common.skills import SkillRegistry
    from shopping_agent import ShoppingAgentConfig, ShoppingSessionContext, ShoppingSessionState
    from shopping_agent.executor import ShoppingToolExecutor, build_memory
    from shopping_agent_sdk import load_mock_backend

    config = ShoppingAgentConfig(brand_name="ACME")
    plain = ShoppingToolExecutor(
        backend=load_mock_backend(),
        config=config,
        skills=SkillRegistry([]),
        session=ShoppingSessionContext(session_id="s", user_id="u"),
        state=ShoppingSessionState(),
        memory=build_memory(config, InMemoryMemoryStore()),
        inline_context=True,
    )
    with pytest.raises(TypeError):
        attach(plain, TreeshipReceipts(ship.client, actor="agent://shopping"))


def test_receipted_puts_the_mixin_first_and_is_idempotent():
    from shopping_agent.executor import ShoppingToolExecutor

    cls = receipted(ShoppingToolExecutor)
    assert cls.__mro__[1] is TreeshipExecutorMixin
    assert issubclass(cls, ShoppingToolExecutor)
    assert receipted(cls) is cls


def test_args_digest_is_canonical():
    assert args_digest({"b": 1, "a": "x"}) == args_digest({"a": "x", "b": 1})
    assert args_digest({}) == args_digest(None)
    assert args_digest({"a": 1}) != args_digest({"a": 2})
    assert json.dumps({"a": 1}) and args_digest({"a": 1}).startswith("sha256:")


async def test_a_recorder_factory_gives_each_executor_its_own_chain(ship: Ship):
    # The runtimes construct executors themselves through `executor_class`,
    # so the factory is the only way to record there. Two executors, two
    # commerce sessions, two recorders, two tags -- never one shared chain.
    from commerce_common.memory import InMemoryMemoryStore
    from commerce_common.skills import SkillRegistry
    from shopping_agent import ShoppingAgentConfig, ShoppingSessionContext, ShoppingSessionState
    from shopping_agent.executor import ShoppingToolExecutor, build_memory
    from shopping_agent_sdk import load_mock_backend

    config = ShoppingAgentConfig(brand_name="ACME")
    cls = receipted(
        ShoppingToolExecutor,
        recorder=lambda ex: TreeshipReceipts(
            ship.client,
            actor="agent://shopping",
            session_id=ex._session.session_id,
            parent_id=ship.session_root,
        ),
    )

    def build(session_id: str):
        return cls(
            backend=load_mock_backend(),
            config=config,
            skills=SkillRegistry([]),
            session=ShoppingSessionContext(session_id=session_id, user_id="u"),
            state=ShoppingSessionState(),
            memory=build_memory(config, InMemoryMemoryStore()),
            inline_context=True,
        )

    a, b = build("session-A"), build("session-B")
    assert a.treeship_receipts is None  # nothing recorded until the first call
    await a.execute("search_products", {"query": "tent"})
    await b.execute("search_products", {"query": "tent"})
    assert a.treeship_receipts is not b.treeship_receipts
    assert a.treeship_receipts.session_tag != b.treeship_receipts.session_tag
    assert len(a.treeship_receipts.recorded) == 2 and len(b.treeship_receipts.recorded) == 2
    for ex in (a, b):
        assert ship.cli_json("verify", ex.treeship_receipts.head)["outcome"] == "pass"


class _OldSdkClient:
    """A treeship-sdk 0.27.0 client: attest_action exists, session_event does not."""

    def __init__(self, inner):
        self._inner = inner

    def attest_action(self, *args, **kwargs):
        return self._inner.attest_action(*args, **kwargs)


async def test_an_sdk_without_session_event_still_writes_signed_receipts(ship: Ship, executor):
    # The SDK on PyPI at launch (0.27.0) predates session_event(). The
    # receipts are the evidence; the timeline must degrade, never raise into
    # the tool call. Before this guard, AttributeError escaped execute().
    attach(
        executor,
        TreeshipReceipts(
            _OldSdkClient(ship.client),
            actor="agent://shopping",
            session_id=COMMERCE_SESSION_ID,
            parent_id=ship.session_root,
        ),
    )
    outcome = await executor.execute("search_products", {"query": "tent"})
    assert not outcome.refused
    receipts: TreeshipReceipts = executor.treeship_receipts
    assert len(receipts.recorded) == 2 and receipts.dropped == 0
    assert ship.cli_json("verify", receipts.head)["outcome"] == "pass"


async def test_a_client_that_raises_anything_never_breaks_the_tool(ship: Ship, executor):
    class Explodes:
        def attest_action(self, *a, **k):
            raise RuntimeError("simulated SDK bug")

        def session_event(self, *a, **k):
            raise KeyError("simulated SDK bug")

    attach(
        executor,
        TreeshipReceipts(Explodes(), actor="agent://shopping", parent_id=ship.session_root),
    )
    outcome = await executor.execute("search_products", {"query": "tent"})
    assert not outcome.refused
    assert executor.treeship_receipts.recorded == []
    assert executor.treeship_receipts.dropped >= 2

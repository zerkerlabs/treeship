# The merchant side. Every test here names the property it exists for, and
# each one is written so that removing the feature makes it fail for the right
# reason -- an approval test that passes because nothing was checked is worse
# than no approval test.

from __future__ import annotations

import pytest

from treeship_commerce import TreeshipReceipts
from treeship_commerce.approvals import change_subject
from treeship_commerce.receipts import _refusal_reason, sdk_supports_subject

from .conftest import Ship, needs_cli

pytestmark = [
    needs_cli,
    pytest.mark.skipif(
        not sdk_supports_subject(),
        reason="installed treeship-sdk cannot name an action subject",
    ),
]

MERCHANT_SESSION_ID = "m-secret-session-3d81"


async def stage_a_change(executor) -> str:
    """Drive the merchant executor until it has one staged change, and return
    its id. Staging is the reference's own path; nothing is faked."""
    listings = await executor.execute("search_listings", {"query": ""})
    assert not listings.refused, listings.result_text
    seen = executor._state.seen_listings
    assert seen, "the merchant mock returned no listings"
    listing_id, listing = next(
        (lid, item) for lid, item in seen.items() if not item.has_options
    )
    # A shallow markdown: deep enough to be a real change, shallow enough to
    # clear the mock's cost floor and promotion-depth guardrails, which are the
    # reference's gates and not what these tests are about.
    outcome = await executor.execute(
        "stage_price_update",
        {
            "items": [{"listing_id": listing_id, "new_price": round(listing.price * 0.97, 2)}],
            "note": "clearance",
        },
    )
    assert not outcome.refused, outcome.result_text
    staged = list(executor._state.seen_changes)
    assert staged, f"no change staged: {outcome.result_text}"
    return staged[0]


def operator_approves(executor, approvals, change_id: str):
    """What a host does when the human says yes: mint the signed grant and set
    the reference's own approval mark. Both, because they answer different
    questions -- the mark lets the apply through, the grant proves it was
    allowed to."""
    grant = approvals.grant(change_id, summary="operator approved in test")
    executor._state.approved_change_ids.add(change_id)
    return grant


async def test_apply_without_a_grant_records_no_approval_evidence(ship: Ship, merchant):
    """The baseline the rest is measured against: with no grant, the apply's
    receipt carries no approval claim at all -- not a false one."""
    executor, approvals = merchant
    change_id = await stage_a_change(executor)
    await executor.execute("apply_change", {"change_id": change_id})

    receipts: TreeshipReceipts = executor.treeship_receipts
    intents = [
        c["statement"]
        for c in ship.chain(receipts.head)
        if c["statement"].get("action") == "commerce.tool.apply_change.intent"
    ]
    assert len(intents) == 1
    meta = intents[0].get("meta") or {}
    assert "approval" not in meta
    assert "approval_grant" not in meta
    assert approvals.minted == []


async def test_operator_approval_is_signed_and_binds_to_the_receipt(ship: Ship, merchant):
    """The operator's yes produces a signed grant, and the apply's receipt
    names it and claims the approval was proven."""
    executor, approvals = merchant
    change_id = await stage_a_change(executor)

    grant = operator_approves(executor, approvals, change_id)
    assert grant is not None
    assert grant.change_id == change_id
    assert grant.subject == change_subject(change_id)
    assert approvals.minted == [grant.artifact_id]
    # The nonce is a capability; it must not leak through the repr that ends
    # up in operator logs.
    assert grant.nonce not in repr(grant)

    await executor.execute("apply_change", {"change_id": change_id})

    receipts: TreeshipReceipts = executor.treeship_receipts
    intents = [
        c["statement"]
        for c in ship.chain(receipts.head)
        if c["statement"].get("action") == "commerce.tool.apply_change.intent"
    ]
    assert len(intents) == 1
    meta = intents[0]["meta"]
    assert meta["approval"] == "proven"
    assert meta["approval_grant"] == grant.artifact_id
    assert meta["change_id"] == change_id
    assert receipts.dropped == 0

    # The journal, not our bookkeeping, is the authority on the use.
    uses = ship.cli_json("approval", "uses", grant.artifact_id)
    assert uses["uses"], uses
    assert len(uses["uses"]) == 1


async def test_a_grant_is_spendable_once(ship: Ship, merchant):
    """The property the in-process approval set cannot provide: a second apply
    of the same approved change gets no approval evidence, because the journal
    refuses the second use."""
    executor, approvals = merchant
    change_id = await stage_a_change(executor)
    grant = operator_approves(executor, approvals, change_id)
    assert grant is not None

    first = await executor.execute("apply_change", {"change_id": change_id})
    assert not first.refused, first.result_text
    # The host would normally re-approve; here the same grant is offered twice
    # on purpose, which is exactly the replay the journal has to refuse.
    approvals._grants[change_id] = grant
    await executor.execute("apply_change", {"change_id": change_id})

    receipts: TreeshipReceipts = executor.treeship_receipts
    intents = [
        c["statement"]
        for c in ship.chain(receipts.head)
        if c["statement"].get("action") == "commerce.tool.apply_change.intent"
    ]
    assert len(intents) == 2
    assert intents[0]["meta"]["approval"] == "proven"
    note = intents[1]["meta"]["approval_note"]
    assert "max_uses" in note
    # The reason, not the SDK's transport wrapper around it.
    assert "attest action failed" not in note
    # Still one use in the journal, not two.
    uses = ship.cli_json("approval", "uses", grant.artifact_id)
    assert len(uses["uses"]) == 1


async def test_a_grant_cannot_be_spent_on_a_different_change(ship: Ship, merchant):
    """Scope, not just counting: a grant minted for one change is refused when
    offered for another, so approvals cannot be shuffled between changes."""
    executor, approvals = merchant
    change_id = await stage_a_change(executor)
    other = approvals.grant("chg_not_this_one")
    assert other is not None

    # Offer the wrong change's grant for this apply. The nonce is valid and
    # unspent; only the subject differs, so the scope check is the only thing
    # that can refuse it.
    approvals._grants[change_id] = other
    await executor.execute("apply_change", {"change_id": change_id})

    receipts: TreeshipReceipts = executor.treeship_receipts
    intents = [
        c["statement"]
        for c in ship.chain(receipts.head)
        if c["statement"].get("action") == "commerce.tool.apply_change.intent"
    ]
    assert intents[-1]["meta"]["approval"] == "unproven"
    assert "scope" in intents[-1]["meta"]["approval_note"].lower()
    uses = ship.cli_json("approval", "uses", other.artifact_id)
    assert uses["uses"] == []


async def test_enforce_holds_the_call_when_there_is_no_grant(ship: Ship, merchant_enforcing):
    """Opt-in enforcement: an unapproved apply is held before the tool runs,
    the hold is the reference's own outcome shape, and the hold is itself a
    signed refusal -- an intent and a blocked result -- never a call that
    left no trace."""
    executor, _ = merchant_enforcing
    change_id = await stage_a_change(executor)
    receipts: TreeshipReceipts = executor.treeship_receipts
    before = len(receipts.recorded)

    outcome = await executor.execute("apply_change", {"change_id": change_id})
    assert outcome.refused
    assert outcome.blocked == "approval"
    assert change_id in outcome.result_text
    assert "no signed approval grant" in outcome.result_text

    assert len(receipts.recorded) == before + 2
    result = ship.artifacts()[receipts.head]["statement"]
    assert result["action"] == "commerce.tool.apply_change.result"
    assert result["meta"]["status"] == "blocked"
    assert result["meta"]["gate"] == "approval"


async def test_enforce_holds_a_replay_of_a_spent_grant(ship: Ship, merchant_enforcing):
    """Under enforce, a grant that would not spend holds the call even though
    the reference's own mark is still set -- the journal is the authority."""
    executor, approvals = merchant_enforcing
    change_id = await stage_a_change(executor)
    grant = operator_approves(executor, approvals, change_id)
    assert grant is not None

    first = await executor.execute("apply_change", {"change_id": change_id})
    assert not first.refused, first.result_text

    approvals._grants[change_id] = grant  # offer the spent grant again
    replay = await executor.execute("apply_change", {"change_id": change_id})
    assert replay.refused
    assert replay.blocked == "approval"
    assert "would not spend" in replay.result_text

    intents = [
        c["statement"]
        for c in ship.chain(executor.treeship_receipts.head)
        if c["statement"].get("action") == "commerce.tool.apply_change.intent"
    ]
    assert [i["meta"]["approval"] for i in intents] == ["proven", "unproven"]


async def test_recording_off_mints_nothing_and_changes_nothing(ship: Ship, merchant, monkeypatch):
    """TREESHIP_DISABLE is absolute: no grant is minted, and the apply behaves
    exactly as the unwrapped reference does -- allowed when the host approved
    it, held by the reference's own gate when it did not."""
    executor, approvals = merchant
    change_id = await stage_a_change(executor)
    monkeypatch.setenv("TREESHIP_DISABLE", "1")

    assert approvals.grant(change_id) is None
    assert approvals.minted == []

    held = await executor.execute("apply_change", {"change_id": change_id})
    assert held.refused
    assert held.blocked == "approval"  # the reference's gate, not ours

    executor._state.approved_change_ids.add(change_id)
    allowed = await executor.execute("apply_change", {"change_id": change_id})
    assert not allowed.refused, allowed.result_text


def test_the_refusal_reason_is_the_cli_reason_not_the_wrapper():
    """The note is signed evidence, so it carries why the grant would not
    spend -- not the SDK's ``failed (exit=1)`` envelope around it."""
    wrapped = RuntimeError(
        'treeship attest action failed (exit=1): '
        '{"error":"approval grant art_x would exceed max_uses (1/1)","status":"error"}'
    )
    assert _refusal_reason(wrapped) == "approval grant art_x would exceed max_uses (1/1)"
    # Anything that is not that shape is still recorded rather than swallowed.
    assert _refusal_reason(RuntimeError("plain failure\nsecond line")) == "plain failure"
    assert _refusal_reason(RuntimeError("")) == "RuntimeError"

# Treeship for Claude Commerce Agents

Signed, offline-verifiable receipts for every tool call in
[anthropics/commerce-agents](https://github.com/anthropics/commerce-agents), on all three of
its runtimes.

The reference draws its own boundary in `docs/safety.md`: the approval surface, payment,
and log hygiene are "what a deployment owns". This package is what a deployment adds for
the record of what happened. It records; it does not gate. The reference's provenance
gates, caps, and host approval still decide what runs.

## What it does

`commerce_common.execution.BaseToolExecutor.execute` is the one method every tool call
passes through on the Messages API, the Agent SDK, and Managed Agents. `TreeshipExecutorMixin`
overrides it:

1. a signed **intent** receipt before dispatch: tool, SHA-256 of the canonical arguments,
   session tag;
2. the tool, exactly as the reference runs it;
3. a signed **result** receipt: status (`ok`, `blocked` with the gate's name, `error`),
   SHA-256 of the result text, event types, timing.

Each receipt names its parent, so a session reads `intent → result → intent → result …` from
the Treeship session's root, and `treeship verify` walks it as one chain. A held call is a
signed refusal, not a missing receipt.

Never written: the arguments, the result text (fenced third-party content on the
reference), or the commerce session id (the request credential). The receipt carries the
same twelve-hex session tag the reference's own log lines use, so an operator holding the id
can correlate and a reader cannot.

## Install

```bash
# from a clone of anthropics/commerce-agents, with its venv active
pip install -r requirements.txt            # their seven packages (unregistered on PyPI)
pip install treeship-sdk treeship-commerce
curl -fsSL https://treeship.dev/install | sh && treeship init
```

## Or let Claude Code wire it

```bash
claude plugin marketplace add zerkerlabs/treeship
claude plugin install treeship-commerce@treeship
/add-treeship-receipts merchant      # or shopping, or both
```

The plugin ([`plugin/`](plugin/)) mirrors the reference's `commerce-builder`: one command that reads
your project and wires the seams below on your runtime, and one skill on what the receipts carry.

## Use

```python
from treeship_sdk import Treeship
from treeship_commerce import TreeshipReceipts, attach, receipted
from treeship_commerce.lifecycle import close_session, start_session
from shopping_agent.executor import ShoppingToolExecutor

ts = Treeship()
root = start_session(ts, name="storefront:acme", actor="agent://shopping")

executor = receipted(ShoppingToolExecutor)(backend=..., config=..., skills=..., session=..., state=..., memory=...)
attach(executor, TreeshipReceipts(ts, actor="agent://shopping", session_id=session.session_id, parent_id=root))

# ... the runtime calls executor.execute(...) as it always did ...

close_session(ts, summary="...")          # seals a .treeship package; `treeship session report` publishes it
```

All three runtimes construct executors themselves through `executor_class`
(`ShoppingAgent`, `ShoppingToolset`, the MCP server's `build_server`). Give
`receipted()` a `recorder` factory and each executor gets its own recorder on
its first tool call:

```python
ReceiptedShopping = receipted(ShoppingToolExecutor, recorder=lambda ex: TreeshipReceipts(
    ts, actor="agent://shopping", session_id=ex._session.session_id, parent_id=root))
```

Same for `MerchantToolExecutor`.

Recording never breaks the agent path: a receipt that cannot be written warns once, is
counted in `TreeshipReceipts.dropped`, and later results say `intent_recorded: false` where
the intent is missing. Nothing is invented. `TREESHIP_DISABLE=1` turns recording off.

## Demo

```bash
TREESHIP_BIN=... python -m treeship_commerce.demo
```

Runs the reference's shopping executor over the retail mock with no model and no API key:
a search, a product read, an add, an add the provenance gate holds, a checkout hand-off.
Prints every receipt id, seals the session, and shows the `treeship verify` command.

```bash
TREESHIP_BIN=... python -m treeship_commerce.demo_merchant
```

The merchant side: a staged price change, held while unapproved, applied once under a
signed single-use operator approval, then refused on replay while the reference's own
in-process approval mark is still set. Prints the grant id and the journal's record of
its one use.

## Checkout

`receipted_backend(backend)` wraps a storefront backend so `checkout_handoff` also signs a
hand-off receipt: cart digest, item count, subtotal, currency, and a digest of each hosted
URL (never the URL). `order_placed(receipts, order_ref=..., amount=..., currency=...)` is
the host's half: a signed order receipt chained onto the hand-off, the order reference
digested. A holder of the checkout card can recompute the cart digest from the card alone.

## Approvals

`MerchantApprovals` turns the host's y/N into a signed Approval Grant scoped to one actor,
one action, and one change (`change://<change_id>`), `max_uses=1`. `approved(receipted(
MerchantToolExecutor), approvals)` signs the apply's intent receipt with the grant's nonce,
so the CLI reserves a use in the Approval Use Journal before signing. A second apply finds
the grant spent; a grant for another change is refused by scope. The receipt says
`approval: "proven"` or `"unproven"` with the reason. Recording only, unless
`enforce=True`. Needs `treeship-sdk` 0.29.0 or later (`attest_action` takes `subject`).

On the Agent SDK runtime, `approving(toolset, approvals)` wraps `MerchantToolset.host_approve`
and `host_clear` in place, so the reference console's y/N loop mints and forgets grants with
no edits. On the Messages API the host calls `approvals.grant()` beside its own mark. On
Managed Agents the platform's prompt is the approval surface and the click is outside the
process; an apply there is receipted with no approval claim, never an invented one.

## What this does not do (yet)

- **Prove the work is correct.** A receipt is evidence of what ran and what the gates
  decided. It does not make a wrong answer right.

## Tests

```bash
TREESHIP_BIN=/path/to/treeship python -m pytest
ANTHROPIC_API_KEY=... TREESHIP_BIN=/path/to/treeship python -m pytest tests/test_live.py   # one real turn
```

Thirty-five cases on a real isolated ship over the real retail and merchant mocks: chain
order and linkage, a held call signed as blocked with its gate, digests-only content,
recording failure leaving the tool untouched, `TREESHIP_DISABLE`, `attach` refusing an
executor that would record nothing, one per runtime, and the approval properties: a grant
binds to its receipt, is spendable once, is refused for another change, `enforce=True`
holds an unapproved apply, the receipt note is the CLI's reason rather than the SDK's
wrapper, the merchant side on all three runtimes through `executor_class`, and arguments
that arrive as parsed pydantic models (the MCP server's shape) digesting like their dicts,
and the checkout hand-off: the cart digest recomputable from the card, the URL never
written, the host's order chaining from the hand-off, and an unwrapped backend's order
saying so.

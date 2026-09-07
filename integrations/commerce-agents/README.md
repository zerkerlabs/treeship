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

## What this does not do (yet)

- **Approvals.** The merchant `apply_change` gate checks a mark the host sets. Turning that
  mark into a signed, single-use Treeship approval (nonce echoed by the apply receipt,
  enforced by the Approval Use Journal) is the next piece.
- **Checkout hand-off receipt.** Signing the cart digest and hosted-checkout URL digest at
  `checkout_handoff`, chained to the host's order placement.
- **Prove the work is correct.** A receipt is evidence of what ran and what the gates
  decided. It does not make a wrong answer right.

## Tests

```bash
TREESHIP_BIN=/path/to/treeship python -m pytest
```

Six cases on a real isolated ship and the real retail mock: chain order and linkage, a held
call signed as blocked with its gate, digests-only content, recording failure leaving the
tool untouched, `TREESHIP_DISABLE`, and `attach` refusing an executor that would record
nothing.

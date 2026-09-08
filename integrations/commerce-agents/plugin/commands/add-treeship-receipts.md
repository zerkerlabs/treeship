---
description: Add Treeship receipts to an existing commerce-agents deployment, on whichever of the three runtimes it uses. Wraps the one executor every tool call passes through, and, for a merchant agent, makes the operator's approval a signed single-use grant; for a shopping agent, signs the cart at checkout hand-off and lets the host chain its order. Use when a shopping or merchant agent on the reference packages needs a tamper-evident record of what ran, what the gates decided, who approved a write, and what went to checkout.
argument-hint: "[shopping | merchant | both] (default: whatever the project has)"
---

Add Treeship receipts to the user's commerce agent. Requested role:

$ARGUMENTS

Without a role, read the project and infer it; with both roles present, wire both. Treeship records; it does not gate. The reference's provenance gates, guardrails, and host approval decide what runs, exactly as before, and every decision they make becomes a signed receipt that verifies offline. Say that once, early, so the user does not expect the agent's behaviour to change.

## Step 1: Locate things

1. The reference (`anthropics/commerce-agents`): the current repo, a local clone, or a fresh clone. Treeship needs it only for the tests and the demos; the deployment imports `treeship_commerce` and its own reference packages.
2. The user's agent and its runtime. Look for the `executor_class` seam: `ShoppingAgent(...)` / `MerchantAgent(...)` (Messages API), `ShoppingToolset(...)` / `MerchantToolset(...)` (Agent SDK), or `build_server(...)` in a `*-mcp-server` (Managed Agents). A project from `/scaffold-commerce-agent` names its runtime in the `## Commerce agent decision record` of `CLAUDE.md`; read it, and read the approval surface entry for a merchant agent.
3. A Treeship ship. `treeship --version` must print 0.29.0 or later, and `treeship init --config .treeship/config.json` must have run in the deployment's working directory (or `TREESHIP_CONFIG` must point at one). Without a ship, receipts are dropped and counted, never invented; say so and offer to run `treeship init --config .treeship/config.json`.

## Step 2: Install

```bash
pip install "treeship-sdk>=0.29.0" "treeship-commerce>=0.29.0"
```

Pin both in the project's dependency file. `treeship-commerce` declares the SDK floor it needs; do not lower it, because signed approvals require the SDK's `attest_action(subject=)`.

## Step 3: Wire the executor

Every tool call on all three runtimes runs through `BaseToolExecutor.execute`, so one wrapper covers the runtime the project uses. Build the receipted class once and pass it where the runtime takes `executor_class`:

```python
from treeship_sdk import Treeship
from treeship_commerce import TreeshipReceipts, receipted
from treeship_commerce.lifecycle import start_session

ts = Treeship()
root = start_session(ts, name="commerce:<store>", actor="agent://shopping")   # or agent://merchant

def make_recorder(executor):
    return TreeshipReceipts(
        ts,
        actor="agent://shopping",                      # match the role
        session_id=executor._session.session_id,       # only its 12-hex tag is ever written
        parent_id=root,
    )

Executor = receipted(ShoppingToolExecutor, recorder=make_recorder)   # or MerchantToolExecutor
```

| Runtime | Where `Executor` goes |
|---|---|
| Messages API | `ShoppingAgent(..., executor_class=Executor)` / `MerchantAgent(..., executor_class=Executor)` |
| Agent SDK | `ShoppingToolset(..., executor_class=Executor)` / `MerchantToolset(..., executor_class=Executor)` |
| Managed Agents | `build_server(..., executor_class=Executor)` |

A project that constructs executors itself can `attach(executor, TreeshipReceipts(...))` instead; `attach` refuses a plain reference executor, because one that silently recorded nothing is the failure this exists to remove.

Pin, in the user's words, the two facts the receipts rely on: the actor URI is the role, and the `session_id` handed to the recorder is the commerce session id (the reference's request credential). The recorder writes only `session_tag(session_id)`, the same twelve hex characters the reference's own log lines carry, so logs and receipts correlate without either holding the id.

## Step 4: A shopping agent: the checkout hand-off

Wrap the storefront backend once, where the runtime is built:

```python
from treeship_commerce import receipted_backend, order_placed

backend = receipted_backend(MyStorefront())
```

`checkout_handoff(session, cart)` now also signs a hand-off receipt: cart digest, item count, subtotal, currency, and a digest of each hosted URL with its seller. The URL is never written. Then find where the host learns the order was placed on its own checkout page, and add the host's half there:

```python
await order_placed(receipts, order_ref=order.order_id, amount=order.total, currency=order.currency)
```

`receipts` is the recorder for that session (`TreeshipReceipts.for_session(session_id)` finds it, or the host keeps the one it built). If the host has no order-placed hook yet, say so and leave a `TODO` at the checkout page's success path; an order receipt without a hand-off says `handoff_recorded: false` rather than inventing a parent, so a partial wiring is honest, not wrong.

## Step 5: A merchant agent: signed approvals

The reference gates `apply_change` on `state.approved_change_ids`, an in-process set the host fills from its y/N. Make the yes a signed, scoped, single-use grant:

```python
from treeship_commerce import MerchantApprovals, approved, approving

approvals = MerchantApprovals(ts, approver="human://operator", actor="agent://merchant")
Executor = approved(receipted(MerchantToolExecutor, recorder=make_recorder), approvals)
```

Then, by runtime, from the decision record's approval surface:

- **Agent SDK.** `toolset = approving(MerchantToolset(..., executor_class=Executor), approvals)`. The console's `host_approve` / `host_clear` calls are unchanged and now mint and forget grants.
- **Messages API.** Where the host adds the id to `state.approved_change_ids`, also call `approvals.grant(change_id, summary=change.summary)`.
- **Managed Agents.** The platform's `always_ask` prompt is the approval surface and the click is outside the process. Nothing can sign it; an apply there is receipted with no approval claim. Say this plainly and do not add `enforce=True` on that runtime, since it would hold every apply.

`approver` is a URI for the human principal, from the host's own authentication; never a display name and never invented. The `actor` must equal the recorder's actor or the grant's scope refuses the apply it was minted for.

Default is recording only: a missing or spent grant is written as `approval: "unproven"` with the CLI's reason, and the reference's gate still holds the call. Offer `approved(..., enforce=True)` only when the user says the receipt should be the authority; then a missing or spent grant holds the apply after its intent receipt, so the hold is itself signed.

## Step 6: Seal, verify, report

At the end of a commerce session:

```python
from treeship_commerce.lifecycle import close_session
sealed = close_session(ts, summary="...")     # a .treeship package
```

```bash
treeship package verify <sealed package>       # every receipt, the Merkle root, the journal check
treeship approval uses <grant-id>              # a merchant grant's one use
treeship session report                         # publish, deliberately, for a shareable receipt page
```

Add the verify line to the project's CI next to its evals, so a receipt chain that stops verifying fails the build.

## Step 7: Verify the wiring

1. Run the reference-style tests the project has with `TREESHIP_BIN` set; a receipted executor changes no tool result.
2. Drive one turn and check `treeship session status` shows receipts, and `dropped == 0` on the recorder.
3. For a merchant agent, approve one change, apply it, apply it again, and confirm the second intent receipt says `approval: "unproven"` with `max_uses (1/1)` in its note.
4. For a shopping agent, run one checkout and confirm the hand-off receipt's `cart_digest` equals `cart_digest(card_payload["cart"])`.
5. Update the decision record: runtime wired, actor URIs, approval surface signed (merchant), hand-off and order hook (shopping), and whether `enforce` is on.

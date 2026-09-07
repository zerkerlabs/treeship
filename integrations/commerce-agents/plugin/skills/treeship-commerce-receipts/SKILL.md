---
name: treeship-commerce-receipts
description: What treeship-commerce signs in an anthropics/commerce-agents deployment and what it never writes, with the three seams (every tool call, the merchant's approval, the shopping checkout hand-off), the receipt fields, the per-runtime differences, and how to verify. Load when adding, reading, or auditing Treeship receipts on a shopping or merchant agent, or when a user asks what a receipt proves.
---

# Treeship receipts for commerce agents

`treeship_commerce` is the `treeship-commerce` package on PyPI; its source is `integrations/commerce-agents/` in `zerkerlabs/treeship`. It records; the reference's gates decide. The reference enforces fencing, provenance, caps, and host approval in code and names the record as "what a deployment owns". These receipts are that record: signed by the deployment's own key, chained, verifiable offline with `treeship verify`, never dependent on a service.

## Three seams, one rule

| Seam | Where | What is signed |
|---|---|---|
| Every tool call | `BaseToolExecutor.execute`, the one method all three runtimes route through | an **intent** receipt before dispatch, a **result** receipt after |
| The merchant's approval | the host's y/N, the moment it sets the reference's approval mark | a scoped **single-use grant**; the apply's intent receipt is signed with its nonce |
| The shopping checkout | `backend.checkout_handoff(session, cart)`, called from the checkout card's enrichment | a **hand-off** receipt for the cart; the host chains an **order** receipt |

The rule on every seam: a receipt that cannot be written is counted in `receipts.dropped` and warned about, and the tool runs. Nothing raised while describing a call reaches the tool. No id is ever invented: a result whose intent is missing says `intent_recorded: false`; an order without a hand-off says `handoff_recorded: false`; an apply whose grant would not spend says `approval: "unproven"` with the CLI's reason.

## What a receipt carries, and what it never carries

Intent: `tool`, `role`, `args_digest` (SHA-256 of the canonical arguments; pydantic models, dataclasses, sets, bytes and datetimes digest like their plain forms), `session_tag`. Result: `status` (`ok` / `blocked` with `gate` / `error`), `result_digest`, `events`, `elapsed_ms`, `intent_recorded`. Hand-off: `cart_digest`, `item_count`, `subtotal`, `currency`, `handoffs[].url_digest` and `seller`. Order: `order_ref_digest`, `amount`, `currency`, `handoff_recorded`. Approved apply intent: `approval: "proven"`, `approval_grant`, `change_id`.

Never: the arguments, the fenced result text, the commerce session id (only the reference's own twelve-hex `session_tag`), the hosted checkout URL, the order reference, the cart's lines. A holder of the original can recompute every digest; a holder of the receipt learns nothing from one.

`cart_digest` is over the lines sorted by canonical form (`product_id`, `variant_of`, `option_values`, `price`, `quantity`) plus `currency`. Titles are not in it; a title edit is not a different purchase. The checkout card's own `cart` payload is enough to recompute it.

## Approvals, precisely

A grant is `treeship attest approval` with `allowed_actors=[<actor>]`, `allowed_actions=["commerce.tool.apply_change.intent"]`, `allowed_subjects=["change://<change_id>"]`, `max_uses=1`. The apply's intent receipt is signed with the grant's nonce and with `subject=change://<change_id>` **taken from the call's own arguments, never from the grant**; otherwise the scope check compares the grant with itself and passes for every change. The CLI reserves a use in the local Approval Use Journal before it signs, so a replay is refused before any receipt exists, and a grant for another change is refused by scope. `treeship approval uses <grant-id>` shows the one use; `treeship package verify` reports `PASS replay-local-journal ... use 1/1`.

`approving(toolset, approvals)` wraps the Agent SDK `MerchantToolset`'s `host_approve` / `host_clear` in place. The reference's mark is set first, so the gate behaves exactly as before even if minting fails. `enforce=True` on `approved(...)` holds an unproven apply *after* its intent receipt, in the reference's own held-outcome shape.

## Per runtime

- **Agent SDK.** The toolset is the approval surface; `approving()` covers it. One executor per toolset.
- **Messages API.** One executor per turn (one recorder each, all chained from the session root). The host owns the approval mark and calls `grant()` beside it.
- **Managed Agents.** One executor per MCP connection. The platform's prompt is the approval surface and the click is outside the process; an apply is receipted with no approval claim rather than an invented one. Arguments arrive as parsed pydantic models on this runtime; the digest handles them.

## Verify

```bash
treeship verify <artifact-id>                          # the chain from that receipt to the root
treeship package verify <session>.treeship             # every receipt, Merkle root, journal check
treeship approval uses <grant-id>                      # a grant's recorded uses
treeship session report                                # publish for a receipt page, deliberately
```

`--format json` gives a CI-consumable document with every check by artifact id and `chain_linkage_ok`.

## What a receipt does not prove

That the tool's answer was right, that the catalog was truthful, or that money moved. A wrong answer with a perfect receipt is still wrong; payment is the host's, and the receipt says what was handed off and what was placed. Treeship authenticates statements; it does not adjudicate commerce.

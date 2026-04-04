# Treeship -- Lobster Cash Ecosystem Listing

## Card (for lobster.cash/skills directory)

**Treeship**

Cryptographic proof of what your agent did.
Attestations for every payment. Privacy-preserving
ZK proofs for what you can't disclose.

**Includes**

- Signed receipt for every lobster.cash payment
- Tamper-evident chain of custody
- ZK proof: policy complied with (policy stays private)
- ZK proof: amount within limits (amount stays private)
- Verify anything at treeship.dev/verify

**Visit website**: https://treeship.dev

---

## Positioning

Every skill on the lobster.cash page executes payments.
Treeship is what proves they happened correctly.

Not competing with BlockRun, ClawCredit, Jupiter, or Purch.
Treeship makes all of them auditable.

What each skill gets from Treeship:

| Skill | What Treeship adds |
|-------|-------------------|
| BlockRun | Prove agent used only approved models, within budget |
| ClawCredit | Prove credit used for declared purposes, chain intact |
| Clawpay | Prove human approval happened before payment, nonce-bound |
| Jupiter | Prove swap within declared slippage and token list |
| Purch | Prove purchase from approved merchants, within price range |

---

## Message to Fede

Hey Fede -- I'm building Treeship, a cryptographic attestation layer
for agent workflows. We built a Lobster Cash compatible skill and
want to get listed in the ecosystem directory.

Every skill on your page executes payments. Treeship is what proves
they happened correctly -- signed receipts for every action, ZK proofs
for when you can't disclose the policy or the amount.

What's live:
- Signed receipt for every agent action (Ed25519, always on)
- ZK proof of policy compliance (Circom Groth16, proves without revealing)
- ZK proof of spend limits (proves amount within max without disclosing either)
- Full chain integrity proof (RISC Zero, background)
- One URL to verify everything: treeship.dev/verify/[session]

Integration docs: https://docs.treeship.dev/integrations/lobster-cash
GitHub: https://github.com/zerkerlabs/treeship/tree/main/packages/skills/lobster-cash
Blog: https://docs.treeship.dev/blog/lobster-cash-treeship-agent-payments

Would love to sync when you're ready to review the skill.

-- Amit, Zerker Labs

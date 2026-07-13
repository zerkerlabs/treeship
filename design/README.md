# design/

The token spine for Treeship's **product surfaces** (session reports, receipts,
certificates, the agent page, the embeddable badge, the CLI and the `treeship ui`
TUI). Not the marketing site. Design intent and rationale live in [`/DESIGN.md`](../DESIGN.md).

## The contract

`tokens.json` is the **single source of truth**. Everything in `generated/` is
code-generated from it and must never be hand-edited:

```
design/tokens.json ──▶ scripts/gen-design-tokens.py ──▶ design/generated/tokens.css
                                                         design/generated/tokens.rs
                                                         design/generated/tokens.ts
```

- `tokens.css` — CSS custom properties + `.ts-verdict-*` classes for the
  self-contained HTML receipt and certificate.
- `tokens.rs` — color consts + the `Verdict` enum (`word` / `glyph` / `color_hex`)
  for the CLI printer and the `treeship ui` TUI theme.
- `tokens.ts` — the same, for the hosted web verify page.

The load-bearing invariant: the **verdict vocabulary** (each trust state's one
`{word, color, glyph}`) is emitted identically to all three targets, so `revoked`
renders `✕ revoked` in fail-red on every surface — enforced by construction, not
by discipline.

## Workflow

Edit `tokens.json`, then regenerate:

```bash
python3 scripts/gen-design-tokens.py
```

CI / pre-commit should fail on drift:

```bash
python3 scripts/gen-design-tokens.py --check   # exit 1 if generated files are stale
```

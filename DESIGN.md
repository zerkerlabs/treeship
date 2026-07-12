# Design System — Treeship

The visual and interaction system for Treeship's **product surfaces** (session reports,
trust receipts, agent certificates, resolution/agent pages, the embeddable badge, the
CLI and the `treeship ui` TUI). Not the marketing site.

Read this before any visual or UI change. The verdict vocabulary and glyph alphabet
below are load-bearing: they must be identical across the HTML surfaces, the web verify
page, the CLI, and the TUI, or trust reads inconsistently and that is a trust bug, not a
style nit.

## Product context
- **What this is:** a portable cryptographic trust layer for AI agents. Every action and
  session produces a signed, offline-verifiable receipt; on top sit capability cards,
  agent certificates, a transparency log, profiles, and selective disclosure.
- **Who the surfaces are for:** the *recipient* of a receipt (a counterparty, an auditor,
  a customer) reads the human document; *agents* consume the JSON + deterministic verify.
  Design the document recipient-first; the shared vocabulary serves the machine surfaces.
- **Category:** developer trust infrastructure. Peers in spirit: Sigstore, Stripe
  receipts, GitHub "Verified", verifiable-credential wallets, Certificate Transparency.

## The one idea
Treeship is honest about the **gradient of certainty** ("structural-pass, not pass"). The
design renders *doubt without looking broken and confidence without overclaiming*. Every
surface is a **document of record**, legible at two distances: glance = the shape of trust,
lean-in = the full story, in one artifact. Model: the **nutrition label, not the credit
score** — never a single trust number/badge that hides the gradient.

Memorable thing (what someone should remember after seeing one): *"it told me exactly
what it could and couldn't prove."*

## Aesthetic direction
- **Direction:** document of record — editorial/certificate, precision-instrument. A
  **temperature fusion**: cool machined precision (graphite ink, mono faceplate,
  registration ticks) *on* warm paper (earthly, enterprise, kept-and-cited), with one
  warm metallic seal as the earthly root.
- **Decoration:** minimal→intentional. Hairline rules, not boxes. Depth from faint tint
  steps and a whisper of paper grain, never drop shadows. The ink-glyph **seal** is the
  one permitted ornament. **No guilloché / holographic texture** — that is security
  theater, the opposite of the honesty positioning.
- **Mood:** calm, premium, precise, honest. An instrument you trust, not a dashboard you
  monitor.

## Color
Warm paper ground + cool graphite ink; verdict semantics are the only place color earns
its keep, and color is *always* paired with a text label (print/grayscale/colorblind safe).

- **Paper (ground):** `#F1F0EA`  · **Panel:** `#EBEAE1`
- **Ink (text):** `#1F2329`  · **Muted:** `#5F646B`  · **Faint:** `#9B9B93`
- **Hairline:** `#DAD8CD`  · **Hairline (cool):** `#CBCED0`
- **Steel (cool accent — links, live elements):** `#37454F`
- **Bronze (the one warm metallic — the seal):** `#856733`, highlight `#C6A972`, shadow `#5E4923`
- **Verdict · pass:** `#3B6A4E`  · **Verdict · fail/revoked:** `#9F4230`  · **Verdict · warn/declared:** `#8F5E1F`
- **Dark surfaces:** avoided by default — these are documents of record, light. A dark
  variant, if ever needed, redesigns surfaces and drops verdict saturation ~15%.

## Verdict vocabulary (LOAD-BEARING — one source of truth)
Each trust state has exactly one canonical **word**, **color**, and **glyph**, identical
on every surface. No synonyms (`valid`/`ok`/`passed` for the same state is a bug).

| State | Word | Color | Glyph |
|---|---|---|---|
| Full pass | `full pass` | pass | `△` |
| Structural pass | `structural pass` | pass | `△` |
| Countersigned | `countersigned` | pass | `△` |
| Permitted | `permitted` | pass | `○` |
| Anchored | `anchored` | pass | `◇` |
| Declared / self-asserted | `declared` / `self-asserted` | warn | muted `△` |
| Pending | `pending` | muted | `·` |
| Revoked | `revoked` | fail | `✕` |
| Unverified | `unverified` | fail | `✕` |

**Glyph alphabet** (the brand product marks, reused — never invent a parallel set):
`△` treeship / identity · `○` gateway / capability · `◇` memory / receipt · `✕` guard /
revoked · plus `✓` plain-verified and dim `·` pending. One meaning each, forever.

Honesty rules encoded in the UI:
- **No trust score.** The verdict is a *label*, never a number.
- **Cap mechanic.** A single fatal flaw (revocation, self-asserted-only key) *caps* the
  top-line verdict; a "what limited this verdict" list states *why* the ceiling is there.
- **No silent gaps.** Every low state gets a calm affirmative label; absence never renders
  as blank (blank reads as a pass).
- **Selective disclosure shows the shape of what's hidden:** sealed/redacted rows + a
  `revealed N of M` ratio, never omitted rows.

## Typography
The serif/sans/mono split *is* the human-summary / machine-evidence seam made visual.
- **Display / masthead / verdict:** **Fraunces** (variable, opsz on, light optical weight
  300–400 for large sizes, 500 for emphasis). The certificate voice.
- **Body / fields / labels:** **Switzer** (400/500/600).
- **Cryptographic evidence only** (hashes, keys, ids, timestamps, faceplate): **mono** —
  Berkeley Mono preferred, JetBrains Mono if a free embeddable is needed. Always
  `font-variant-numeric: tabular-nums`.
- **Scale (session report):** masthead 33px Fraunces / verdict 31px Fraunces 300 /
  section labels 10px Switzer 600 tracked .22em uppercase / body 14.5px Switzer /
  mono 11px. `tnum` + `ss01` on the root.

## Spacing & layout
- **Base unit:** 8px. **Ladder:** 4 / 8 / 12 / 24 / 48 / 96. Generous *between* sections,
  tight *within* rows.
- **Layout:** single centered column, max ~676px, grid-disciplined within. The document
  *is* the page — no app chrome. Print = web (PDF fidelity is first-class:
  `print-color-adjust: exact`, `break-inside: avoid` on evidence rows).
- **Radius:** three values — `sm 5px` (chips/code), `md 12px` (cards/badge context), `full`
  (the badge pill). No bubble-radius-everything.

## The seal
A struck medallion, flat: a double bronze ring (highlight + shadow line), the graphite
`△` triangle, a steel inner triangle, a bronze center point. It replaces the gold
medallion; the glyph *class* encodes the attestation class. The one crafted ornament.

## Motion
Minimal-functional, with exactly one rationed beat: on a document's first paint it *rises*
(fade + 10px, ~700ms) and the seal's triangle *draws in* once, then nothing moves.
Respect `prefers-reduced-motion`. Never animate uncertainty — motion on a partial state
reads as spin.

## Cross-surface architecture (the spine)
Author tokens once in `design/tokens.json` (colors, type scale, spacing, and the verdict
vocabulary as `{word, color, glyph}` per state) and codegen to: `tokens.rs` (TUI theme +
CLI printer), `tokens.css` + embedded `@font-face` (the self-contained HTML receipt +
certificate), and `tokens.ts` (the web verify page). One renderer + one verifier across
the offline receipt and the hosted verify page. This is what makes `✕ revoked` identical
everywhere — the "consistent" bar enforced mechanically, not by discipline.

## Prototypes
- Session report (flagship): `~/.gstack/projects/zerkerlabs-treeship/designs/session-report-prototype.html` (v3).
- Verified-by-Treeship badge (+ states, in-context, expand card): the badge-showcase prototype.

## Decisions log
| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-07-12 | Initial system: paper/ink document-of-record, Fraunces + Switzer + mono, temperature-fusion (graphite precision on warm paper, bronze seal), verdict-vocabulary SSOT | From a 4-stream research synthesis (product strategy, design references, CLI/TUI, UI tech) + 3 flagship prototype iterations. Flagship = the session report; system verified to hold down to the embeddable badge. |

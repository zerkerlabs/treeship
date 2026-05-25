# Token Capture — design

**Status:** working markdown, not committed
**Last updated:** 2026-05-25

## The problem

A Treeship receipt should record how many tokens a model actually used — input and output — so the model-provenance claim ("this model did this work at this cost") is real. Getting an accurate count is harder than it looks, and three different wrong answers have been proposed:

1. **"Leave tokens empty"** (the current skill) — gives up; records nothing.
2. **"Read `input_tokens` from the transcript"** (an earlier recommendation) — wrong 98% of the time.
3. **"JSONL is unreliable, use a statusline script / proxy instead"** (a research report) — abandons a source that actually works.

All three are wrong for the same reason: they read (or refuse to read) one field. The correct answer is to **sum the right fields from the transcript.**

## What the data actually shows

Empirically, across 152 Claude Code transcripts / 17,447 assistant turns on a real machine:

| Field | Behavior |
|---|---|
| bare `input_tokens` | ≤ 10 on **98%** of turns (median **1**). It is only the *fresh, non-cached* input for the turn. Useless alone. |
| `cache_read_input_tokens` | accurate. The cached prefix (system prompt + history + tool defs) read this turn. |
| `cache_creation_input_tokens` | accurate. Newly-cached input this turn. |
| `input_tokens + cache_read + cache_creation` | **> 1000 on 99%** of turns (median **132,162**). This is the real input the model processed. |
| `output_tokens` | median 235, max ~18k. Mostly reliable, but may exclude extended-thinking tokens (unverified — see caveats). |

A single real turn:
```json
{ "input_tokens": 6, "cache_creation_input_tokens": 19721,
  "cache_read_input_tokens": 14906, "output_tokens": 316 }
// true input = 6 + 19721 + 14906 = 34,633
```

The "100x undercount" some research flagged is real for the bare field and fully resolved by summing. The data was never missing; it was distributed across three fields because Claude Code aggressively caches the prompt.

## The rule

```
input_tokens_total = input_tokens
                   + cache_read_input_tokens
                   + cache_creation_input_tokens
```

Never record bare `input_tokens` as "the input." Always sum. Preserve the breakdown (below) because the three components bill at different rates.

## Canonical usage schema (provider-neutral)

The receipt records one canonical shape per agent node, regardless of provider or runtime:

```jsonc
{
  "input_tokens": 34633,            // the SUMMED total — what the model processed
  "input_breakdown": {              // preserved because each bills differently
    "fresh": 6,
    "cache_read": 14906,
    "cache_creation": 19721
  },
  "output_tokens": 316,
  "output_complete": false,         // true only once thinking-token inclusion is verified
  "total_tokens": 34949,
  "model": "claude-opus-4-7",
  "provider": "anthropic",
  "source": "transcript"            // transcript | statusline | proxy | hook | estimate
}
```

Two fields carry the honesty:
- **`source`** — provenance of the number itself. A receipt must not blur actual (transcript/proxy) with estimate (count_tokens).
- **`output_complete`** — whether output is known to include thinking tokens. `false` means the value is a floor, not exact.

## Cross-provider normalization

The summing rule is Anthropic-shaped (it has cache fields). Other providers differ. Normalization is isolated to one table; the canonical schema above is what everything maps into.

| Provider | input (sum these) | output | notes |
|---|---|---|---|
| Anthropic | `input_tokens + cache_read_input_tokens + cache_creation_input_tokens` | `output_tokens` | cache fields are the bulk; bare input is the delta |
| OpenAI | `usage.prompt_tokens` (+ `prompt_tokens_details.cached_tokens` already included) | `usage.completion_tokens` | cached tokens are a *subset* of prompt_tokens, not additive |
| Google Gemini | `usageMetadata.promptTokenCount` | `usageMetadata.candidatesTokenCount` | cachedContentTokenCount is a subset |
| Cohere | `meta.billed_units.input_tokens` | `meta.billed_units.output_tokens` | |
| Ollama / llama.cpp | `prompt_eval_count` | `eval_count` | no caching concept |

**Critical per-provider subtlety:** Anthropic *adds* cache fields to bare input (they're separate). OpenAI/Gemini *nest* cached tokens *inside* the prompt total (they're a subset, do NOT add). Getting this wrong double-counts on OpenAI or under-counts on Anthropic. The normalization table must encode "additive vs subset" per provider.

## Two capture positions

**Position A — transcript reader (default, post-hoc).**
The runtime already received the provider `usage` object and wrote it to its transcript. Per-runtime adapter reads it, applies the provider's summing rule, emits canonical usage. Works offline, no API key, authoritative for what happened.
- Claude Code: `transcript_path` (from the hook payload) → JSONL → sum the three input fields
- OpenClaw: session transcript → normalized fields
- Others: per-runtime adapter

**Position B — attestation proxy (opt-in, inline).**
Treeship sits in the request path (OpenAI-compatible local proxy), reads the raw provider response `usage`, normalizes, attests, forwards. Guarantees capture regardless of runtime; adds a network hop. The right answer for runtimes that don't log usage.

## Cross-checks (not replacements)

The research surfaced two other accurate sources. They're useful as **validation**, not as the primary path:
- **Statusline script** — Claude Code pipes session-level context to a statusline script at ~1.0x to the API. Good for session totals and for validating the summed transcript figure.
- **Agent-tool PostToolUse hook** — for subagent turns, this hook *does* expose `usage` (input/output/cache). Useful for per-subagent granularity. (Regular-tool hooks don't expose usage yet — that's the legitimate upstream ask, FR #11008.)

If the summed-transcript input disagrees materially with the statusline session total, the receipt should surface the discrepancy rather than silently pick one.

## The output-token caveat (unresolved)

A research report claims `output_tokens` undercounts by 10-17x because it excludes extended-thinking tokens. This is **not yet verified** — it requires cross-checking transcript `output_tokens` against the API's actual billed `output_tokens`, which needs API billing access or the statusline session totals. Until verified:
- Treat output as a **floor**, mark `output_complete: false`
- Do not claim an exact output cost in a receipt
- Validating this is the prerequisite before output tokens are trusted as exact

## What the skill must say (the fix)

The current skill says "leave tokens empty" and references `count_tokens`. Replace with:
- **Input:** sum `input_tokens + cache_read_input_tokens + cache_creation_input_tokens` from the transcript. Bare `input_tokens` alone is wrong 98% of the time.
- **Output:** read `output_tokens`; treat as a floor pending thinking-token verification.
- **count_tokens:** an input-only *estimate* requiring an API key. Use for pre-flight cost estimation, never recorded in a receipt as actual.
- **Cross-provider:** the canonical schema + normalization table; mind additive (Anthropic) vs subset (OpenAI/Gemini) cache accounting.

## Honest status

| Claim | Status |
|---|---|
| Accurate input tokens | ✅ Solved — sum transcript fields (validated, 17k turns) |
| Cross-provider input | ✅ Solved — normalization table, mind additive-vs-subset |
| Accurate output tokens | ⚠️ Floor only — thinking-token inclusion unverified |
| Pre-flight estimate | ✅ count_tokens (Anthropic), input-only, estimate, needs key |
| Real-time push to Treeship without reading files | ⏸️ Upstream (FR #11008 for all-tool hooks) — convenience, not a gap |

## Implementation phases

1. **Transcript reader for Claude Code** — sum the three input fields, emit canonical usage on `agent.decision` / a new `agent.usage` event. Validate summed input against statusline on a few sessions.
2. **Resolve the output caveat** — cross-check transcript output vs billed/statusline; set `output_complete` accordingly.
3. **Cross-provider normalization table** — OpenAI, Gemini, Ollama adapters with additive-vs-subset encoded.
4. **OpenClaw + other runtime adapters.**
5. **Attestation proxy (Position B)** — separate, larger scope; guarantees capture for runtimes that don't log usage.

## The lesson baked in

Three confident answers ("leave empty," "read input_tokens," "JSONL unreliable") were all wrong, and one `python3` read of one transcript — then 152 of them — settled it. The data was in the file the whole time. Verify against the data before writing the guidance.

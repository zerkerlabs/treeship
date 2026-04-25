---
name: Feature request
about: Propose a new capability or a meaningful change to existing behavior
title: "[feature] "
labels: enhancement
---

## What's the user-facing problem?

<!--
Describe the situation, not the solution.
"Agents that produce a receipt every 100ms blow up the events.jsonl file" is a
problem; "add a buffered events writer" is a solution. Lead with the problem.
-->

## Why does the current shape not solve it?

<!--
Treeship is opinionated; we'd rather extend an existing concept than add a new
one. Show that you've looked at what exists. If there's a workaround today,
mention what it is and why it isn't enough.
-->

## Sketch of what you'd want

<!--
Optional. If you have a concrete API or CLI shape in mind, propose it. If you
don't, that's fine -- the maintainers will sketch it during triage.
-->

## Threat model / non-goals

<!--
Anything that should NOT be in scope, especially around verifier behavior or
on-the-wire format. Treeship's correctness rests on the receipt format being
boring and stable; new features that change it need extra care.
-->

---
description: Run bounded spec-first cycles on Treeship's workflow and graph proof layer
argument-hint: "[cycles: 1-3] [focus]"
---
Load and follow `.agents/skills/treeship-graph-loop/SKILL.md` completely.

Cycle budget: ${1:-1}
Focus: ${2:-the first unfinished implementation-order item}
Additional focus words: ${@:3}

Run only while this invocation is active. Do not claim background or between-turn execution. Stop at the skill's decision and safety gates.

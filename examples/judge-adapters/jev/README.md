# Jev behind the judge contract

`adapter.mjs` puts TypeSafe's Jev in Treeship's judge slot: it speaks
Treeship's [judge contract](https://docs.treeship.dev/cli/judge#any-judge-the-http-contract)
on one side and Jev's `POST /v1/systemone` on the other. No dependencies,
Node 18+.

```bash
TYPESAFE_API_KEY=… node examples/judge-adapters/jev/adapter.mjs &
treeship judge --tool Bash --input '{"command":"rm -rf /"}' \
  --judge-url http://127.0.0.1:8787 --attest --subject art_…
```

Every answer is signed as a `judgement.v1` receipt naming `jev-1.13.0`
(pinned; set `JEV_MODEL` to change it), provider `typesafe`, kind
`decision-model`, `replayable: false`. The Claude Code gate takes the same
URL in `TREESHIP_JUDGE`.

`run.sh` runs the adapter against `mock-jev.mjs`, a mock of the documented
request and response shapes, and is part of CI. This is an independent
implementation against TypeSafe's published API documentation; it has not
been run against the live service, and TypeSafe has not reviewed it.

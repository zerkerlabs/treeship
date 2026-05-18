# Integration parity tests

End-to-end smoke tests for every hook-based plugin in `integrations/`. Verifies every agent emits the right typed Treeship event with the right `--agent-name`.

Drives each plugin's hook scripts with fixture JSON payloads that simulate what the host CLI delivers on stdin. A mock `treeship` binary on PATH captures every CLI invocation so we can assert exact `session event` calls without a real Treeship install or running session.

## Run

```bash
integrations/tests/parity.sh                       # all plugins
integrations/tests/parity.sh kimi-code-plugin      # one plugin
```

Exit code 0 = all expectations met. Non-zero = failures.

## Layout

```
integrations/tests/
├── parity.sh                              # test runner
├── lib/mock-treeship.sh                   # fake treeship CLI
├── fixtures/<plugin>/<event>.json         # input on stdin
└── expectations/<plugin>/<event>.txt      # expected treeship calls
```

`<event>` matches the hook script name (e.g. `pre-tool-use-read` for `pre-tool-use.sh` driven by a "read" fixture).

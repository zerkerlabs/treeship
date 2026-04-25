<!--
Thanks for contributing to Treeship!

If your change is small (typo, doc tweak, single-file fix), feel free to delete
the sections below that don't apply. The intent is "tell the reviewer what they
need to know," not "fill in every box."
-->

## What

<!-- One or two sentences. The change, not the motivation. -->

## Why

<!-- The motivation. Link to the issue or thread that prompted this. -->

## How tested

<!--
Concrete evidence. Examples:
- `cargo test -p treeship-core` (177 passing, including new <test_name>)
- `./tests/cross-sdk/run.sh` (4/4 vectors agree)
- Smoke: ran `treeship session start && treeship wrap -- echo hi && treeship session close`,
  verified the resulting .treeship package
-->

## Risk and rollback

<!--
What could go wrong? How do we revert?
For docs / CI / build-tooling changes: usually "low risk, revert by `git revert`."
For changes to keys/, attestation/, event_log/, hub/: be more specific.
-->

## Checklist

- [ ] Lib tests pass (`cargo test -p treeship-core`)
- [ ] Cross-SDK contract tests pass (`./tests/cross-sdk/run.sh`) — required if you touched SDKs, CLI verify, or the receipt format
- [ ] `cargo fmt` + `cargo clippy --all-targets` clean (no new warnings)
- [ ] CHANGELOG.md updated under the next-release heading (or noted "no user-visible change")

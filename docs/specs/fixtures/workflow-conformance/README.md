# Workflow conformance golden reports

These fixtures pin the first `workflow.v1` conformance report before implementation.

- `declaration.json` is the shared minimal declaration.
- Each other file contains an abstract observed run and its expected report.
- IDs such as `art_inspect` and `chk_10` are readable placeholders. They are not signatures, hashes, or cryptographic test vectors.
- Reducer unit tests may deserialize these files. End-to-end verification tests must create real signed envelopes, inclusion proofs, and consistency proofs independently of the reducer under test.

The expected reports deliberately keep path, authority, loop limits, and declaration pre-existence as separate axes. An implementation must not collapse them into one score or upgrade adapter assertions to checked evidence.

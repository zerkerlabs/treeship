# Verifiable Intent interop

Both directions against the reference SDK at [agent-intent/verifiable-intent](https://github.com/agent-intent/verifiable-intent) (pinned in `.github/workflows/ci.yml`):

- the reference verifies a Layer 3 pair `treeship vi attest` signed, and reads past the `agent_attestation` claim as the spec requires of an unknown scheme;
- `treeship vi verify` verifies a Layer 2 the reference issued;
- a request outside the mandate is refused before anything is signed;
- one edited byte fails on both verifiers.

```bash
cargo build -p treeship-cli
git clone https://github.com/agent-intent/verifiable-intent /tmp/vi && pip install -e /tmp/vi pytest
TREESHIP_BIN=target/debug/treeship python -m pytest -q tests/vi-interop
```

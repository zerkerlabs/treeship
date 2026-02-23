# Contributing to Treeship

Thank you for your interest in contributing to the Treeship Protocol. This document outlines the process for contributing code, documentation, and protocol improvements.

## Code of Conduct

Contributors are expected to maintain a professional and respectful environment. Focus on technical merit and constructive feedback.

## Getting Started

### Prerequisites

- Node.js 20+
- Python 3.10+
- Docker (for sidecar development)
- Git

### Local Development

```bash
# Clone
git clone https://github.com/zerkerlabs/treeship.git
cd treeship

# CLI
cd packages/cli
npm install
npm link
treeship --version

# Python SDK
cd packages/sdk-python
python -m venv .venv
source .venv/bin/activate
pip install -e .

# Sidecar
cd packages/sidecar
docker build -t treeship-sidecar .
docker run -p 2019:2019 treeship-sidecar
```

### Running Tests

```bash
# CLI
cd packages/cli && npm test

# Python SDK
cd packages/sdk-python && pytest

# Sidecar
cd packages/sidecar && pytest
```

## Project Structure

```
treeship/
├── packages/
│   ├── cli/           # treeship-cli (npm)
│   ├── sidecar/       # Docker sidecar
│   ├── sdk-python/    # treeship-sdk (PyPI)
│   └── sdk-js/        # treeship (npm)
├── protocol/          # Protocol specification
├── integrations/      # Framework integrations
├── examples/          # Example projects
└── docs/              # Documentation
```

## Making Changes

### Branch Naming

- `feat/description` — New features
- `fix/description` — Bug fixes
- `docs/description` — Documentation
- `integration/framework` — New framework integration

### Commit Messages

Use conventional commits:

```
feat(cli): add export command
fix(sidecar): handle timeout gracefully
docs: update self-hosting guide
integration(crewai): add agent tool
```

### Pull Request Process

1. Fork and create your branch from `main`
2. Make changes
3. Add/update tests
4. Ensure CI passes
5. Submit PR with clear description

## Adding Framework Integrations

Framework integrations live in `integrations/`. Each integration is self-contained:

```
integrations/your-framework/
├── README.md           # How to use this integration
├── skill.py            # or skill.md, callback.py, etc.
└── example/            # Working example (optional)
```

Requirements:
1. Works end-to-end
2. Follows privacy contract (hash inputs, never send content)
3. Has its own README
4. Doesn't modify the framework itself

## Protocol Changes

The protocol spec in `protocol/SPEC.md` is stable. Breaking changes require:
1. GitHub issue with rationale
2. 90-day deprecation period
3. Migration guide
4. Major version bump

## Questions?

- Open a GitHub Discussion
- Check [docs.treeship.dev](https://docs.treeship.dev)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

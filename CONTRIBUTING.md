# Contributing to VaultScrub

Thanks for your interest in contributing! VaultScrub is a small,
zero-dependency project, and contributions that keep it that way are
especially welcome.

## Getting set up

```bash
git clone https://github.com/alireza0xj/javid0x1.git
cd javid0x1
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install   # optional, but recommended
```

## Development workflow

- Run the test suite: `pytest`
- Run the linter and formatter: `ruff check .` and `ruff format .`
- Run the type checker: `mypy src`
- Scan your changes: `vaultscrub scan src`

## Guidelines

- **Zero runtime dependencies.** New features must use only the standard library.
- **Python 3.9+ compatibility.** Avoid syntax and stdlib APIs newer than 3.9.
- **Tests for every detector.** If you add or change a detector, add positive
  and negative test cases in `tests/test_detectors.py`.
- **No real secrets in tests or docs.** Use obviously fake values (for example
  the AWS documentation example key) and masked previews in documentation.
- **Keep outputs safe.** Machine-readable output must never include raw
  secrets — use fingerprints and masked previews.

## Pull requests

1. Open an issue first for larger changes.
2. Keep PRs focused; one feature or fix per PR.
3. Make sure CI passes (tests, lint, typecheck, dogfood scan).
4. Update `CHANGELOG.md` under `[Unreleased]`.

## Releases

Maintainers cut releases by pushing a `vX.Y.Z` tag. The release workflow
builds the package, publishes it to PyPI via trusted publishing, and creates
a GitHub release with generated notes. Bump the version in both
`pyproject.toml` and `src/vaultscrub/_version.py`.

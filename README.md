<div align="center">

# VaultScrub

**Zero-dependency secret & PII redaction for Python applications, logs, and CI pipelines.**

[![CI](https://github.com/alireza0xj/javid0x1/actions/workflows/ci.yml/badge.svg)](https://github.com/alireza0xj/javid0x1/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/vaultscrub)](https://pypi.org/project/vaultscrub/)
[![Python](https://img.shields.io/pypi/pyversions/vaultscrub)](https://pypi.org/project/vaultscrub/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](https://github.com/alireza0xj/javid0x1)

</div>

VaultScrub finds and redacts leaked credentials and personal data — AWS keys, GitHub tokens, JWTs, private keys, payment cards, IBANs, emails, and high-entropy secrets — in application logs, configuration files, and CI output. It works as a Python library, a command-line tool, a pre-commit hook, and a CI gate with SARIF output for GitHub's Security tab.

## Why VaultScrub?

- **Runtime redaction, not just file scanning.** Most secret scanners look at files in a repo. VaultScrub also redacts secrets *inside your running application* — log lines, error messages, and API responses — before they reach disk or a third-party log service.
- **Zero dependencies.** Pure standard library. Nothing to audit, nothing to break, works in locked-down environments.
- **Validated detections.** Card numbers are checked with Luhn, IBANs with mod-97, and JWTs by decoding their headers — so you get fewer false positives than a regex-only tool.
- **CI-ready.** Exit codes, JSON and SARIF output, and a pre-commit hook make it easy to block secret leaks in pull requests.
- **Safe by default.** CLI and machine-readable outputs never print raw secrets — only masked previews and SHA-256 fingerprints.

## Installation

```bash
pip install vaultscrub
```

Requires Python 3.9 or newer.

## Quickstart

### Redact text in your application

```python
from vaultscrub import redact

line = "request failed for key AKIAIOSFODNN7EXAMPLE"
print(redact(line))
# request failed for key ***
```

### Find secrets programmatically

```python
from vaultscrub import find_secrets

for finding in find_secrets(log_line):
    print(finding.detector, finding.severity, finding.line, finding.column)
```

### Redact secrets from your logs

```python
import logging
from vaultscrub import RedactingFilter

handler = logging.StreamHandler()
handler.addFilter(RedactingFilter())  # redacts every record before it is emitted
```

Or use `RedactingFormatter` to redact the fully formatted line (covers `%(message)s`, exception text, and custom fields):

```python
handler.setFormatter(RedactingFormatter("%(asctime)s %(levelname)s %(message)s"))
```

### Scan a repository from the command line

```bash
vaultscrub scan .                 # human-readable report, exit 1 on findings
vaultscrub scan src --format sarif --fail-on high > results.sarif
vaultscrub redact config.yaml -o config.redacted.yaml
vaultscrub check "some text to inspect"
```

Directory scanning skips `.git`, virtualenvs, `node_modules`, build output, and tool caches by default. Use `--exclude` to add your own glob patterns.

### Block leaks in CI with GitHub Actions

```yaml
- name: Scan for secrets
  run: |
    pip install vaultscrub
    vaultscrub scan . --format sarif --fail-on high > results.sarif
- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

> The upload step needs `permissions: security-events: write` on the job.

### Block leaks before commit with pre-commit

```yaml
repos:
  - repo: https://github.com/alireza0xj/javid0x1
    rev: v0.1.0
    hooks:
      - id: vaultscrub
```

## Detectors

| Detector | Severity | What it finds |
|---|---|---|
| `private-key` | critical | PEM private key blocks |
| `aws-access-key` | critical | AWS access key IDs (`AKIA…`) |
| `github-token` | critical | GitHub personal access tokens |
| `slack-token` | critical | Slack API tokens |
| `stripe-live-key` | critical | Stripe live keys |
| `jwt` | critical | JSON Web Tokens (header-validated) |
| `aws-secret-key` | high | AWS secret keys (context-aware) |
| `google-api-key` | high | Google API keys |
| `openai-key` | high | OpenAI API keys |
| `discord-token` | high | Discord tokens |
| `credit-card` | high | Card numbers (Luhn-validated) |
| `iban` | high | IBANs (mod-97 validated) |
| `generic-secret` | high | `password = "…"` style assignments |
| `email` | medium | Email addresses (PII) |
| `stripe-test-key` | medium | Stripe test keys |
| `high-entropy` | medium | High-entropy strings (configurable) |

See [docs/detectors.md](docs/detectors.md) for details, tuning, and false-positive guidance.

## Configuration

```python
from vaultscrub import Redactor

redactor = Redactor(
    replacement="***",  # replacement text
    entropy_threshold=4.5,  # Shannon entropy cutoff
    min_entropy_length=20,  # shortest token the entropy detector considers
    use_entropy=True,  # disable for speed or fewer false positives
    allowlist={"AKIA..."},  # exact values that are never flagged
)
```

The high-entropy detector only considers mixed-case alphanumeric tokens, so plain hex hashes (for example SHA-256 digests in lockfiles) are not flagged.

## Security model

- VaultScrub is a **defense-in-depth** tool. It reduces accidental exposure; it does not replace a secrets manager, and it cannot detect every possible credential format.
- Machine-readable outputs (JSON, SARIF) contain **fingerprints and masked previews only** — never raw secrets.
- `Finding.value` holds the raw matched text for programmatic use. Treat findings like the secrets themselves.
- No network calls, no telemetry, no files written except where you ask (`redact -o`, `--in-place`).

## Comparison

| | VaultScrub | Gitleaks / TruffleHog | detect-secrets |
|---|---|---|---|
| Runtime log redaction | ✅ | ❌ | ❌ |
| Zero dependencies | ✅ | ❌ | ❌ |
| Python library API | ✅ | ❌ | ✅ |
| SARIF output | ✅ | ✅ | ❌ |
| Pre-commit hook | ✅ | ✅ | ✅ |

## Roadmap

- [ ] Additional detectors (cloud provider keys, database URLs, phone numbers)
- [ ] YAML/TOML-aware scanning that understands quoted values
- [ ] Baseline file for known false positives
- [ ] Respect `.gitignore` during directory scans
- [ ] GitHub Action wrapper

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports and feature requests are welcome — please use the issue templates.

## License

MIT — see [LICENSE](LICENSE).

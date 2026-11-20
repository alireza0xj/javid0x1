# Detectors

VaultScrub ships with 15 built-in detectors plus a generic high-entropy
detector. This page documents what each one finds, how it validates matches,
and how to tune it.

All examples below use obviously fake values. Masked previews (`AKIA…`)
are used in documentation so that docs themselves stay clean under scanning.

## Built-in detectors

| Detector | Severity | Validation | Notes |
|---|---|---|---|
| `private-key` | critical | — | Matches full PEM blocks, or a lone `BEGIN … PRIVATE KEY` header. |
| `aws-access-key` | critical | — | `AKIA`/`ASIA` followed by 16 uppercase alphanumerics. |
| `aws-secret-key` | high | Context | 40-character base64-ish string, only flagged when an AWS keyword (for example `aws_secret_access_key`) appears within 80 characters. |
| `github-token` | critical | — | Classic (`ghp_…`, `gho_…`, …) and fine-grained (`github_pat_…`) tokens. |
| `slack-token` | critical | — | `xox[baprs]-…` tokens. |
| `stripe-live-key` | critical | — | `sk_live_…` and `rk_live_…`. Publishable keys (`pk_…`) are intentionally not flagged. |
| `stripe-test-key` | medium | — | `sk_test_…` and `rk_test_…`. |
| `google-api-key` | high | — | `AIza…` keys. |
| `openai-key` | high | — | `sk-…` and `sk-proj-…` keys. |
| `jwt` | critical | Header | Three base64url segments; the header must decode to a JSON object containing `alg`. |
| `discord-token` | high | — | Three-part bot/user token shape. |
| `credit-card` | high | Luhn | 13–19 digits with optional spaces/dashes; must pass the Luhn check. |
| `iban` | high | Mod-97 | 15–34 characters; must pass the IBAN mod-97 check. |
| `email` | medium | — | Standard email shape (PII). |
| `generic-secret` | high | Literal | Assignments to well-known names (`password`, `secret`, `api_key`, `access_token`, `auth_token`, `client_secret`, `passwd`). Values shorter than 8 characters, placeholders (`changeme`, `example`, …), and code references (`os.getenv`) are ignored. Values containing a dot are ignored to avoid flagging code references. |
| `high-entropy` | medium | Entropy | Mixed-case alphanumeric tokens of at least `min_entropy_length` characters whose Shannon entropy is at least `entropy_threshold`. |

## Tuning

```python
from vaultscrub import Redactor

# Stricter: fewer false positives, may miss unusual formats.
strict = Redactor(entropy_threshold=5.0, min_entropy_length=24)

# Faster and quieter: disable the generic detector entirely.
quiet = Redactor(use_entropy=False)

# Known-safe values that should never be flagged.
with_allowlist = Redactor(allowlist={"AKIAIOSFODNN7EXAMPLE"})
```

On the command line:

```bash
vaultscrub scan . --entropy-threshold 5.0
vaultscrub scan . --no-entropy
vaultscrub scan . --exclude "vendor/*" --exclude "*.lock"
```

## False positives

The most common false positives, and what to do about them:

- **Hashes and checksums** (SHA-256 digests in lockfiles, `RECORD` files):
  the entropy detector requires mixed-case alphanumeric tokens, so plain hex
  digests are ignored. Exclude lockfiles with `--exclude "*.lock"` if needed.
- **Base64 blobs** (embedded images, certificates): these genuinely look like
  secrets. Exclude the containing files or disable the entropy detector.
- **Example keys in docs and tests**: exclude those paths, for example
  `--exclude "docs/*" --exclude "tests/*"`.
- **Email addresses in license files**: exclude `LICENSE*` files or use
  `--fail-on high` (emails are medium severity).

## Custom detectors

```python
import re
from vaultscrub import Redactor
from vaultscrub.detectors import Detector

detector = Detector(
    name="internal-token",
    severity="high",
    description="Internal service token",
    pattern=re.compile(r"svc_[A-Za-z0-9]{24}"),
)
redactor = Redactor(detectors=[detector], use_entropy=False)
print(redactor.redact("token svc_abcdefghijklmnopqrstuvwx"))
```

Custom detectors replace the built-in set. To extend the built-ins instead,
pass `list(DEFAULT_DETECTORS) + [detector]`.

# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |
| < 0.1   | ❌        |

## Reporting a vulnerability

Please report security issues **privately** using GitHub's private
vulnerability reporting: go to the
[Security tab](https://github.com/alireza0xj/javid0x1/security) of this
repository and choose **Report a vulnerability**.

Please include:

- A description of the issue and its impact
- Steps to reproduce (a minimal example is ideal)
- The VaultScrub version and Python version

Do **not** open a public issue for a suspected vulnerability, and do not
include real credentials in your report.

## What to expect

- Acknowledgement within 3 business days
- A fix or mitigation plan within 30 days for confirmed issues
- Credit in the release notes (unless you prefer to stay anonymous)

## Scope

VaultScrub is a detection and redaction tool. Reports about missed
detections (false negatives) for new credential formats are welcome as
feature requests, while issues in the redaction logic itself (secrets
leaking through `redact()`) are treated as security vulnerabilities.

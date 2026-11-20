# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-20

### Added

- Core redaction engine (`Redactor`, `redact`, `find_secrets`, `contains_secret`)
- 15 built-in detectors for cloud keys, tokens, JWTs, private keys, payment
  cards, IBANs, emails, and high-entropy strings
- File and directory scanning with binary/size guards, default excludes for
  virtualenvs and build output, and glob excludes
- `vaultscrub` CLI with `scan`, `redact`, and `check` commands
- JSON and SARIF output for CI and GitHub Security integration
- Standard-library logging integration (`RedactingFilter`, `RedactingFormatter`)
- Pre-commit hook and GitHub Actions examples
- Full test suite, CI with CodeQL and dependency review, and PyPI release
  automation

"""VaultScrub: zero-dependency secret and PII redaction for Python."""

from __future__ import annotations

from ._version import __version__
from .core import (
    Redactor,
    contains_secret,
    find_secrets,
    redact,
    scan_directory,
    scan_file,
    scan_paths,
)
from .detectors import DEFAULT_DETECTORS, Detector, Finding, severity_rank
from .integrations import RedactingFilter, RedactingFormatter

__all__ = [
    "DEFAULT_DETECTORS",
    "Detector",
    "Finding",
    "Redactor",
    "RedactingFilter",
    "RedactingFormatter",
    "__version__",
    "contains_secret",
    "find_secrets",
    "redact",
    "scan_directory",
    "scan_file",
    "scan_paths",
    "severity_rank",
]

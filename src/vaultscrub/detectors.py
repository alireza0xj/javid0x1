"""Secret and PII detectors for VaultScrub.

Each detector is a compiled regular expression plus optional validation
logic (for example a Luhn check for card numbers or a mod-97 check for
IBANs). Validation keeps false positives low while the patterns stay fast
enough for large log files.
"""

from __future__ import annotations

import base64
import json
import math
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass

__all__ = [
    "DEFAULT_DETECTORS",
    "SEVERITIES",
    "Detector",
    "Finding",
    "detect",
    "iban_valid",
    "luhn_check",
    "mask",
    "severity_rank",
    "shannon_entropy",
]

#: Severity levels ordered from lowest to highest.
SEVERITIES = ("low", "medium", "high", "critical")


def severity_rank(severity: str) -> int:
    """Return the rank of a severity level (higher means more severe)."""
    try:
        return SEVERITIES.index(severity)
    except ValueError:
        raise ValueError(f"Unknown severity: {severity!r}") from None


@dataclass(frozen=True)
class Finding:
    """A single secret or PII match inside a piece of text."""

    detector: str
    severity: str
    start: int
    end: int
    value: str
    line: int
    column: int
    redacted: str


@dataclass(frozen=True)
class Detector:
    """A named pattern that finds one kind of secret or PII."""

    name: str
    severity: str
    description: str
    pattern: re.Pattern[str]
    validator: Callable[[str], bool] | None = None
    group: int = 0
    context_keywords: tuple[str, ...] = ()
    context_window: int = 80


def mask(value: str, *, keep_start: int = 4, keep_end: int = 4) -> str:
    """Return a masked preview of a secret, keeping a few edge characters."""
    if len(value) <= keep_start + keep_end:
        return "*" * len(value)
    return value[:keep_start] + "*" * (len(value) - keep_start - keep_end) + value[-keep_end:]


def shannon_entropy(value: str) -> float:
    """Compute the Shannon entropy (in bits per character) of a string."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def luhn_check(value: str) -> bool:
    """Validate a card number with the Luhn algorithm."""
    digits = [int(char) for char in value if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def iban_valid(value: str) -> bool:
    """Validate an IBAN using the mod-97 check."""
    compact = re.sub(r"\s+", "", value).upper()
    if not 15 <= len(compact) <= 34:
        return False
    if not re.fullmatch(r"[A-Z]{2}[0-9]{2}[A-Z0-9]+", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    try:
        numeric = "".join(str(int(char, 36)) for char in rearranged)
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def jwt_valid(value: str) -> bool:
    """Check that a token looks like a JWT with a JSON header."""
    parts = value.split(".")
    if len(parts) != 3:
        return False
    header = parts[0]
    padded = header + "=" * (-len(header) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        data = json.loads(decoded.decode("utf-8"))
    except ValueError:
        return False
    return isinstance(data, dict) and "alg" in data


_PLACEHOLDERS = frozenset(
    {
        "password",
        "changeme",
        "change-me",
        "example",
        "placeholder",
        "your-password",
        "your_password",
        "your_api_key",
        "xxx",
        "xxxx",
        "test",
        "secret",
        "redacted",
        "none",
        "null",
        "todo",
        "fixme",
        "lorem",
        "ipsum",
        "sample",
        "demo",
    }
)


def _looks_like_literal(value: str) -> bool:
    """Reject placeholders and code references such as ``os.getenv``."""
    if "." in value:
        return False
    return value.strip().lower() not in _PLACEHOLDERS


def _detector(
    name: str,
    severity: str,
    description: str,
    pattern: str,
    *,
    flags: int = 0,
    validator: Callable[[str], bool] | None = None,
    group: int = 0,
    context_keywords: tuple[str, ...] = (),
    context_window: int = 80,
) -> Detector:
    return Detector(
        name=name,
        severity=severity,
        description=description,
        pattern=re.compile(pattern, flags),
        validator=validator,
        group=group,
        context_keywords=context_keywords,
        context_window=context_window,
    )


#: Built-in detectors, ordered from most to least specific.
DEFAULT_DETECTORS: tuple[Detector, ...] = (
    _detector(
        "private-key",
        "critical",
        "PEM-encoded private key block",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        r"[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        r"|-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
    ),
    _detector(
        "aws-access-key",
        "critical",
        "AWS access key ID",
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    ),
    _detector(
        "aws-secret-key",
        "high",
        "AWS secret access key (requires AWS context nearby)",
        r"\b[A-Za-z0-9/+=]{40}\b",
        context_keywords=(
            "aws_secret_access_key",
            "aws_secret",
            "secret_access_key",
            "secret key",
        ),
    ),
    _detector(
        "github-token",
        "critical",
        "GitHub personal access token",
        r"\b(?:gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
    ),
    _detector(
        "slack-token",
        "critical",
        "Slack API token",
        r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
    ),
    _detector(
        "stripe-live-key",
        "critical",
        "Stripe live secret or restricted key",
        r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b",
    ),
    _detector(
        "stripe-test-key",
        "medium",
        "Stripe test secret or restricted key",
        r"\b(?:sk|rk)_test_[A-Za-z0-9]{16,}\b",
    ),
    _detector(
        "google-api-key",
        "high",
        "Google API key",
        r"\bAIza[0-9A-Za-z\-_]{35}\b",
    ),
    _detector(
        "openai-key",
        "high",
        "OpenAI API key",
        r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b",
    ),
    _detector(
        "jwt",
        "critical",
        "JSON Web Token",
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        validator=jwt_valid,
    ),
    _detector(
        "discord-token",
        "high",
        "Discord bot or user token",
        r"\b[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b",
    ),
    _detector(
        "credit-card",
        "high",
        "Payment card number (Luhn-validated)",
        r"\b\d(?:[ -]?\d){12,18}\b",
        validator=luhn_check,
    ),
    _detector(
        "iban",
        "high",
        "International Bank Account Number (mod-97 validated)",
        r"\b[A-Z]{2}\d{2}(?: ?\d{4}){2,7} ?\d{0,4}\b",
        validator=iban_valid,
    ),
    _detector(
        "email",
        "medium",
        "Email address (PII)",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    ),
    _detector(
        "generic-secret",
        "high",
        "Hard-coded credential assigned to a well-known variable name",
        r"(?<![A-Za-z0-9])(?:password|passwd|secret|api[_-]?key"
        r"|access[_-]?token|auth[_-]?token|client[_-]?secret)"
        r"\s*[:=]\s*[\"']?([^\s\"';,()\[\]]{8,})",
        flags=re.IGNORECASE,
        validator=_looks_like_literal,
        group=1,
    ),
)

_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9+/=_-]{8,}")


def _line_and_column(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    line_start = text.rfind("\n", 0, offset) + 1
    return line, offset - line_start + 1


def _detect_high_entropy(
    text: str,
    existing: list[Finding],
    *,
    threshold: float,
    min_length: int,
) -> list[Finding]:
    results: list[Finding] = []
    for match in _TOKEN_PATTERN.finditer(text):
        token = match.group(0)
        if len(token) < min_length:
            continue
        if any(match.start() < finding.end and finding.start < match.end() for finding in existing):
            continue
        # Require mixed character classes: pure hex hashes (sha256 digests in
        # lockfiles, RECORD files, etc.) are the most common false positives
        # for entropy-based detection, while real credentials are almost
        # always mixed-case alphanumeric.
        if not (
            any(char.isupper() for char in token)
            and any(char.islower() for char in token)
            and any(char.isdigit() for char in token)
        ):
            continue
        if shannon_entropy(token) < threshold:
            continue
        line, column = _line_and_column(text, match.start())
        results.append(
            Finding(
                detector="high-entropy",
                severity="medium",
                start=match.start(),
                end=match.end(),
                value=token,
                line=line,
                column=column,
                redacted=mask(token),
            )
        )
    return results


def detect(
    text: str,
    detectors: tuple[Detector, ...] | list[Detector] = DEFAULT_DETECTORS,
    *,
    entropy_threshold: float = 4.5,
    min_entropy_length: int = 20,
    use_entropy: bool = True,
) -> list[Finding]:
    """Find secrets and PII in text using the given detectors."""
    findings: list[Finding] = []

    for detector in detectors:
        for match in detector.pattern.finditer(text):
            value = match.group(detector.group)
            if not value:
                continue
            if detector.validator is not None and not detector.validator(value):
                continue
            if detector.context_keywords:
                window_start = max(0, match.start() - detector.context_window)
                window_end = min(len(text), match.end() + detector.context_window)
                window = text[window_start:window_end].lower()
                if not any(keyword in window for keyword in detector.context_keywords):
                    continue
            start, end = match.span(detector.group)
            line, column = _line_and_column(text, start)
            findings.append(
                Finding(
                    detector=detector.name,
                    severity=detector.severity,
                    start=start,
                    end=end,
                    value=value,
                    line=line,
                    column=column,
                    redacted=mask(value),
                )
            )

    if use_entropy:
        findings.extend(
            _detect_high_entropy(
                text,
                findings,
                threshold=entropy_threshold,
                min_length=min_entropy_length,
            )
        )

    findings.sort(key=lambda finding: (finding.start, finding.end))
    return findings

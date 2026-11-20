"""Tests for the Redactor and module-level API."""

import base64
import json
import logging
import re

from vaultscrub import (
    RedactingFilter,
    RedactingFormatter,
    Redactor,
    contains_secret,
    find_secrets,
    redact,
)
from vaultscrub.detectors import Detector

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
ENTROPY_TOKEN = "aB3dEf7hIjKlMnOpQrStUvWx"


def _jwt() -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "1"}).encode())
    signature = base64.urlsafe_b64encode(b"signature-bytes")
    return ".".join(part.rstrip(b"=").decode() for part in (header, payload, signature))


def test_redact_replaces_secret():
    assert redact(f"key={AWS_KEY}") == "key=***"


def test_redact_clean_text_unchanged():
    text = "nothing to see here"
    assert redact(text) == text


def test_redact_multiple_secrets():
    text = f"a {AWS_KEY} b {AWS_KEY} c"
    assert redact(text) == "a *** b *** c"


def test_redact_custom_replacement():
    redactor = Redactor(replacement="[REDACTED]")
    assert redact(f"k {AWS_KEY}", redactor) == "k [REDACTED]"


def test_redact_jwt():
    token = _jwt()
    assert token not in redact(f"Bearer {token}")


def test_contains_secret():
    assert contains_secret(f"leak: {AWS_KEY}")
    assert not contains_secret("clean")


def test_find_secrets_returns_findings():
    findings = find_secrets(f"leak: {AWS_KEY}")
    assert len(findings) == 1
    assert findings[0].detector == "aws-access-key"
    assert findings[0].severity == "critical"


def test_allowlist():
    redactor = Redactor(allowlist={AWS_KEY})
    assert redactor.find(f"k {AWS_KEY}") == []
    assert redactor.redact(f"k {AWS_KEY}") == f"k {AWS_KEY}"


def test_entropy_can_be_disabled():
    assert Redactor().contains(ENTROPY_TOKEN)
    assert not Redactor(use_entropy=False).contains(ENTROPY_TOKEN)


def test_entropy_threshold_configurable():
    assert not Redactor(entropy_threshold=5.0).contains(ENTROPY_TOKEN)


def test_overlapping_findings_do_not_leak():
    # Both the AWS detector and the generic detector match the same span;
    # redaction must still cover the whole secret.
    text = f"aws_secret_access_key = {AWS_KEY}"
    redacted = redact(text)
    assert AWS_KEY not in redacted
    assert "***" in redacted


def test_custom_detectors():
    detector = Detector(
        name="custom",
        severity="low",
        description="custom test detector",
        pattern=re.compile(r"SECRET-\d+"),
    )
    redactor = Redactor(detectors=[detector], use_entropy=False)
    assert redactor.redact("code SECRET-123 here") == "code *** here"


def test_redacting_filter():
    record = logging.LogRecord("test", logging.INFO, __file__, 1, f"key {AWS_KEY}", (), None)
    assert RedactingFilter().filter(record) is True
    assert AWS_KEY not in record.getMessage()
    assert "***" in record.getMessage()


def test_redacting_formatter():
    formatter = RedactingFormatter("%(message)s")
    record = logging.LogRecord("test", logging.INFO, __file__, 1, f"key {AWS_KEY}", (), None)
    output = formatter.format(record)
    assert AWS_KEY not in output
    assert "***" in output

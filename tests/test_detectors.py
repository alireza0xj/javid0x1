"""Tests for the individual secret and PII detectors."""

import base64
import json

import pytest

from vaultscrub.detectors import (
    detect,
    iban_valid,
    luhn_check,
    mask,
    severity_rank,
    shannon_entropy,
)

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
ENTROPY_TOKEN = "aB3dEf7hIjKlMnOpQrStUvWx"


def _names(text: str) -> list[str]:
    return [finding.detector for finding in detect(text)]


def _jwt() -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "1"}).encode())
    signature = base64.urlsafe_b64encode(b"signature-bytes")
    return ".".join(part.rstrip(b"=").decode() for part in (header, payload, signature))


def test_aws_access_key_detected():
    assert "aws-access-key" in _names(f"key = {AWS_KEY}")


def test_aws_access_key_negative():
    assert "aws-access-key" not in _names("key = AKIA123")


def test_github_token_detected():
    token = "ghp_Ab3dEf7hIjKlMnOpQrStUvWxYz0123456789"
    assert "github-token" in _names(f"token {token}")


def test_private_key_detected():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    assert "private-key" in _names(text)


def test_jwt_detected():
    assert "jwt" in _names(f"Authorization: Bearer {_jwt()}")


def test_jwt_invalid_header_rejected():
    bad = "eyJub3QtanNvbg.signaturepart.signaturepart"
    assert "jwt" not in _names(bad)


def test_credit_card_luhn_valid():
    assert "credit-card" in _names("card 4242 4242 4242 4242")


def test_credit_card_luhn_invalid():
    assert "credit-card" not in _names("card 4242 4242 4242 4241")


def test_iban_valid():
    assert "iban" in _names("IBAN DE89 3704 0044 0532 0130 00")


def test_iban_invalid():
    assert "iban" not in _names("IBAN DE89 3704 0044 0532 0130 01")


def test_email_detected():
    assert "email" in _names("contact jane.doe@example.org for details")


def test_generic_password_detected():
    assert "generic-secret" in _names('password = "correct-horse-9"')


def test_generic_password_placeholder_ignored():
    assert "generic-secret" not in _names('password = "changeme"')


def test_generic_password_code_reference_ignored():
    assert "generic-secret" not in _names("password = os.getenv('DB_PASSWORD')")


def test_stripe_live_key():
    assert "stripe-live-key" in _names("key sk_live_51H7exampleexample1234")


def test_google_api_key():
    assert "google-api-key" in _names("key " + "AIza" + "x" * 35)


def test_openai_key():
    assert "openai-key" in _names("key sk-proj-Ab3dEf7hIjKlMnOpQrSt")


def test_slack_token():
    assert "slack-token" in _names("token xoxb-123456789012-abcdefghijkl")


def test_aws_secret_key_requires_context():
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert "aws-secret-key" not in _names(secret)
    assert "aws-secret-key" in _names(f"aws_secret_access_key = {secret}")


def test_high_entropy_token_detected():
    assert "high-entropy" in _names(f"token: {ENTROPY_TOKEN}")


def test_plain_text_not_flagged():
    assert detect("The quick brown fox jumps over the lazy dog.") == []


def test_mask():
    assert mask("abcdefghij") == "abcd**ghij"
    assert mask("short") == "*****"


def test_shannon_entropy():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("ab") == pytest.approx(1.0)


def test_luhn_check():
    assert luhn_check("4242 4242 4242 4242")
    assert not luhn_check("4242 4242 4242 4241")
    assert not luhn_check("123")


def test_iban_valid_function():
    assert iban_valid("DE89 3704 0044 0532 0130 00")
    assert not iban_valid("DE89 3704 0044 0532 0130 01")
    assert not iban_valid("not-an-iban")


def test_severity_rank():
    assert severity_rank("low") < severity_rank("critical")
    with pytest.raises(ValueError):
        severity_rank("bogus")


def test_finding_positions():
    findings = detect(f"line one\nkey {AWS_KEY} end")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.line == 2
    assert finding.column == 5
    assert finding.value == AWS_KEY

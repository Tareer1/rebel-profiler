"""Redaction pipeline tests (PDF 17: secrets never leave the system)."""

from __future__ import annotations

from rebel_profiler.core.redact import pattern_names, redact


def test_aws_key_redacted():
    text = "key AKIAIOSFODNN7EXAMPLE found in output"
    assert "AKIAIOSFODNN7EXAMPLE" not in redact(text)
    assert "[REDACTED]" in redact(text)


def test_private_key_block_redacted():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"
    assert "MIIEow" not in redact(text)


def test_bearer_token_redacted():
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.signature"
    red = redact(text)
    assert "eyJhbGciOiJIUzI1NiJ9" not in red


def test_kv_secret_redacted():
    text = "password=hunter2"
    assert "hunter2" not in redact(text)


def test_normal_text_untouched():
    text = "host lab.example.test has 22/tcp open ssh"
    assert redact(text) == text


def test_pattern_names_exposed():
    names = pattern_names()
    assert "aws_access_key" in names

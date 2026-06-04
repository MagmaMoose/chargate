import hashlib
import hmac

import jwt
import pytest

from chargate_api.config import Settings
from chargate_api.security import issue_ingest_token, verify_ingest_token, verify_webhook


def _sig(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_webhook_signature_accept_reject():
    body = b'{"a":1}'
    assert verify_webhook("s", body, _sig("s", body)) is True
    assert verify_webhook("s", body + b"x", _sig("s", body)) is False
    assert verify_webhook("s", body, None) is False
    assert verify_webhook("", body, _sig("s", body)) is False


def test_ingest_token_roundtrip():
    s = Settings(ingest_secret="topsecret")
    tok = issue_ingest_token(s, "scan-123")
    assert verify_ingest_token(s, tok) == "scan-123"


def test_ingest_token_rejects_wrong_secret():
    tok = issue_ingest_token(Settings(ingest_secret="a"), "scan-1")
    with pytest.raises(jwt.InvalidTokenError):
        verify_ingest_token(Settings(ingest_secret="b"), tok)

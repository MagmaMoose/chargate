"""Webhook signature verification and the short-lived per-scan ingest token."""
from __future__ import annotations

import hashlib
import hmac
import time

import jwt

from .config import Settings


def verify_webhook(secret: str, body: bytes, signature: str | None) -> bool:
    """Constant-time check of GitHub's X-Hub-Signature-256 header."""
    if not secret or not signature:
        return False
    mac = hmac.new(secret.encode(), body, hashlib.sha256)
    return hmac.compare_digest(f"sha256={mac.hexdigest()}", signature)


def issue_ingest_token(settings: Settings, scan_id: str) -> str:
    """A bearer the Actions runner uses exactly once to post results for one scan."""
    now = int(time.time())
    return jwt.encode(
        {"scan_id": scan_id, "iat": now, "exp": now + settings.ingest_token_ttl_seconds, "aud": "ingest"},
        settings.ingest_secret, algorithm="HS256",
    )


def verify_ingest_token(settings: Settings, token: str) -> str:
    """Return the scan_id the token authorises, or raise."""
    data = jwt.decode(token, settings.ingest_secret, algorithms=["HS256"], audience="ingest")
    return data["scan_id"]

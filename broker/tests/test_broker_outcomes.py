"""Every /token path emits exactly one structured outcome line, from a closed vocabulary.

This is the only observability the broker has. The client fails soft, so a broker that is
cleanly and consistently answering 403 produces no error metric and no red check anywhere —
the Lambda error alarm catches a raise, not a wrong answer. A CloudWatch metric filter keys
on these lines.

The vocabulary must stay CLOSED: /token is unauthenticated, so any caller-supplied value
reaching a log record is CodeQL py/log-injection.
"""

from __future__ import annotations

import json
import logging

import pytest

from app.broker import handle_token
from app.config import BrokerConfig

_CONFIG = BrokerConfig(app_id="1", private_key="-----BEGIN RSA PRIVATE KEY-----\nx\n")


async def _outcomes(caplog, body: bytes, **kwargs) -> list[str]:
    with caplog.at_level(logging.INFO, logger="chargate.broker"):
        await handle_token(body, **kwargs)
    return [
        json.loads(r.getMessage())["outcome"]
        for r in caplog.records
        if r.name == "chargate.broker" and r.levelno == logging.INFO
    ]


@pytest.mark.parametrize(
    "body,expected",
    [
        (b"not json", "invalid_json"),
        (b'["a list"]', "invalid_json"),
        (b'{"owner": "org"}', "missing_fields"),
        (b'{"oidcToken": "x", "owner": {"a": 1}, "repo": "r"}', "invalid_repository"),
        (b'{"oidcToken": "x", "owner": "org", "repo": "r/../evil"}', "invalid_repository"),
    ],
)
async def test_each_rejection_names_itself(caplog, body, expected):
    assert await _outcomes(caplog, body, config=_CONFIG) == [expected]


async def test_exactly_one_line_per_request(caplog):
    """Two lines for one request would double-count every CloudWatch metric built on these."""
    assert len(await _outcomes(caplog, b"not json", config=_CONFIG)) == 1


async def test_the_line_is_machine_readable(caplog):
    with caplog.at_level(logging.INFO, logger="chargate.broker"):
        await handle_token(b"not json", config=_CONFIG)
    record = next(r for r in caplog.records if r.levelno == logging.INFO)
    # Must parse as JSON — a metric filter pattern depends on the shape, not on substrings.
    assert json.loads(record.getMessage()) == {"outcome": "invalid_json"}


async def test_no_request_derived_text_reaches_the_log(caplog):
    """A CRLF payload in the repo name must not appear, forged or escaped, in any record."""
    payload = b'{"oidcToken": "x", "owner": "org", "repo": "r\\r\\nWARNING:root:forged"}'
    outcomes = await _outcomes(caplog, payload, config=_CONFIG)
    assert outcomes == ["invalid_repository"]
    assert not any("forged" in r.getMessage() for r in caplog.records)

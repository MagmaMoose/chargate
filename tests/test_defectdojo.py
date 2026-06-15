"""Unit tests for the DefectDojo client (chargate.defectdojo), no network."""

from __future__ import annotations

import io
import urllib.error
from pathlib import Path

import pytest

from chargate import defectdojo as dd


class _FakeResponse:
    def __init__(self, status: int, body: str):
        self.status = status
        self._body = body.encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def getcode(self) -> int:
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


class _FakeOpener:
    def __init__(self, response=None, exc: Exception | None = None):
        self.response = response
        self.exc = exc
        self.request = None
        self.timeout = None

    def open(self, request, timeout=None):
        self.request = request
        self.timeout = timeout
        if self.exc is not None:
            raise self.exc
        return self.response


@pytest.fixture
def sarif_file(tmp_path: Path) -> Path:
    path = tmp_path / "full.sarif"
    path.write_text('{"runs": []}', encoding="utf-8")
    return path


def _config(**kw) -> dd.DefectDojoConfig:
    base = {
        "base_url": "https://dd.example.com/",
        "token": "abc123",
        "product_name": "P",
        "engagement_name": "E",
    }
    base.update(kw)
    return dd.DefectDojoConfig(**base)


def test_endpoint_url_reimport_vs_import():
    assert _config(reimport=True).endpoint_url() == "https://dd.example.com/api/v2/reimport-scan/"
    assert _config(reimport=False).endpoint_url() == "https://dd.example.com/api/v2/import-scan/"


def test_build_form_fields_has_sarif_and_context():
    fields = dd.build_form_fields(_config(tags=("ci", "chargate")))
    assert fields["scan_type"] == "SARIF"
    assert fields["auto_create_context"] == "true"
    assert fields["close_old_findings"] == "true"
    assert fields["product_name"] == "P"
    assert fields["engagement_name"] == "E"
    assert fields["tags"] == "ci,chargate"


def test_encode_multipart_contains_fields_and_file():
    body = dd.encode_multipart(
        {"scan_type": "SARIF"}, "file", "r.sarif", b'{"runs":[]}', boundary="B"
    )
    text = body.decode("utf-8")
    assert "--B" in text
    assert 'name="scan_type"' in text
    assert 'filename="r.sarif"' in text
    assert '{"runs":[]}' in text


def test_import_success(sarif_file):
    opener = _FakeOpener(_FakeResponse(201, '{"test": 7}'))
    result = dd.import_sarif(_config(), sarif_file, opener=opener)
    assert result.ok
    assert result.status == 201
    assert result.response == {"test": 7}
    # Auth header + correct endpoint.
    assert opener.request.get_header("Authorization") == "Token abc123"
    assert opener.request.full_url.endswith("/api/v2/reimport-scan/")


def test_import_http_error_is_not_ok(sarif_file):
    http_error = urllib.error.HTTPError(
        "https://dd.example.com", 400, "Bad Request", {}, io.BytesIO(b'{"message":"nope"}')
    )
    result = dd.import_sarif(_config(), sarif_file, opener=_FakeOpener(exc=http_error))
    assert not result.ok
    assert result.status == 400
    assert "nope" in result.message


def test_import_connection_error_is_not_ok(sarif_file):
    result = dd.import_sarif(
        _config(), sarif_file, opener=_FakeOpener(exc=urllib.error.URLError("refused"))
    )
    assert not result.ok
    assert "connection error" in result.message


def test_import_missing_file_is_not_ok(tmp_path: Path):
    opener = _FakeOpener(_FakeResponse(201, "{}"))
    result = dd.import_sarif(_config(), tmp_path / "missing.sarif", opener=opener)
    assert not result.ok
    assert opener.request is None  # never attempted the upload


def test_import_uses_import_endpoint_when_not_reimport(sarif_file):
    opener = _FakeOpener(_FakeResponse(201, "{}"))
    dd.import_sarif(_config(reimport=False), sarif_file, opener=opener)
    assert opener.request.full_url.endswith("/api/v2/import-scan/")

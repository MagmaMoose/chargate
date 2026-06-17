"""Unit tests for the Dependency-Track client (chargate.dependencytrack), no network."""

from __future__ import annotations

import base64
import io
import json
import urllib.error
from pathlib import Path

import pytest

from chargate import dependencytrack as dt


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
def bom_file(tmp_path: Path) -> Path:
    path = tmp_path / "sbom.cdx.json"
    path.write_text('{"bomFormat": "CycloneDX", "components": []}', encoding="utf-8")
    return path


def _config(**kw) -> dt.DependencyTrackConfig:
    base = {
        "base_url": "https://dtrack.example.com/",
        "api_key": "key123",
        "project_name": "P",
        "project_version": "1.0.0",
    }
    base.update(kw)
    return dt.DependencyTrackConfig(**base)


def _payload(opener: _FakeOpener) -> dict:
    return json.loads(opener.request.data.decode("utf-8"))


def test_endpoint_url():
    assert _config().endpoint_url() == "https://dtrack.example.com/api/v1/bom"


def test_build_payload_name_version_autocreate():
    payload = dt.build_payload(_config(), b'{"bomFormat":"CycloneDX"}')
    assert payload["projectName"] == "P"
    assert payload["projectVersion"] == "1.0.0"
    assert payload["autoCreate"] is True
    # BOM is base64-encoded in the body.
    assert base64.b64decode(payload["bom"]) == b'{"bomFormat":"CycloneDX"}'
    assert "project" not in payload  # no UUID path


def test_build_payload_uuid_omits_name_and_autocreate():
    payload = dt.build_payload(
        _config(project_uuid="abc-uuid", project_name=None, project_version=None),
        b"{}",
    )
    assert payload["project"] == "abc-uuid"
    assert "projectName" not in payload
    assert "autoCreate" not in payload  # meaningless for an existing-UUID upload


def test_build_payload_parent_and_is_latest():
    payload = dt.build_payload(
        _config(parent_name="root", parent_version="2.0", is_latest=True), b"{}"
    )
    assert payload["parentName"] == "root"
    assert payload["parentVersion"] == "2.0"
    assert payload["isLatest"] is True


def test_encode_bom_strips_utf8_bom_marker():
    with_marker = b"\xef\xbb\xbf" + b'{"bomFormat":"CycloneDX"}'
    encoded = dt.encode_bom(with_marker)
    assert not encoded.startswith("77u/")  # the base64 of the UTF-8 BOM
    assert base64.b64decode(encoded) == b'{"bomFormat":"CycloneDX"}'


def test_build_request_uses_put_and_api_key_header(bom_file):
    request = dt.build_request(_config(), bom_file)
    assert request.method == "PUT"
    assert request.get_header("X-api-key") == "key123"
    assert request.full_url.endswith("/api/v1/bom")


def test_build_request_sets_identifying_user_agent(bom_file):
    # Not the default "Python-urllib/X.Y" — edge WAFs ban that by signature.
    ua = dt.build_request(_config(), bom_file).get_header("User-agent")
    assert ua and ua.startswith("chargate/")


def test_upload_success(bom_file):
    opener = _FakeOpener(_FakeResponse(200, '{"token": "t-42"}'))
    result = dt.upload_bom(_config(), bom_file, opener=opener)
    assert result.ok
    assert result.status == 200
    assert result.token == "t-42"
    assert opener.request.get_header("X-api-key") == "key123"
    assert opener.request.full_url.endswith("/api/v1/bom")
    assert _payload(opener)["projectName"] == "P"


def test_upload_http_error_is_not_ok(bom_file):
    http_error = urllib.error.HTTPError(
        "https://dtrack.example.com", 401, "Unauthorized", {}, io.BytesIO(b'{"message":"bad key"}')
    )
    result = dt.upload_bom(_config(), bom_file, opener=_FakeOpener(exc=http_error))
    assert not result.ok
    assert result.status == 401
    assert "bad key" in result.message


def test_upload_connection_error_is_not_ok(bom_file):
    result = dt.upload_bom(
        _config(), bom_file, opener=_FakeOpener(exc=urllib.error.URLError("refused"))
    )
    assert not result.ok
    assert "connection error" in result.message


def test_upload_missing_file_is_not_ok(tmp_path: Path):
    opener = _FakeOpener(_FakeResponse(200, "{}"))
    result = dt.upload_bom(_config(), tmp_path / "missing.json", opener=opener)
    assert not result.ok
    assert opener.request is None  # never attempted the upload

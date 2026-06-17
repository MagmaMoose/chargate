"""Unit tests for the Dependency-Track client (chargate.dependencytrack), no network."""

from __future__ import annotations

import io
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


def test_endpoint_url():
    assert _config().endpoint_url() == "https://dtrack.example.com/api/v1/bom"


def test_build_form_fields_name_version_autocreate():
    fields = dt.build_form_fields(_config())
    assert fields["projectName"] == "P"
    assert fields["projectVersion"] == "1.0.0"
    assert fields["autoCreate"] == "true"
    assert "project" not in fields  # no UUID path


def test_build_form_fields_uuid_omits_name_and_autocreate():
    fields = dt.build_form_fields(
        _config(project_uuid="abc-uuid", project_name=None, project_version=None)
    )
    assert fields["project"] == "abc-uuid"
    assert "projectName" not in fields
    assert "autoCreate" not in fields  # meaningless for an existing-UUID upload


def test_build_form_fields_parent_and_is_latest():
    fields = dt.build_form_fields(_config(parent_name="root", parent_version="2.0", is_latest=True))
    assert fields["parentName"] == "root"
    assert fields["parentVersion"] == "2.0"
    assert fields["isLatest"] == "true"


def test_strip_bom_marker():
    assert dt.strip_bom_marker(b"\xef\xbb\xbf{}") == b"{}"
    assert dt.strip_bom_marker(b"{}") == b"{}"


def test_encode_multipart_sends_raw_bom_not_base64():
    body = dt.encode_multipart(
        {"projectName": "P"}, "bom", "sbom.json", b'{"bomFormat":"CycloneDX"}', boundary="B"
    )
    text = body.decode("utf-8")
    assert "--B" in text
    assert 'name="projectName"' in text
    assert 'name="bom"; filename="sbom.json"' in text
    assert '{"bomFormat":"CycloneDX"}' in text  # raw bytes, not base64


def test_build_request_uses_post_multipart_and_api_key(bom_file):
    request = dt.build_request(_config(), bom_file)
    assert request.method == "POST"
    assert request.get_header("X-api-key") == "key123"
    assert request.get_header("Content-type").startswith("multipart/form-data; boundary=")
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
    body = opener.request.data.decode("utf-8")
    assert 'name="projectName"' in body
    assert "P" in body


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

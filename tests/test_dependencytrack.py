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
    """Records every request; returns ``responses`` in order, else a single response.

    ``upload_bom`` may now make two calls (the BOM POST, then a project lookup), so
    the opener keeps the full request list and ``.request`` is the first (the upload).
    """

    def __init__(self, response=None, exc: Exception | None = None, responses=None):
        self.response = response
        self._responses = list(responses) if responses is not None else None
        self.exc = exc
        self.requests: list = []
        self.timeout = None

    @property
    def request(self):
        return self.requests[0] if self.requests else None

    def open(self, request, timeout=None):
        self.requests.append(request)
        self.timeout = timeout
        if self.exc is not None:
            raise self.exc
        if self._responses is not None:
            item = self._responses[min(len(self.requests) - 1, len(self._responses) - 1)]
        else:
            item = self.response
        if isinstance(item, Exception):
            raise item  # a per-call failure (e.g. a 403 on the lookup)
        return item


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


def test_upload_resolves_project_url_via_lookup(bom_file):
    # Upload returns a token; a follow-up lookup resolves the UUID for the UI link.
    opener = _FakeOpener(
        responses=[_FakeResponse(200, '{"token": "t-1"}'), _FakeResponse(200, '{"uuid": "u-9"}')]
    )
    result = dt.upload_bom(_config(), bom_file, opener=opener)
    assert result.ok
    assert result.project_url == "https://dtrack.example.com/projects/u-9"
    # Second call is the lookup, carrying the project name + version.
    lookup = opener.requests[1]
    assert "/api/v1/project/lookup" in lookup.full_url
    assert "name=P" in lookup.full_url and "version=1.0.0" in lookup.full_url


def test_upload_project_url_from_provided_uuid_skips_lookup(bom_file):
    opener = _FakeOpener(_FakeResponse(200, '{"token": "t-2"}'))
    result = dt.upload_bom(_config(project_uuid="abc-uuid"), bom_file, opener=opener)
    assert result.project_url == "https://dtrack.example.com/projects/abc-uuid"
    assert len(opener.requests) == 1  # UUID known up front — no lookup call


def test_upload_lookup_miss_leaves_project_url_none(bom_file):
    opener = _FakeOpener(
        responses=[_FakeResponse(200, '{"token": "t-3"}'), _FakeResponse(200, "{}")]
    )
    result = dt.upload_bom(_config(), bom_file, opener=opener)
    assert result.ok  # upload still succeeded
    assert result.project_url is None


def test_upload_lookup_forbidden_hints_view_portfolio(bom_file):
    # The BOM POST succeeds; the project lookup is 403 (key lacks VIEW_PORTFOLIO).
    forbidden = urllib.error.HTTPError(
        "https://dtrack.example.com/api/v1/project/lookup",
        403,
        "Forbidden",
        {},
        io.BytesIO(b"{}"),
    )
    opener = _FakeOpener(responses=[_FakeResponse(200, '{"token": "t-4"}'), forbidden])
    result = dt.upload_bom(_config(), bom_file, opener=opener)
    assert result.ok  # the upload itself is unaffected
    assert result.project_url is None
    assert "VIEW_PORTFOLIO" in result.message  # the reason is surfaced, not silent


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

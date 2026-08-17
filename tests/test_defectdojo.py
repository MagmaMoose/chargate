"""Unit tests for the DefectDojo client (chargate.defectdojo), no network."""

from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path

import pytest

from chargate import __version__
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


class _SequenceOpener:
    """Answers each ``open()`` from a queue, so a retry can get a different outcome."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.requests: list = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _mismatch_error() -> urllib.error.HTTPError:
    """The exact 400 DefectDojo returned for chargate's own engagement (run 31548114084)."""
    body = (
        b'{"message":"[\\"Test type mismatch: Test 1 has test_type \'KICS Scan (SARIF)\', '
        b"but the report contains test_type 'shellcheck (MegaLinter BASH_SHELLCHECK) "
        b'Scan (SARIF)\'. Reimport with matching test_type or create a new test.\\"]"}'
    )
    return urllib.error.HTTPError(
        "https://dd.example.com", 400, "Bad Request", {}, io.BytesIO(body)
    )


def _endpoints(opener: _SequenceOpener) -> list[str]:
    return [r.full_url.rsplit("/api/v2/", 1)[-1] for r in opener.requests]


@pytest.fixture
def sarif_file(tmp_path: Path) -> Path:
    path = tmp_path / "full.sarif"
    path.write_text('{"runs": []}', encoding="utf-8")
    return path


@pytest.fixture
def merged_sarif_file(tmp_path: Path) -> Path:
    """A MegaLinter-shaped merged report: several tools, one run each."""
    path = tmp_path / "megalinter-report.sarif"
    path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "shellcheck (MegaLinter BASH_SHELLCHECK)"}},
                        "results": [{"ruleId": "SC2086"}],
                    },
                    {
                        "tool": {"driver": {"name": "bandit (MegaLinter PYTHON_BANDIT)"}},
                        "results": [{"ruleId": "B404"}],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
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


def test_build_form_fields_includes_product_type_for_autocreate():
    fields = dd.build_form_fields(_config(product_type_name="Research and Development"))
    assert fields["product_type_name"] == "Research and Development"


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


def test_test_url_from_response():
    assert (
        dd.test_url("https://dd.example.com/", {"test_id": 12}) == "https://dd.example.com/test/12"
    )
    assert dd.test_url("https://dd.example.com", {"test": "8"}) == "https://dd.example.com/test/8"
    assert dd.test_url("https://dd.example.com", {"test": "nope"}) is None
    assert dd.test_url("https://dd.example.com", {}) is None
    assert dd.test_url("https://dd.example.com", None) is None


def test_import_success_sets_test_url(sarif_file):
    opener = _FakeOpener(_FakeResponse(201, '{"test_id": 42}'))
    result = dd.import_sarif(_config(), sarif_file, opener=opener)
    assert result.ok
    assert result.url == "https://dd.example.com/test/42"


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


def test_build_request_sets_identifying_user_agent(sarif_file):
    # Not the default "Python-urllib/X.Y" — edge WAFs ban that by signature.
    ua = dd.build_request(_config(), sarif_file).get_header("User-agent")
    assert ua and ua.startswith("chargate/")


# --- DefectDojo types the Test from runs[0] only -----------------------------------
#
# Regression tests for the sink going silently dead. DefectDojo's SARIF parser builds one
# ParserTest per run and the importer takes the Test's type from `tests[0]` alone, then
# rejects a reimport whose derived type differs from the Test already in the engagement.
# Against MegaLinter's merged report that first run is whichever linter emitted first —
# a property of the PR's file types, not of the repo — so chargate stamps its own run in
# front, and retries once via import-scan when an older Test is already in the way.


def _uploaded_sarif(request) -> dict:
    """The SARIF actually sent, pulled back out of the multipart body."""
    body = request.data.decode("utf-8")
    marker = "Content-Type: application/json\r\n\r\n"
    start = body.index(marker) + len(marker)
    return json.loads(body[start : body.rindex("\r\n--")])


def _run_names(sarif: dict) -> list[str]:
    return [run["tool"]["driver"]["name"] for run in sarif["runs"]]


def test_upload_prepends_chargate_identity_run(merged_sarif_file):
    opener = _FakeOpener(_FakeResponse(201, '{"test_id": 5}'))
    dd.import_sarif(_config(), merged_sarif_file, opener=opener)
    sent = _uploaded_sarif(opener.request)

    # DefectDojo names the Test after runs[0] and only runs[0].
    assert _run_names(sent)[0] == "chargate"
    # ...but aggregates findings from every run, so nothing may be dropped or reordered.
    assert _run_names(sent)[1:] == [
        "shellcheck (MegaLinter BASH_SHELLCHECK)",
        "bandit (MegaLinter PYTHON_BANDIT)",
    ]
    assert sent["runs"][0]["results"] == []
    assert sent["runs"][0]["tool"]["driver"]["version"] == __version__

    # The artifact on disk is the linters' report, unedited.
    assert _run_names(json.loads(merged_sarif_file.read_text(encoding="utf-8")))[0] != "chargate"


def test_identity_run_is_stable_when_the_first_linter_changes(tmp_path: Path):
    # The bug: an incremental PR only runs the linters its changed files match, so the
    # merged report's first run moves. Before the identity run, these two uploads derived
    # two different DefectDojo test types and the second reimport 400'd.
    names = []
    for first in ("shellcheck (MegaLinter BASH_SHELLCHECK)", "eslint (MegaLinter JAVASCRIPT_ES)"):
        path = tmp_path / f"{first[:4]}.sarif"
        path.write_text(
            json.dumps({"runs": [{"tool": {"driver": {"name": first}}, "results": []}]}),
            encoding="utf-8",
        )
        opener = _FakeOpener(_FakeResponse(201, "{}"))
        dd.import_sarif(_config(), path, opener=opener)
        names.append(_run_names(_uploaded_sarif(opener.request))[0])
    assert names == ["chargate", "chargate"]


def test_with_identity_run_is_idempotent_and_passes_through_what_it_cannot_parse():
    stamped = dd.with_identity_run(b'{"runs": []}')
    assert dd.with_identity_run(stamped) == stamped  # re-uploading a --sarif-out copy
    for raw in (b"not json at all", b"[1, 2]", b"{}", b'{"runs": "nope"}'):
        assert dd.with_identity_run(raw) == raw


def test_reimport_test_type_mismatch_retries_against_import_scan(merged_sarif_file):
    opener = _SequenceOpener(_mismatch_error(), _FakeResponse(201, '{"test": 9}'))
    result = dd.import_sarif(_config(), merged_sarif_file, opener=opener)

    assert _endpoints(opener) == ["reimport-scan/", "import-scan/"]
    assert result.ok
    assert result.url == "https://dd.example.com/test/9"
    assert "new test" in result.message
    assert "Test type mismatch" in result.message  # why, verbatim from DefectDojo


def test_reimport_retries_only_for_the_test_type_mismatch(merged_sarif_file):
    # A 400 for any other reason is a real error; a second Test would only hide it.
    other = urllib.error.HTTPError(
        "https://dd.example.com",
        400,
        "Bad Request",
        {},
        io.BytesIO(b'{"message":"no such product"}'),
    )
    opener = _SequenceOpener(other, _FakeResponse(201, "{}"))
    result = dd.import_sarif(_config(), merged_sarif_file, opener=opener)
    assert _endpoints(opener) == ["reimport-scan/"]
    assert not result.ok


def test_import_scan_never_retries(merged_sarif_file):
    opener = _SequenceOpener(_mismatch_error(), _FakeResponse(201, "{}"))
    result = dd.import_sarif(_config(reimport=False), merged_sarif_file, opener=opener)
    assert _endpoints(opener) == ["import-scan/"]
    assert not result.ok


def test_failed_fallback_reports_both_reasons(merged_sarif_file):
    server_error = urllib.error.HTTPError(
        "https://dd.example.com", 500, "Server Error", {}, io.BytesIO(b"boom")
    )
    opener = _SequenceOpener(_mismatch_error(), server_error)
    result = dd.import_sarif(_config(), merged_sarif_file, opener=opener)
    assert not result.ok
    assert "reimport rejected" in result.message
    assert "import-scan fallback also failed" in result.message
    assert "HTTP 500" in result.message

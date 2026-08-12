"""DefectDojo import client — optional, first-class, and failure-isolated.

Always ships the **full** (unfiltered) SARIF so the security system sees the
complete picture, including inherited debt. Uses ``reimport-scan`` by default
(recurring gate → one Test per engagement, with ``close_old_findings`` mitigating
findings that disappear), falling back to ``import-scan`` when DefectDojo refuses
the reimport because the target Test was typed by a different tool.

Two mechanisms in this module exist solely to keep that reimport working against a
*merged, multi-tool* SARIF; both are described in full at :func:`identity_run` and
:func:`import_sarif`. In short: DefectDojo's SARIF parser is a "dynamic test type"
parser that names the Test after ``runs[0].tool.driver.name`` **only**, and MegaLinter's
merged report has no stable first run — so chargate prepends a findings-free run naming
itself, and retries once against ``import-scan`` if an older, differently-typed Test is
already in the way.

Stdlib only (urllib): no third-party HTTP dependency. By contract a DefectDojo
failure NEVER raises out of :func:`import_sarif` — it returns a result with
``ok=False`` so the caller can log-and-continue without failing the gate.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from chargate import __version__

_PROJECT_URL = "https://github.com/MagmaMoose/chargate"
_BOUNDARY = "----chargateDefectDojoBoundary7MA4YWxkTrZu0gW"
# Identify ourselves instead of the default "Python-urllib/X.Y", which edge WAFs
# (e.g. Cloudflare Bot Fight Mode / error 1010) commonly ban by client signature.
_USER_AGENT = f"chargate/{__version__} (+{_PROJECT_URL})"

# The tool name DefectDojo will derive this report's Test_Type from. See identity_run().
IDENTITY_TOOL_NAME = "chargate"

# Substring of the ValidationError DefectDojo raises from
# BaseImporter.consolidate_dynamic_tests when a reimport's derived Test_Type does not
# match the one already on the target Test. Matched case-insensitively on the 400 body.
_TEST_TYPE_MISMATCH = "test type mismatch"


@dataclass(frozen=True)
class DefectDojoConfig:
    base_url: str
    token: str
    product_name: str | None = None
    product_type_name: str | None = None
    engagement_name: str | None = None
    engagement_id: int | None = None
    scan_type: str = "SARIF"
    reimport: bool = True
    close_old_findings: bool = True
    auto_create_context: bool = True
    minimum_severity: str = "Info"
    active: bool = True
    verified: bool = False
    test_title: str | None = None
    tags: tuple[str, ...] = ()
    verify_ssl: bool = True
    timeout: float = 60.0

    def endpoint_url(self) -> str:
        path = "reimport-scan" if self.reimport else "import-scan"
        return f"{self.base_url.rstrip('/')}/api/v2/{path}/"


@dataclass(frozen=True)
class DefectDojoResult:
    ok: bool
    endpoint: str
    status: int | None = None
    message: str = ""
    response: dict[str, Any] | None = None
    url: str | None = None  # link to the imported Test in the DefectDojo UI


def _bool(value: bool) -> str:
    return "true" if value else "false"


def test_url(base_url: str, response: dict[str, Any] | None) -> str | None:
    """Build a UI link to the imported Test from an import/reimport response.

    The (re)import-scan responses carry the test id under ``test_id`` (reimport) or
    ``test`` (import); the Test page is ``{base}/test/{id}``. Returns None when no
    numeric id is present.
    """
    if not isinstance(response, dict):
        return None
    raw = response.get("test_id")
    if raw is None:
        raw = response.get("test")
    if isinstance(raw, bool) or not isinstance(raw, (int, str)):
        return None
    test_id = str(raw).strip()
    if not test_id.isdigit():
        return None
    return f"{base_url.rstrip('/')}/test/{test_id}"


def build_form_fields(config: DefectDojoConfig) -> dict[str, str]:
    """The non-file form fields for the import/reimport request."""
    fields: dict[str, str] = {
        "scan_type": config.scan_type,
        "active": _bool(config.active),
        "verified": _bool(config.verified),
        "close_old_findings": _bool(config.close_old_findings),
        "auto_create_context": _bool(config.auto_create_context),
        "minimum_severity": config.minimum_severity,
    }
    if config.product_type_name:
        # Required for auto_create_context to create a not-yet-existing product.
        fields["product_type_name"] = config.product_type_name
    if config.product_name:
        fields["product_name"] = config.product_name
    if config.engagement_name:
        fields["engagement_name"] = config.engagement_name
    if config.engagement_id is not None:
        fields["engagement"] = str(config.engagement_id)
    if config.test_title:
        fields["test_title"] = config.test_title
    if config.tags:
        # DefectDojo accepts repeated tag fields; comma-join is also accepted.
        fields["tags"] = ",".join(config.tags)
    return fields


def encode_multipart(
    fields: dict[str, str],
    file_field: str,
    filename: str,
    file_bytes: bytes,
    boundary: str = _BOUNDARY,
) -> bytes:
    """Encode ``fields`` plus one file as a multipart/form-data body."""
    parts: list[bytes] = []
    for name, value in fields.items():
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        parts.append(f"{value}\r\n".encode())
    parts.append(f"--{boundary}\r\n".encode())
    parts.append(
        f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'.encode()
    )
    parts.append(b"Content-Type: application/json\r\n\r\n")
    parts.append(file_bytes)
    parts.append(b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts)


def identity_run() -> dict[str, Any]:
    """A findings-free SARIF run naming chargate as the tool that produced the report."""
    return {
        "tool": {
            "driver": {
                "name": IDENTITY_TOOL_NAME,
                "version": __version__,
                "informationUri": _PROJECT_URL,
            }
        },
        "results": [],
    }


def with_identity_run(sarif_bytes: bytes) -> bytes:
    """Return the SARIF with :func:`identity_run` first, so DefectDojo types it stably.

    DefectDojo's SARIF parser is a *dynamic test type* parser: ``get_tests()`` builds one
    ``ParserTest`` per SARIF run named after ``run.tool.driver.name``, and the importer
    then does ``test_raw = tests[0]`` — it takes the Test's type from the **first run
    only**, while still aggregating findings from every run. On reimport it compares that
    derived name against the Test already in the engagement and rejects the upload with
    HTTP 400 ``Test type mismatch`` if they differ.

    chargate ships MegaLinter's *merged* report, where run[0] is whichever linter happened
    to emit a SARIF first — and which linters emit at all depends on the file types in the
    diff, because the action's ``incremental`` default makes the file-based linters run
    only over changed files. So the derived name is not a property of the repo, it is a
    property of the PR: a JS-only PR types the Test after eslint, the next one after
    shellcheck, and the reimport 400s. That is not hypothetical — chargate's own
    engagement was typed ``KICS Scan (SARIF)`` by the months of empty reports this branch
    fixes, so the first upload carrying real findings was rejected with
    ``Test 1 has test_type 'KICS Scan (SARIF)', but the report contains test_type
    'shellcheck (MegaLinter BASH_SHELLCHECK) Scan (SARIF)'`` and the full SARIF silently
    never landed — the exact "sink looks configured, ships nothing" failure this branch
    exists to end.

    Prepending one run of our own makes the derived type ``chargate Scan (SARIF)`` for
    every repo and every PR, permanently. It adds no findings (``results: []``) and
    removes none: DefectDojo's ``consolidate_dynamic_tests`` walks *all* tests for
    findings and only ``tests[0]`` for the name. The version travels with it, so the DD
    Test records which chargate produced it.

    Only the uploaded bytes are rewritten; the SARIF artifact on disk is untouched.
    Anything we cannot confidently parse (not JSON, not an object, no ``runs`` list) is
    passed through byte-for-byte — a report we do not understand is not a report we
    should be editing, and DefectDojo's own error is more useful than a mangled upload.
    """
    try:
        report = json.loads(sarif_bytes)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return sarif_bytes
    if not isinstance(report, dict):
        return sarif_bytes
    runs = report.get("runs")
    if not isinstance(runs, list):
        return sarif_bytes
    if runs and _run_tool_name(runs[0]) == IDENTITY_TOOL_NAME:
        return sarif_bytes  # already stamped (e.g. re-uploading a chargate --sarif-out copy)
    report["runs"] = [identity_run(), *runs]
    return json.dumps(report).encode("utf-8")


def _run_tool_name(run: Any) -> str | None:
    if not isinstance(run, dict):
        return None
    driver = run.get("tool", {}).get("driver", {}) if isinstance(run.get("tool"), dict) else {}
    name = driver.get("name") if isinstance(driver, dict) else None
    return name if isinstance(name, str) else None


def build_request(config: DefectDojoConfig, sarif_path: Path) -> urllib.request.Request:
    body = encode_multipart(
        build_form_fields(config),
        file_field="file",
        filename=sarif_path.name,
        file_bytes=with_identity_run(sarif_path.read_bytes()),
    )
    request = urllib.request.Request(config.endpoint_url(), data=body, method="POST")
    request.add_header("Authorization", f"Token {config.token}")
    request.add_header("Content-Type", f"multipart/form-data; boundary={_BOUNDARY}")
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", _USER_AGENT)
    return request


def _default_opener(verify_ssl: bool) -> urllib.request.OpenerDirector:
    if verify_ssl:
        return urllib.request.build_opener()
    # Reachable only via `chargate ci --dd-insecure`: DefectDojoConfig.verify_ssl defaults
    # to True and the CLI passes `verify_ssl=not args.dd_insecure`, so TLS verification is
    # on unless an operator turns it off by hand. The escape hatch is for a self-hosted
    # DefectDojo behind an internal CA the runner does not trust — without it the import
    # fails and the full SARIF is silently never shipped.
    #
    # DevSkim's DS130822 "Disabled certificate validation" matches the `check_hostname`
    # assignment specifically (not the CERT_NONE line below it) and cannot see the
    # `if verify_ssl` guard above, so the suppression sits on that one line.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # DevSkim: ignore DS130822
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


def is_test_type_mismatch(result: DefectDojoResult) -> bool:
    """True for the HTTP 400 DefectDojo returns when the target Test is typed by another tool."""
    return result.status == 400 and _TEST_TYPE_MISMATCH in result.message.lower()


def import_sarif(
    config: DefectDojoConfig,
    sarif_path: str | Path,
    *,
    opener: urllib.request.OpenerDirector | None = None,
) -> DefectDojoResult:
    """Upload the full SARIF to DefectDojo. Never raises — returns a result.

    On ``reimport-scan``, retries **once** against ``import-scan`` if DefectDojo rejects
    the reimport with its ``Test type mismatch`` 400. :func:`with_identity_run` keeps that
    from recurring, but it cannot rename a Test that already exists: an engagement whose
    Test was typed by an earlier tool (chargate's own said ``KICS Scan (SARIF)``, left
    behind by months of empty reports) will otherwise refuse every reimport forever.
    ``import-scan`` creates a correctly-typed Test in the same engagement, after which the
    identity run means reimport matches it on every later run — so the sink heals itself
    on the next scan instead of staying silently dead until someone edits DefectDojo by
    hand. The retry is deliberately narrow: only this one 400, only when we were
    reimporting. Any other rejection is a real error and creating a duplicate Test would
    hide it.
    """
    endpoint = config.endpoint_url()
    path = Path(sarif_path)
    if not path.is_file():
        return DefectDojoResult(False, endpoint, message=f"SARIF file not found: {path}")

    if opener is None:
        opener = _default_opener(config.verify_ssl)

    result = _post(config, path, opener)
    if not config.reimport or not is_test_type_mismatch(result):
        return result

    retry = _post(replace(config, reimport=False), path, opener)
    if retry.ok:
        return replace(
            retry,
            message=(
                f"{retry.message} to a new test — the engagement's existing test is typed "
                f"by another tool, so reimport was rejected ({result.message})"
            ),
        )
    return replace(
        retry,
        message=(
            f"reimport rejected ({result.message}); "
            f"import-scan fallback also failed: {retry.message}"
        ),
    )


def _post(
    config: DefectDojoConfig,
    path: Path,
    opener: urllib.request.OpenerDirector,
) -> DefectDojoResult:
    """One (re)import request. Never raises — every failure becomes a result."""
    endpoint = config.endpoint_url()
    try:
        request = build_request(config, path)
    except OSError as exc:  # reading the file
        return DefectDojoResult(False, endpoint, message=f"could not read SARIF: {exc}")

    try:
        with opener.open(request, timeout=config.timeout) as response:
            status = getattr(response, "status", None) or response.getcode()
            raw = response.read().decode("utf-8", errors="replace")
            parsed = _safe_json(raw)
            ok = 200 <= int(status) < 300
            return DefectDojoResult(
                ok=ok,
                endpoint=endpoint,
                status=int(status),
                message="uploaded" if ok else raw[:500],
                response=parsed,
                url=test_url(config.base_url, parsed) if ok else None,
            )
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500] if exc.fp else ""
        return DefectDojoResult(
            False, endpoint, status=exc.code, message=f"HTTP {exc.code}: {detail}"
        )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return DefectDojoResult(False, endpoint, message=f"connection error: {exc}")


def _safe_json(raw: str) -> dict[str, Any] | None:
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None

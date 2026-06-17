"""Dependency-Track BOM upload client — optional, first-class, failure-isolated.

Ships a CycloneDX BOM (generated upstream by Syft / ``anchore/sbom-action``) to an
OWASP Dependency-Track server so the full component inventory is monitored
continuously — the supply-chain analog of the DefectDojo SARIF sink. Like that
sink, the upload NEVER blocks the gate: a failure returns a result with
``ok=False`` so the caller can log-and-continue.

Uses the ``PUT /api/v1/bom`` JSON endpoint (BOM base64-encoded in the body),
which needs no multipart handling — stdlib ``urllib`` only, no third-party HTTP.
The project is addressed either by ``project`` UUID or by ``projectName`` +
``projectVersion`` (with ``autoCreate`` to create it on first upload).

Mirrors :mod:`chargate.defectdojo`; see also :mod:`chargate.sarif` for the pure
gate core. Dependency-Track auth is the ``X-Api-Key`` header; the key needs
``BOM_UPLOAD`` (plus ``PROJECT_CREATION_UPLOAD`` when ``autoCreate`` is set).
"""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# A UTF-8 byte-order mark on the BOM makes Dependency-Track's parser reject the
# upload ("77u/" once base64-encoded). Strip it before encoding, mirroring what
# the official gh-upload-sbom action does.
_UTF8_BOM = b"\xef\xbb\xbf"


@dataclass(frozen=True)
class DependencyTrackConfig:
    base_url: str
    api_key: str
    project_name: str | None = None
    project_version: str | None = None
    project_uuid: str | None = None
    auto_create: bool = True
    parent_name: str | None = None
    parent_version: str | None = None
    parent_uuid: str | None = None
    is_latest: bool = False
    verify_ssl: bool = True
    timeout: float = 60.0

    def endpoint_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/api/v1/bom"


@dataclass(frozen=True)
class DependencyTrackResult:
    ok: bool
    endpoint: str
    status: int | None = None
    message: str = ""
    token: str | None = None
    response: dict[str, Any] | None = None


def encode_bom(bom_bytes: bytes) -> str:
    """Base64-encode the BOM, dropping a leading UTF-8 BOM marker if present."""
    if bom_bytes.startswith(_UTF8_BOM):
        bom_bytes = bom_bytes[len(_UTF8_BOM) :]
    return base64.b64encode(bom_bytes).decode("ascii")


def build_payload(config: DependencyTrackConfig, bom_bytes: bytes) -> dict[str, Any]:
    """The JSON body for ``PUT /api/v1/bom``.

    Identifies the project by UUID when given, otherwise by name + version with
    ``autoCreate`` (the common CI case). ``autoCreate`` is meaningless for an
    existing-UUID upload, so it is only emitted on the name/version path.
    """
    payload: dict[str, Any] = {"bom": encode_bom(bom_bytes)}
    if config.project_uuid:
        payload["project"] = config.project_uuid
    else:
        payload["projectName"] = config.project_name or ""
        payload["projectVersion"] = config.project_version or ""
        payload["autoCreate"] = config.auto_create
    if config.parent_uuid:
        payload["parentUUID"] = config.parent_uuid
    elif config.parent_name:
        payload["parentName"] = config.parent_name
        if config.parent_version:
            payload["parentVersion"] = config.parent_version
    if config.is_latest:
        payload["isLatest"] = True
    return payload


def build_request(config: DependencyTrackConfig, bom_path: Path) -> urllib.request.Request:
    body = json.dumps(build_payload(config, bom_path.read_bytes())).encode("utf-8")
    request = urllib.request.Request(config.endpoint_url(), data=body, method="PUT")
    request.add_header("X-Api-Key", config.api_key)
    request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "application/json")
    return request


def upload_bom(
    config: DependencyTrackConfig,
    bom_path: str | Path,
    *,
    opener: urllib.request.OpenerDirector | None = None,
) -> DependencyTrackResult:
    """Upload a CycloneDX BOM to Dependency-Track. Never raises — returns a result."""
    endpoint = config.endpoint_url()
    path = Path(bom_path)
    if not path.is_file():
        return DependencyTrackResult(False, endpoint, message=f"BOM file not found: {path}")

    try:
        request = build_request(config, path)
    except OSError as exc:  # reading the file
        return DependencyTrackResult(False, endpoint, message=f"could not read BOM: {exc}")

    if opener is None:
        if config.verify_ssl:
            opener = urllib.request.build_opener()
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

    try:
        with opener.open(request, timeout=config.timeout) as response:
            status = getattr(response, "status", None) or response.getcode()
            raw = response.read().decode("utf-8", errors="replace")
            parsed = _safe_json(raw)
            ok = 200 <= int(status) < 300
            token = parsed.get("token") if isinstance(parsed, dict) else None
            return DependencyTrackResult(
                ok=ok,
                endpoint=endpoint,
                status=int(status),
                message="uploaded" if ok else raw[:500],
                token=token if isinstance(token, str) else None,
                response=parsed,
            )
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500] if exc.fp else ""
        return DependencyTrackResult(
            False, endpoint, status=exc.code, message=f"HTTP {exc.code}: {detail}"
        )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return DependencyTrackResult(False, endpoint, message=f"connection error: {exc}")


def _safe_json(raw: str) -> dict[str, Any] | None:
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None

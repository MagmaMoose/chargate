"""Dependency-Track BOM upload client — optional, first-class, failure-isolated.

Ships a CycloneDX BOM (generated upstream by Syft / ``anchore/sbom-action``) to an
OWASP Dependency-Track server so the full component inventory is monitored
continuously — the supply-chain analog of the DefectDojo SARIF sink. Like that
sink, the upload NEVER blocks the gate: a failure returns a result with
``ok=False`` so the caller can log-and-continue.

Uses the ``POST /api/v1/bom`` multipart/form-data endpoint — Dependency-Track's
documented primary upload method. The BOM is sent as a raw file part (no base64),
which is friendlier to reverse proxies than the PUT-JSON variant. The project is
addressed either by ``project`` UUID or by ``projectName`` + ``projectVersion``
(with ``autoCreate`` to create it on first upload).

Mirrors :mod:`chargate.defectdojo`; see also :mod:`chargate.sarif` for the pure
gate core. Dependency-Track auth is the ``X-Api-Key`` header; the key needs
``BOM_UPLOAD`` (plus ``PROJECT_CREATION_UPLOAD`` when ``autoCreate`` is set).
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from chargate import __version__

_BOUNDARY = "----chargateDependencyTrackBoundary7MA4YWxkTrZu0gW"
# A UTF-8 byte-order mark on the BOM can trip Dependency-Track's parser; strip it
# before upload, mirroring what the official gh-upload-sbom action does.
_UTF8_BOM = b"\xef\xbb\xbf"
# Identify ourselves instead of the default "Python-urllib/X.Y", which edge WAFs
# (e.g. Cloudflare Bot Fight Mode / error 1010) commonly ban by client signature.
_USER_AGENT = f"chargate/{__version__} (+https://github.com/MagmaMoose/chargate)"


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


def strip_bom_marker(bom_bytes: bytes) -> bytes:
    """Drop a leading UTF-8 BOM marker if present."""
    if bom_bytes.startswith(_UTF8_BOM):
        return bom_bytes[len(_UTF8_BOM) :]
    return bom_bytes


def build_form_fields(config: DependencyTrackConfig) -> dict[str, str]:
    """The non-file multipart fields for ``POST /api/v1/bom``.

    Identifies the project by UUID when given, otherwise by name + version with
    ``autoCreate`` (the common CI case). ``autoCreate`` is meaningless for an
    existing-UUID upload, so it is only emitted on the name/version path.
    """
    fields: dict[str, str] = {}
    if config.project_uuid:
        fields["project"] = config.project_uuid
    else:
        fields["projectName"] = config.project_name or ""
        fields["projectVersion"] = config.project_version or ""
        fields["autoCreate"] = "true" if config.auto_create else "false"
    if config.parent_uuid:
        fields["parentUUID"] = config.parent_uuid
    elif config.parent_name:
        fields["parentName"] = config.parent_name
        if config.parent_version:
            fields["parentVersion"] = config.parent_version
    if config.is_latest:
        fields["isLatest"] = "true"
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


def build_request(config: DependencyTrackConfig, bom_path: Path) -> urllib.request.Request:
    body = encode_multipart(
        build_form_fields(config),
        file_field="bom",
        filename=bom_path.name,
        file_bytes=strip_bom_marker(bom_path.read_bytes()),
    )
    request = urllib.request.Request(config.endpoint_url(), data=body, method="POST")
    request.add_header("X-Api-Key", config.api_key)
    request.add_header("Content-Type", f"multipart/form-data; boundary={_BOUNDARY}")
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", _USER_AGENT)
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

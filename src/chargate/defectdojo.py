"""DefectDojo import client — optional, first-class, and failure-isolated.

Always ships the **full** (unfiltered) SARIF so the security system sees the
complete picture, including inherited debt. Uses ``reimport-scan`` by default
(recurring gate → one Test per engagement, with ``close_old_findings`` mitigating
findings that disappear), falling back to ``import-scan``.

Stdlib only (urllib): no third-party HTTP dependency. By contract a DefectDojo
failure NEVER raises out of :func:`import_sarif` — it returns a result with
``ok=False`` so the caller can log-and-continue without failing the gate.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_BOUNDARY = "----chargateDefectDojoBoundary7MA4YWxkTrZu0gW"


@dataclass(frozen=True)
class DefectDojoConfig:
    base_url: str
    token: str
    product_name: str | None = None
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


def _bool(value: bool) -> str:
    return "true" if value else "false"


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


def build_request(config: DefectDojoConfig, sarif_path: Path) -> urllib.request.Request:
    body = encode_multipart(
        build_form_fields(config),
        file_field="file",
        filename=sarif_path.name,
        file_bytes=sarif_path.read_bytes(),
    )
    request = urllib.request.Request(config.endpoint_url(), data=body, method="POST")
    request.add_header("Authorization", f"Token {config.token}")
    request.add_header("Content-Type", f"multipart/form-data; boundary={_BOUNDARY}")
    request.add_header("Accept", "application/json")
    return request


def import_sarif(
    config: DefectDojoConfig,
    sarif_path: str | Path,
    *,
    opener: urllib.request.OpenerDirector | None = None,
) -> DefectDojoResult:
    """Upload the full SARIF to DefectDojo. Never raises — returns a result."""
    endpoint = config.endpoint_url()
    path = Path(sarif_path)
    if not path.is_file():
        return DefectDojoResult(False, endpoint, message=f"SARIF file not found: {path}")

    try:
        request = build_request(config, path)
    except OSError as exc:  # reading the file
        return DefectDojoResult(False, endpoint, message=f"could not read SARIF: {exc}")

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
            return DefectDojoResult(
                ok=200 <= int(status) < 300,
                endpoint=endpoint,
                status=int(status),
                message="uploaded" if 200 <= int(status) < 300 else raw[:500],
                response=parsed,
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

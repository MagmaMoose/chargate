"""Verify the standalone-image table against the LIVE ghcr.io registry.

Opt-in, because the rest of the suite is offline and must stay that way::

    CHARGATE_REGISTRY_TESTS=1 uv run pytest tests/test_linters_registry.py

CI runs it on a weekly schedule, not on every PR. A MegaLinter version bump that drops
a linter, renames an image, or loses an arm64 build has to fail HERE — loudly, in a job
whose whole purpose is this — rather than at run time, where it presents as an arm64
scan that quietly got smaller and a gate that quietly got weaker.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

import pytest

from chargate.linters import FLAVOR_STANDALONE_SETS, STANDALONE_LINTERS
from chargate.megalinter import DEFAULT_NAMESPACE, DEFAULT_TAG

pytestmark = pytest.mark.skipif(
    os.environ.get("CHARGATE_REGISTRY_TESTS") != "1",
    reason="needs network; set CHARGATE_REGISTRY_TESTS=1",
)

_ACCEPT = ",".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


def _manifest(repo: str, ref: str) -> dict:
    """Fetch a manifest from ghcr.io with an anonymous pull token."""
    token_url = f"https://ghcr.io/token?scope=repository:{repo}:pull&service=ghcr.io"
    with urllib.request.urlopen(token_url) as response:  # nosec B310
        token = json.load(response)["token"]
    request = urllib.request.Request(
        f"https://ghcr.io/v2/{repo}/manifests/{ref}",
        headers={"Authorization": f"Bearer {token}", "Accept": _ACCEPT},
    )
    with urllib.request.urlopen(request) as response:  # nosec B310
        return json.load(response)


def _linux_arches(manifest: dict) -> set[str]:
    return {
        entry["platform"]["architecture"]
        for entry in manifest.get("manifests", ())
        if entry.get("platform", {}).get("os") == "linux"
        and entry["platform"].get("architecture") != "unknown"
    }


@pytest.mark.parametrize("key", sorted(FLAVOR_STANDALONE_SETS["security"]))
def test_security_standalone_images_still_publish_arm64(key: str):
    repo = f"{DEFAULT_NAMESPACE}/{STANDALONE_LINTERS[key].repository()}"
    arches = _linux_arches(_manifest(repo, DEFAULT_TAG))
    assert "arm64" in arches, f"{repo}:{DEFAULT_TAG} has no linux/arm64 manifest ({arches})"


def test_the_default_flavor_image_still_exists_at_the_pinned_tag():
    # A single-arch manifest has no `manifests` key; either shape proves the tag exists.
    manifest = _manifest(f"{DEFAULT_NAMESPACE}/megalinter-security", DEFAULT_TAG)
    assert manifest.get("schemaVersion") == 2


@pytest.mark.parametrize("key", sorted(FLAVOR_STANDALONE_SETS["quality"]))
def test_quality_standalone_images_still_publish_arm64(key: str):
    repo = f"{DEFAULT_NAMESPACE}/{STANDALONE_LINTERS[key].repository()}"
    arches = _linux_arches(_manifest(repo, DEFAULT_TAG))
    assert "arm64" in arches, f"{repo}:{DEFAULT_TAG} has no linux/arm64 manifest ({arches})"


# ── the `sarif` flag, cross-checked against MegaLinter's own descriptors ──────
#
# The arm64 probes above cannot see this: an image can exist, be multi-arch, start
# cleanly and still emit nothing the gate reads, because `can_output_sarif` lives in the
# descriptor rather than the registry. That gap let ACTION_ACTIONLINT and PYTHON_PYLINT
# sit in this table as sarif=True — the `_entry` default, never probed — for their whole
# life. A linter recorded as SARIF-emitting that is not costs a container pull per run
# and contributes zero findings, which reads exactly like a clean repo.

# MegaLinter descriptors nest each linter one list level under `linters:`.
_BLOCK_INDENT = 2
_KEY_INDENT = 4

_DESCRIPTOR_URL = (
    "https://raw.githubusercontent.com/oxsecurity/megalinter/"
    "{tag}/megalinter/descriptors/{descriptor}.megalinter-descriptor.yml"
)


def _descriptor_sarif_flags(descriptor: str) -> dict[str, bool]:
    """``{linter key: can_output_sarif}`` for one MegaLinter descriptor at the pinned tag.

    Parsed by indentation rather than with PyYAML: chargate has no runtime dependencies
    and its dev group carries no YAML parser, and this needs three keys out of a flat
    list of linter blocks. Indentation is load-bearing — ``name:`` also appears deeper
    inside each block's ``variables:`` list, and treating one of those as the linter's
    key silently renames it.
    """
    url = _DESCRIPTOR_URL.format(tag=DEFAULT_TAG, descriptor=descriptor.lower())
    try:
        with urllib.request.urlopen(url) as response:  # nosec B310
            text = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:  # pragma: no cover - a missing descriptor IS the finding
        pytest.fail(f"no MegaLinter descriptor for '{descriptor}' at {DEFAULT_TAG}: {exc}")

    flags: dict[str, bool] = {}
    in_linters = False
    block: dict[str, str] | None = None

    def flush() -> None:
        if not block or "linter_name" not in block:
            return
        derived = f"{descriptor.upper()}_{block['linter_name'].upper().replace('-', '_')}"
        # An explicit `name:` overrides the derived key — this is how ESLint becomes
        # JAVASCRIPT_ES and not JAVASCRIPT_ESLINT.
        flags[block.get("name", derived)] = block.get("can_output_sarif", "").lower() == "true"

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        if indent == 0:
            flush()
            block = None
            in_linters = raw.startswith("linters:")
            continue
        if not in_linters:
            continue
        if indent == _BLOCK_INDENT and raw.lstrip().startswith("- "):
            flush()
            block = {}
            raw = " " * _KEY_INDENT + raw.lstrip()[2:]  # `  - k: v` -> a key at indent 4
            indent = _KEY_INDENT
        if block is None or indent != _KEY_INDENT or ":" not in raw:
            continue
        key, _, value = raw.strip().partition(":")
        if key in ("linter_name", "name", "can_output_sarif"):
            block[key] = value.strip().strip("\"'")
    flush()
    return flags


@pytest.mark.parametrize(
    "descriptor",
    sorted({key.split("_", 1)[0] for key in STANDALONE_LINTERS}),
)
def test_sarif_flags_match_megalinters_descriptors(descriptor: str):
    upstream = _descriptor_sarif_flags(descriptor)
    for key, image in STANDALONE_LINTERS.items():
        if not key.startswith(f"{descriptor}_"):
            continue
        assert key in upstream, (
            f"{key} is in STANDALONE_LINTERS but has no linter entry in the "
            f"{descriptor.lower()} descriptor at {DEFAULT_TAG}"
        )
        assert image.sarif is upstream[key], (
            f"{key}: table says sarif={image.sarif}, {DEFAULT_TAG} descriptor says "
            f"can_output_sarif={upstream[key]}"
        )

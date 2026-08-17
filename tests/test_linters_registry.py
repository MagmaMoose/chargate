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

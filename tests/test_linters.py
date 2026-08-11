"""Unit tests for the standalone-linter table (chargate.linters).

Offline invariants only — the live-registry cross-check lives in
``tests/test_linters_registry.py`` and is opt-in.
"""

from __future__ import annotations

import pytest

from chargate.linters import FLAVOR_STANDALONE_SETS, STANDALONE_LINTERS


def test_keys_are_canonical_megalinter_linter_keys():
    for key, image in STANDALONE_LINTERS.items():
        assert key == key.upper(), key
        assert image.key == key


def test_repository_name_matches_megalinters_image_naming():
    assert STANDALONE_LINTERS["REPOSITORY_TRIVY"].repository() == "megalinter-only-repository_trivy"


def test_security_set_is_the_eighteen_sarif_emitting_linters():
    security = FLAVOR_STANDALONE_SETS["security"]
    assert len(security) == 18
    assert len(set(security)) == 18


@pytest.mark.parametrize("key", sorted(FLAVOR_STANDALONE_SETS["security"]))
def test_every_security_linter_is_known_arm64_capable_and_sarif_emitting(key: str):
    # The default arm64 substitution set: anything here that is amd64-only or emits no
    # SARIF would be silently dropped at run time, quietly shrinking the scan.
    image = STANDALONE_LINTERS[key]
    assert image.arm64 is True
    assert image.sarif is True


def test_amd64_only_linters_are_never_security_linters():
    # Upstream's 13 amd64-only linters are all style/language tooling; if a security
    # linter ever loses its arm64 build, this catches it before arm64 coverage drops.
    amd64_only = {key for key, image in STANDALONE_LINTERS.items() if not image.arm64}
    assert amd64_only.isdisjoint(FLAVOR_STANDALONE_SETS["security"])


def test_the_all_flavor_has_no_standalone_substitution():
    # Substituting `all` would mean 100+ container starts and several GB of pulls.
    assert "all" not in FLAVOR_STANDALONE_SETS

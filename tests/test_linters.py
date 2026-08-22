"""Unit tests for the standalone-linter table (chargate.linters).

Offline invariants only — the live-registry cross-check lives in
``tests/test_linters_registry.py`` and is opt-in.
"""

from __future__ import annotations

import pytest

from chargate.linters import FLAVOR_STANDALONE_SETS, STANDALONE_LINTERS, SYNTHETIC_FLAVORS


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


def test_kubescape_is_the_only_gated_kubernetes_linter():
    # kubescape is the sole SARIF-emitting Kubernetes linter, so it is the only one that
    # reaches the net-new gate — it must stay in the security substitution set.
    assert "KUBERNETES_KUBESCAPE" in FLAVOR_STANDALONE_SETS["security"]
    assert STANDALONE_LINTERS["KUBERNETES_KUBESCAPE"].sarif is True


def test_kubeconform_is_known_but_not_gated_and_kube_score_is_absent():
    # kubeconform validates manifests but emits no SARIF, so it must never be in the
    # security (SARIF-gated) set. kube-score has no MegaLinter descriptor: guarding here
    # stops anyone naming a non-existent KUBERNETES_KUBE_SCORE key that would do nothing.
    assert STANDALONE_LINTERS["KUBERNETES_KUBECONFORM"].sarif is False
    assert "KUBERNETES_KUBECONFORM" not in FLAVOR_STANDALONE_SETS["security"]
    assert "KUBERNETES_KUBE_SCORE" not in STANDALONE_LINTERS


def test_the_all_flavor_has_no_standalone_substitution():
    # Substituting `all` would mean 100+ container starts and several GB of pulls.
    assert "all" not in FLAVOR_STANDALONE_SETS


# ── the `quality` set (brimyr#33) ────────────────────────────────────────────


def test_quality_set_is_five_curated_linters():
    # Five, not a flavor's worth: MegaLinter's quality half is dense enough that a
    # whole-flavor first PR is how the gate gets switched off. Growing this is a
    # deliberate act, so a change here should be a change to this number too.
    quality = FLAVOR_STANDALONE_SETS["quality"]
    assert len(quality) == 5
    assert len(set(quality)) == 5


@pytest.mark.parametrize("key", sorted(FLAVOR_STANDALONE_SETS["quality"]))
def test_every_quality_linter_is_arm64_capable_and_sarif_emitting(key: str):
    # Same rule as the security set: anything amd64-only or non-SARIF here is silently
    # dropped at run time, and a quality gate that reports nothing looks like a clean
    # repo. `sarif` is the one that bites — the gate only ever reads the merged SARIF.
    image = STANDALONE_LINTERS[key]
    assert image.arm64 is True
    assert image.sarif is True


def test_quality_and_security_sets_are_disjoint():
    # A repo running both gates must not have one finding block it twice — that is
    # double-reporting, and double-reporting is how a gate earns its reputation for
    # noise. shellcheck/hadolint/tflint are quality-ish AND security, and stay security.
    assert set(FLAVOR_STANDALONE_SETS["quality"]).isdisjoint(FLAVOR_STANDALONE_SETS["security"])


def test_eslint_keys_are_the_v10_names_not_the_obvious_guess():
    # MegaLinter declares ESLint as JAVASCRIPT_ES / TYPESCRIPT_ES. The `*_ESLINT` names
    # everyone reaches for first have no descriptor and no image: the pull 404s, and in
    # standalone mode the linter is skipped as unknown — a quietly smaller scan.
    assert "JAVASCRIPT_ES" in STANDALONE_LINTERS
    assert "TYPESCRIPT_ES" in STANDALONE_LINTERS
    assert "JAVASCRIPT_ESLINT" not in STANDALONE_LINTERS
    assert "TYPESCRIPT_ESLINT" not in STANDALONE_LINTERS


def test_actionlint_and_pylint_emit_no_sarif_at_v10():
    # Both carried sarif=True purely from the `_entry` default and were never probed;
    # neither descriptor sets can_output_sarif at v10.0.0. Recorded honestly, they are
    # skipped by name with a reason instead of starting a container the gate cannot see.
    assert STANDALONE_LINTERS["ACTION_ACTIONLINT"].sarif is False
    assert STANDALONE_LINTERS["PYTHON_PYLINT"].sarif is False
    assert "ACTION_ACTIONLINT" not in FLAVOR_STANDALONE_SETS["quality"]
    assert "PYTHON_PYLINT" not in FLAVOR_STANDALONE_SETS["quality"]


def test_dotnet_has_no_quality_linter_because_none_emits_sarif():
    # No C#/VB.NET linter sets can_output_sarif at v10.0.0, so none can reach the gate.
    # Asserted so the absence reads as a finding rather than an oversight.
    assert not [key for key in FLAVOR_STANDALONE_SETS["quality"] if key.startswith("CSHARP_")]


def test_every_synthetic_flavor_has_a_standalone_set():
    # A synthetic flavor IS its standalone set — one without a set would resolve to
    # zero runnable linters and raise at run time instead of here.
    for flavor in SYNTHETIC_FLAVORS:
        assert FLAVOR_STANDALONE_SETS.get(flavor), flavor

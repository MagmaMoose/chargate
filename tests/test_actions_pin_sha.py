"""Tag ordering for the ``actions-pin-sha`` hook.

The hook annotates a SHA pin with the tag that SHA carries. That comment is not
decoration: Caldrith's version-downgrade guard parses the version out of it to
decide whether a repo is ahead of the admin baseline, so choosing the wrong tag
silently corrupts org-wide file reconciliation.

Choosing is the hard part because several tags routinely point at ONE commit.
``actions/deploy-pages`` carries ``v5.0.0``, the floating ``v5`` and a legacy
``v3.0.2-node.24`` on the same SHA. The ordering rules live in ``_TAG_RANK_AWK``
inside the hook; these tests exercise it directly, offline — sourcing the hook
exposes the helpers without running ``main``.
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404 - runs the hook under bash to test it; no user input
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parent.parent / "hooks" / "github-actions-pin-sha.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None, reason="the hook is bash; no bash on PATH"
)


def rank(*tags: str) -> str:
    """Return the tag ``_TAG_RANK_AWK`` picks as best out of ``tags``."""
    script = f'source "{HOOK.as_posix()}"; printf "%s\\n" "$@" | awk "$_TAG_RANK_AWK"'
    result = subprocess.run(  # nosec B603 B607 - fixed argv, literal script
        ["bash", "-c", script, "_", *tags],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def test_deploy_pages_legacy_tag_does_not_win() -> None:
    """The regression: three tags on one commit, and the legacy one used to win.

    Ranking on segment count first meant the four segments of ``v3.0.2-node.24``
    outscored the three of ``v5.0.0`` before either version was compared, so the
    hook annotated a v5.0.0 SHA as v3.0.2.
    """
    assert rank("v3.0.2-node.24", "v5", "v5.0.0") == "v5.0.0"


def test_order_of_candidates_does_not_matter() -> None:
    """Ranking is a true maximum, not "first acceptable candidate wins"."""
    assert rank("v5.0.0", "v5", "v3.0.2-node.24") == "v5.0.0"
    assert rank("v5", "v5.0.0", "v3.0.2-node.24") == "v5.0.0"


def test_exact_release_beats_floating_major() -> None:
    """``v7.0.1`` is more useful in a comment than ``v7`` at the same version."""
    assert rank("v7", "v7.0.1") == "v7.0.1"


def test_prerelease_loses_to_the_release_it_precedes() -> None:
    assert rank("v5.0.0-rc.1", "v5.0.0") == "v5.0.0"


def test_prerelease_still_wins_when_it_is_all_there_is() -> None:
    """A suffixed tag is deprioritised, never discarded — the pin still needs a name."""
    assert rank("v5.0.0-rc.1") == "v5.0.0-rc.1"


def test_versions_compare_numerically_not_lexically() -> None:
    assert rank("v1.2.3", "v1.2.10") == "v1.2.10"
    assert rank("v1.9.0", "v1.10.0") == "v1.10.0"


def test_minor_version_breaks_the_tie() -> None:
    """Guards a bug where the running best's minor was assigned from itself.

    ``b2=b2`` instead of ``b2=a[2]`` left the minor permanently 0, so any
    comparison that reached the minor field compared against the wrong value.
    """
    assert rank("v1.2.0", "v1.3.0") == "v1.3.0"
    assert rank("v1.3.0", "v1.2.0") == "v1.3.0"


def test_no_candidates_yields_empty() -> None:
    assert rank() == ""


@pytest.mark.parametrize("tag", ["v5.0.0", "5.0.0"])
def test_leading_v_is_optional(tag: str) -> None:
    assert rank(tag, "v3.0.2-node.24") == tag


def test_sourcing_the_hook_does_not_run_it() -> None:
    """The source guard is what makes these tests possible; assert it holds.

    Without it, sourcing the hook would walk the repo's workflows and hit the
    network on every test.
    """
    script = f'source "{HOOK.as_posix()}"; echo SOURCED_CLEANLY'
    result = subprocess.run(  # nosec B603 B607 - fixed argv, literal script
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "SOURCED_CLEANLY"
    assert "Processing" not in result.stdout

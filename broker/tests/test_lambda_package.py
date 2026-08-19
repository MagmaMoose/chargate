"""The package contract: what ships, that it is reproducible, and that it imports.

This is the test that makes the whole design safe to deploy. `scripts/build_lambda_zip.py`
can produce a zip that uploads cleanly, deploys cleanly, and then ImportErrors on the
first real request — and because `scripts/request-app-token.sh` fails soft, that failure
is INVISIBLE: PR comments simply revert to `github-actions[bot]` and nothing goes red.
The bug is caught here or it is caught by nobody.

Nievah's `tests/test_edge_package.py` makes the same argument for its dependency-free
edge zip. This one has to work harder, because chargate's package carries compiled
wheels (`cryptography`, `cffi`) whose platform tags are exactly what a careless build
gets wrong.
"""

from __future__ import annotations

import hashlib
import os
import platform
import subprocess
import sys
import sysconfig
import zipfile
from pathlib import Path

import pytest

BROKER_ROOT = Path(__file__).resolve().parents[1]
BUILD_PLATFORM = "x86_64-manylinux_2_28"

#: Generous but not unbounded. Measured at ~5.3 MB; this catches a dependency bump that
#: drags in something large, well before Lambda's 50 MB zipped limit turns it into a
#: deploy-time failure. Raise it deliberately, with the new measurement in hand.
MAX_ZIP_BYTES = 12_000_000


def _build(out: Path) -> str:
    from scripts.build_lambda_zip import build

    return build(BROKER_ROOT, out, platform=BUILD_PLATFORM, python_version="3.12")


@pytest.fixture(scope="module")
def package(tmp_path_factory) -> tuple[Path, str]:
    out = tmp_path_factory.mktemp("pkg") / "chargate-broker.zip"
    return out, _build(out)


class TestContents:
    def test_app_modules_are_byte_identical_to_the_repo(self, package):
        """The edge runs the SAME files the tests exercise, not a copy of them."""
        zip_path, _ = package
        with zipfile.ZipFile(zip_path) as archive:
            for name in ("app/github.py", "app/oidc.py", "app/broker.py", "app/config.py"):
                assert archive.read(name) == (BROKER_ROOT / name).read_bytes(), name

    def test_main_is_excluded(self, package):
        """app/main.py is the one module importing FastAPI, which is not shipped."""
        zip_path, _ = package
        with zipfile.ZipFile(zip_path) as archive:
            assert "app/main.py" not in archive.namelist()

    def test_lambda_entrypoints_are_present(self, package):
        zip_path, _ = package
        with zipfile.ZipFile(zip_path) as archive:
            assert "app/lambda_handler.py" in archive.namelist()
            assert "app/ssm.py" in archive.namelist()

    def test_boto3_is_not_bundled(self, package):
        """The runtime supplies it; our own copy would add ~50 MB."""
        zip_path, _ = package
        with zipfile.ZipFile(zip_path) as archive:
            assert not [n for n in archive.namelist() if n.startswith(("boto3/", "botocore/"))]

    def test_framework_packages_are_not_bundled(self, package):
        zip_path, _ = package
        banned = ("fastapi/", "starlette/", "pydantic/", "pydantic_core/", "pydantic_settings/")
        with zipfile.ZipFile(zip_path) as archive:
            assert not [n for n in archive.namelist() if n.startswith(banned)]

    def test_no_build_litter(self, package):
        zip_path, _ = package
        with zipfile.ZipFile(zip_path) as archive:
            names = archive.namelist()
        assert not [n for n in names if "__pycache__" in n or n.endswith((".pyc", ".pyo"))]
        assert not [n for n in names if ".dist-info" in n or n.startswith("bin/")]

    def test_linux_compiled_wheels_were_resolved(self, package):
        """A build on a developer's Mac must not silently ship macOS binaries.

        This is what `--platform` being a required flag with no default is defending,
        and this assertion is what proves the flag was honoured.

        Note the shape of the check. A stable-ABI wheel names its object
        `_rust.abi3.so` with NO platform tag at all, so "every .so mentions linux" is
        unsatisfiable. What is checkable is that at least one object carries an
        explicit Linux tag, and that nothing carries a macOS or Windows one.
        """
        zip_path, _ = package
        with zipfile.ZipFile(zip_path) as archive:
            names = archive.namelist()

        native = [n for n in names if n.endswith((".so", ".dylib", ".pyd"))]
        assert native, "expected compiled extension modules from cryptography/cffi"

        assert any("linux" in n for n in native), native
        foreign = [
            n for n in native if n.endswith((".dylib", ".pyd")) or "darwin" in n or "win_" in n
        ]
        assert not foreign, foreign

    def test_size_is_within_budget(self, package):
        zip_path, _ = package
        assert zip_path.stat().st_size < MAX_ZIP_BYTES, zip_path.stat().st_size


class TestReproducible:
    def test_two_builds_agree(self, package, tmp_path):
        """A changed digest is the publish signal; nondeterminism would make every
        chargate release open an infra bump PR redeploying byte-identical code."""
        _, first = package
        second = _build(tmp_path / "again.zip")
        assert first == second

    def test_a_changed_input_moves_the_digest(self, package, tmp_path):
        """The inverse, which is the half that actually proves anything: a build that
        ignored its inputs would also produce two matching digests."""
        from scripts.build_lambda_zip import write_zip

        staged = tmp_path / "staged"
        (staged / "app").mkdir(parents=True)
        (staged / "app" / "__init__.py").write_text('"""x"""\n')
        before = write_zip(staged, tmp_path / "a.zip")

        (staged / "app" / "__init__.py").write_text('"""y"""\n')
        after = write_zip(staged, tmp_path / "b.zip")

        assert before != after


@pytest.mark.skipif(
    not (
        sys.platform.startswith("linux")
        and platform.machine() == "x86_64"
        and sysconfig.get_python_version() == "3.12"
    ),
    reason="the shipped wheels are linux/x86_64/cp312; only that host can execute them",
)
class TestImportable:
    """Unzip the real artifact and import it the way Lambda will.

    Everything above inspects the zip. This executes it — the only check that would
    have caught a wheel built for the wrong platform, a missing transitive dependency,
    or an `app/` module that grew an import of something not shipped.
    """

    def _run(self, root: Path, code: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-c", code],
            cwd=root,
            env={"PYTHONPATH": "", "PATH": "/usr/bin:/bin", "HOME": str(root)},
            capture_output=True,
            text=True,
        )

    def test_handlers_import_from_the_unzipped_tree(self, package, tmp_path):
        zip_path, _ = package
        root = tmp_path / "unzipped"
        with zipfile.ZipFile(zip_path) as archive:
            archive.extractall(root)

        result = self._run(
            root,
            "import app.lambda_handler as h; assert callable(h.handler); print('ok')",
        )
        assert result.returncode == 0, result.stderr
        assert "ok" in result.stdout

    def test_nothing_leaks_in_from_outside_the_zip(self, package, tmp_path):
        """Poison the modules the package must not need, and the ones it must get from
        inside the zip are asserted to resolve there rather than from the host."""
        zip_path, _ = package
        root = tmp_path / "poisoned"
        with zipfile.ZipFile(zip_path) as archive:
            archive.extractall(root)

        code = (
            "import sys\n"
            "for name in ('fastapi','starlette','pydantic','pydantic_settings','mangum'):\n"
            "    sys.modules[name] = None\n"
            "import app.lambda_handler, app.broker, app.config\n"
            "import jwt, httpx\n"
            f"assert jwt.__file__.startswith({str(root)!r}), jwt.__file__\n"
            f"assert httpx.__file__.startswith({str(root)!r}), httpx.__file__\n"
            "print('ok')\n"
        )
        result = self._run(root, code)
        assert result.returncode == 0, result.stderr
        assert "ok" in result.stdout


def test_build_script_refuses_to_guess_a_platform():
    """`--platform` has no default: a Mac build that silently produced macOS wheels
    would deploy and then ImportError on the first request."""
    result = subprocess.run(
        [sys.executable, "scripts/build_lambda_zip.py", "--out", os.devnull],
        cwd=BROKER_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "--platform" in result.stderr


def test_changed_since_does_not_require_a_platform():
    """`--changed-since` asks a question about git history and builds nothing.

    Requiring `--platform` for it made the release workflow's publish gate exit 2, which
    `set -euo pipefail` turned into a failed release job — the build had already succeeded, and
    then the gate query killed it. Regression test for that exact invocation.
    """
    result = subprocess.run(
        [sys.executable, "scripts/build_lambda_zip.py", "--changed-since", "HEAD"],
        cwd=BROKER_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() in {"true", "false"}


def test_gate_watches_every_input_that_changes_what_ships():
    """The publish gate must key on pyproject.toml as well as the lock.

    `uv export --frozen --no-dev` reads pyproject to decide which dependencies are in scope, so
    moving a package between `dependencies` and an extra changes the shipped set while uv.lock
    stays byte-identical. A gate that watched only the lock would never publish that change.
    """
    from scripts.build_lambda_zip import changed_since

    source = (BROKER_ROOT / "scripts" / "build_lambda_zip.py").read_text()
    assert "broker/pyproject.toml" in source
    assert callable(changed_since)


def test_digest_matches_the_file(package):
    zip_path, digest = package
    assert hashlib.sha256(zip_path.read_bytes()).hexdigest() == digest

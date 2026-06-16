"""Unit tests for the global hook installer (chargate.install_hooks).

Everything is mocked: a fake runner stands in for ``git config --global`` and
``pre-commit``, and ``home`` is redirected to ``tmp_path``. These tests must never
mutate the real global git config or the developer's ``$HOME``.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from chargate import __version__
from chargate.install_hooks import (
    SENTINEL,
    HookInstallError,
    install_hooks,
    uninstall_hooks,
)


def _cp(
    cmd: list[str], returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)


class FakeGit:
    """Fakes ``git config --global`` (get/set/unset) and ``pre-commit``."""

    def __init__(self, config: dict[str, str] | None = None, precommit_rc: int = 0) -> None:
        self.config: dict[str, str] = dict(config or {})
        self.precommit_rc = precommit_rc
        self.calls: list[list[str]] = []

    def __call__(self, cmd: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(cmd)
        if cmd[:4] == ["git", "config", "--global", "--get"]:
            key = cmd[4]
            if key in self.config:
                return _cp(cmd, 0, stdout=self.config[key] + "\n")
            return _cp(cmd, 1)
        if cmd[:4] == ["git", "config", "--global", "--unset"]:
            key = cmd[4]
            if key in self.config:
                del self.config[key]
                return _cp(cmd, 0)
            return _cp(cmd, 5)
        is_set = cmd[:3] == ["git", "config", "--global"] and len(cmd) == 5
        if is_set and not cmd[3].startswith("-"):
            self.config[cmd[3]] = cmd[4]
            return _cp(cmd, 0)
        if cmd[:2] == ["pre-commit", "init-templatedir"]:
            return _cp(cmd, self.precommit_rc, stderr="" if self.precommit_rc == 0 else "boom")
        return _cp(cmd, 0)


def _which(present: set[str]) -> object:
    return lambda tool: f"/usr/bin/{tool}" if tool in present else None


def _paths(home: Path) -> tuple[Path, Path, Path, Path]:
    config = home / ".pre-commit-config.yaml"
    state = home / ".config" / "chargate" / "state.json"
    template_dir = home / ".config" / "chargate" / "git-template"
    return config, state, template_dir, template_dir / "hooks"


def test_missing_pre_commit_raises(tmp_path: Path) -> None:
    with pytest.raises(HookInstallError, match="pre-commit"):
        install_hooks(home=tmp_path, runner=FakeGit(), which=_which({"git"}))


def test_missing_git_raises(tmp_path: Path) -> None:
    with pytest.raises(HookInstallError, match="git"):
        install_hooks(home=tmp_path, runner=FakeGit(), which=_which({"pre-commit"}))


def test_refuses_to_clobber_foreign_config(tmp_path: Path) -> None:
    config, *_ = _paths(tmp_path)
    config.write_text("repos: []  # hand maintained\n", encoding="utf-8")
    with pytest.raises(HookInstallError, match="Refusing to overwrite"):
        install_hooks(home=tmp_path, runner=FakeGit(), which=_which({"git", "pre-commit"}))
    # Untouched.
    assert "hand maintained" in config.read_text(encoding="utf-8")


def test_force_overwrites_foreign_config(tmp_path: Path) -> None:
    config, *_ = _paths(tmp_path)
    config.write_text("repos: []  # hand maintained\n", encoding="utf-8")
    install_hooks(force=True, home=tmp_path, runner=FakeGit(), which=_which({"git", "pre-commit"}))
    assert SENTINEL in config.read_text(encoding="utf-8")


def test_writes_managed_config_pinned_to_version(tmp_path: Path) -> None:
    config, *_ = _paths(tmp_path)
    install_hooks(home=tmp_path, runner=FakeGit(), which=_which({"git", "pre-commit"}))
    text = config.read_text(encoding="utf-8")
    assert text.startswith(SENTINEL)
    assert "default_install_hook_types: [pre-commit, pre-push, commit-msg]" in text
    assert ">>> chargate-managed" in text and "<<< chargate-managed" in text
    assert f"rev: v{__version__}" in text
    assert "id: actions-pin-sha" in text
    assert "id: conventional-branch-name" in text


def test_wires_global_config_and_templatedir(tmp_path: Path) -> None:
    _, _, template_dir, hooks_dir = _paths(tmp_path)
    git = FakeGit()
    install_hooks(home=tmp_path, runner=git, which=_which({"git", "pre-commit"}))

    assert git.config["core.hooksPath"] == str(hooks_dir)
    assert git.config["init.templateDir"] == str(template_dir)

    init_calls = [c for c in git.calls if c[:2] == ["pre-commit", "init-templatedir"]]
    assert len(init_calls) == 1
    assert str(template_dir) in init_calls[0]
    for stage in ("pre-commit", "pre-push", "commit-msg"):
        assert stage in init_calls[0]


def test_points_dispatchers_at_global_config(tmp_path: Path) -> None:
    config, _, _, hooks_dir = _paths(tmp_path)
    hooks_dir.mkdir(parents=True)
    for stage in ("pre-commit", "pre-push", "commit-msg"):
        (hooks_dir / stage).write_text(
            "ARGS=(hook-impl --config=.pre-commit-config.yaml --hook-type=x)\n", encoding="utf-8"
        )
    install_hooks(home=tmp_path, runner=FakeGit(), which=_which({"git", "pre-commit"}))
    for stage in ("pre-commit", "pre-push", "commit-msg"):
        text = (hooks_dir / stage).read_text(encoding="utf-8")
        assert f"--config={config}" in text
        assert "--config=.pre-commit-config.yaml" not in text


def test_preserves_user_section_on_rerun(tmp_path: Path) -> None:
    config, *_ = _paths(tmp_path)
    install_hooks(home=tmp_path, runner=FakeGit(), which=_which({"git", "pre-commit"}))
    # Tamper the managed rev and add a user hook OUTSIDE the managed block.
    text = config.read_text(encoding="utf-8").replace(f"rev: v{__version__}", "rev: vSTALE")
    text += (
        "  - repo: local\n"
        "    hooks:\n"
        "      - id: my-hook\n"
        "        entry: /bin/true\n"
        "        language: system\n"
    )
    config.write_text(text, encoding="utf-8")

    install_hooks(home=tmp_path, runner=FakeGit(), which=_which({"git", "pre-commit"}))
    rerun = config.read_text(encoding="utf-8")
    assert "id: my-hook" in rerun  # user section preserved
    assert "vSTALE" not in rerun  # managed block regenerated
    assert f"rev: v{__version__}" in rerun
    assert rerun.count(">>> chargate-managed") == 1  # block not duplicated


def test_init_templatedir_failure_raises(tmp_path: Path) -> None:
    with pytest.raises(HookInstallError, match="init-templatedir"):
        install_hooks(
            home=tmp_path,
            runner=FakeGit(precommit_rc=1),
            which=_which({"git", "pre-commit"}),
        )


def test_saves_prior_state_once(tmp_path: Path) -> None:
    _, state, _, _ = _paths(tmp_path)
    git = FakeGit(config={"core.hooksPath": "/Users/x/.git-hooks"})
    install_hooks(home=tmp_path, runner=git, which=_which({"git", "pre-commit"}))

    saved = json.loads(state.read_text(encoding="utf-8"))
    assert saved["core.hooksPath"] == "/Users/x/.git-hooks"
    assert saved["init.templateDir"] is None

    # Re-running must NOT overwrite the genuine original (now that hooksPath is ours).
    install_hooks(home=tmp_path, runner=git, which=_which({"git", "pre-commit"}))
    saved_again = json.loads(state.read_text(encoding="utf-8"))
    assert saved_again["core.hooksPath"] == "/Users/x/.git-hooks"


def test_uninstall_restores_prior_hookspath(tmp_path: Path) -> None:
    _, state, template_dir, hooks_dir = _paths(tmp_path)
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(
        json.dumps({"core.hooksPath": "/Users/x/.git-hooks", "init.templateDir": None}),
        encoding="utf-8",
    )
    git = FakeGit(config={"core.hooksPath": str(hooks_dir), "init.templateDir": str(template_dir)})
    uninstall_hooks(home=tmp_path, runner=git)

    assert git.config["core.hooksPath"] == "/Users/x/.git-hooks"
    assert "init.templateDir" not in git.config
    assert not state.exists()


def test_uninstall_leaves_foreign_values_alone(tmp_path: Path) -> None:
    git = FakeGit(config={"core.hooksPath": "/someone/elses/path"})
    uninstall_hooks(home=tmp_path, runner=git)
    assert git.config["core.hooksPath"] == "/someone/elses/path"


def test_uninstall_only_removes_managed_config(tmp_path: Path) -> None:
    config, *_ = _paths(tmp_path)
    config.write_text("repos: []  # not ours\n", encoding="utf-8")
    uninstall_hooks(home=tmp_path, runner=FakeGit())
    assert config.exists()  # left intact — no sentinel

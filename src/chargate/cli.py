"""Chargate command-line interface.

Subcommands:

* ``chargate filter-sarif`` — the pure net-new filter (SARIF + base/head →
  filtered SARIF + counts + gate exit code). Decoupled from GitHub Actions and
  unit-tested in isolation.
* ``chargate ci`` — the full CI flow (run MegaLinter, filter, gate, ship).
* ``chargate local`` — fast staged-file checks for the pre-commit framework.
* ``chargate install-hooks`` / ``uninstall-hooks`` — wire chargate's hooks into
  git globally (via pre-commit), or revert that.
* ``chargate version`` — print the version.

Exit codes: ``0`` pass · ``1`` blocking net-new findings · ``2`` setup/usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, NamedTuple

from chargate import __version__
from chargate import defectdojo as dd
from chargate import dependencytrack as dt
from chargate import git as cgit
from chargate import github_comment as ghc
from chargate import local as local_mod
from chargate import megalinter as ml
from chargate import report as report_mod
from chargate.gate import EXIT_ERROR, EXIT_OK, FAIL_ON_CHOICES, decide_gate, effective_band
from chargate.install_hooks import HookInstallError, install_hooks, uninstall_hooks
from chargate.modes import Mode, resolve_mode
from chargate.sarif.diff import DiffIndex
from chargate.sarif.filter import (
    FilterPolicy,
    FilterResult,
    NoLocationPolicy,
    Precision,
    filter_sarif,
    normalize_sarif_uri,
)
from chargate.sarif.model import (
    canonicalize_tool_names,
    is_secret_result,
    iter_results,
    primary_uri,
)
from chargate.sarif.sops import EMPTY_SOPS_INDEX, SopsIndex, scan_encrypted_lines


def _eprint(message: str) -> None:
    print(message, file=sys.stderr)


def _env_default(name: str, fallback: str) -> str:
    """Env-var default for a CLI flag, so an operator can override fleet-wide.

    Precedence: an explicit flag (i.e. an action input) > the ``CHARGATE_*`` env var >
    the built-in. This is what lets a self-hosted fleet point every repo at an internal
    mirror by exporting one variable on the runner, without editing 40 workflows — and
    it only works because ``action.yml`` appends these flags conditionally rather than
    always passing its own default.
    """
    return os.environ.get(name, "").strip() or fallback


def _env_int_default(name: str, fallback: int) -> int:
    """:func:`_env_default` for an integer flag, ignoring a non-numeric value.

    Parser construction happens before any subcommand runs, so a typo'd env var must
    not turn `chargate version` into a traceback.
    """
    raw = os.environ.get(name, "").strip()
    return int(raw) if raw.isdigit() else fallback


def _load_sarif(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(_fail(f"SARIF file not found: {path}")) from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(_fail(f"SARIF file is not valid JSON ({path}): {exc}")) from exc


def _fail(message: str) -> int:
    _eprint(f"chargate: error: {message}")
    return EXIT_ERROR


def _build_sops_index(repo: str, sarif: dict[str, Any], policy: FilterPolicy) -> SopsIndex:
    """Index the SOPS-encrypted lines of files that carry a secret finding.

    The IO boundary for the pure SOPS filter — mirrors how :mod:`chargate.git`
    reads git and feeds a pure ``DiffIndex`` to the filter. Only files with a
    secret-scanner finding are read, so a PR with no secret findings does zero file
    reads. A file that can't be read (missing/binary) is skipped, leaving its
    findings eligible to gate.
    """
    if not policy.ignore_sops_encrypted:
        return EMPTY_SOPS_INDEX
    repo_root = Path(repo)
    encrypted: dict[str, frozenset[int]] = {}
    read: set[str] = set()
    for _run_index, _result_index, result, run in iter_results(sarif):
        if not is_secret_result(result, run):
            continue
        uri = primary_uri(result)
        if uri is None:
            continue
        norm = normalize_sarif_uri(uri, policy.strip_prefixes)
        if norm in read:
            continue
        read.add(norm)
        try:
            text = (repo_root / norm).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        lines = scan_encrypted_lines(text)
        if lines:
            encrypted[norm] = lines
    return SopsIndex(encrypted)


def counts_to_dict(result: FilterResult) -> dict[str, Any]:
    c = result.counts
    return {
        "net_new_count": c.net_new,
        "total_count": c.total,
        "pre_existing_count": c.pre_existing,
        "suppressed_count": c.suppressed,
        "sops_ignored_count": c.sops_ignored,
        "deduped_count": c.deduped,
        "per_level_total": c.per_level_total,
        "per_level_net_new": c.per_level_net_new,
        "per_severity_total": c.per_band_total,
        "per_severity_net_new": c.per_band_net_new,
    }


def _print_summary(result: FilterResult, decision: Any) -> None:
    c = result.counts
    _eprint(
        f"chargate: net-new {c.net_new} / {c.total} total "
        f"({c.pre_existing} pre-existing, never blocking)"
    )
    if c.suppressed:
        _eprint(f"chargate: {c.suppressed} suppressed (accepted in-source, never blocking)")
    if c.sops_ignored:
        _eprint(
            f"chargate: {c.sops_ignored} SOPS-encrypted secret finding(s) ignored "
            "(false positives, never blocking)"
        )
    if c.deduped:
        _eprint(
            f"chargate: {c.deduped} duplicate net-new finding(s) collapsed "
            "(same rule + fingerprint from another engine/re-scan)"
        )
    if c.per_band_net_new:
        bands = ", ".join(f"{k}={v}" for k, v in sorted(c.per_band_net_new.items()))
        _eprint(f"chargate: net-new by severity: {bands}")
    if decision.blocking:
        _eprint(
            f"chargate: BLOCKING {len(decision.blocking)} net-new finding(s) "
            f"(fail_on={decision.fail_on}):"
        )
        for verdict in decision.blocking:
            where = verdict.uri or "(no location)"
            if verdict.start_line is not None:
                where = f"{where}:{verdict.start_line}"
            rule = f" [{verdict.rule_id}]" if verdict.rule_id else ""
            _eprint(f"  - {effective_band(verdict)}{rule} {where} ({verdict.reason})")
    elif decision.fail_on == "none":
        _eprint("chargate: report-only (fail_on=none); not gating")
    else:
        _eprint("chargate: no blocking net-new findings")


def _emit_github_output(result: FilterResult, decision: Any) -> None:
    c = result.counts
    report_mod.write_outputs(
        {
            "net_new_count": str(c.net_new),
            "total_count": str(c.total),
            "gate_failed": "true" if decision.failed else "false",
            "gate_result": "fail" if decision.failed else "pass",
        }
    )


def cmd_filter_sarif(args: argparse.Namespace) -> int:
    sarif = _load_sarif(Path(args.sarif))
    try:
        diff_index = cgit.compute_changed_lines(
            args.base, args.head, args.repo, use_merge_base=not args.no_merge_base
        )
    except cgit.GitError as exc:
        return _fail(str(exc))

    policy = FilterPolicy(
        precision=Precision(args.precision),
        no_location_policy=NoLocationPolicy(args.no_location_policy),
        file_level_fallback_when_no_region=not args.no_region_fallback,
        strip_prefixes=tuple(args.strip_prefix or ()),
        ignore_sops_encrypted=not args.no_sops_ignore,
    )
    sops_index = _build_sops_index(args.repo, sarif, policy)
    result = filter_sarif(sarif, diff_index, policy, sops_index)

    try:
        decision = decide_gate(result, args.fail_on)
    except ValueError as exc:
        return _fail(str(exc))

    if args.out:
        Path(args.out).write_text(json.dumps(result.filtered_sarif, indent=2), encoding="utf-8")
    if args.full_out:
        Path(args.full_out).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    if args.counts_json:
        Path(args.counts_json).write_text(
            json.dumps(counts_to_dict(result), indent=2), encoding="utf-8"
        )

    if not args.quiet:
        _print_summary(result, decision)
    _emit_github_output(result, decision)

    if args.no_gate:
        return 0
    return decision.exit_code


def cmd_version(_args: argparse.Namespace) -> int:
    print(__version__)
    return 0


def _policy_from_args(
    args: argparse.Namespace, extra_prefixes: tuple[str, ...] = ()
) -> FilterPolicy:
    prefixes = tuple(args.strip_prefix or ()) + extra_prefixes
    return FilterPolicy(
        precision=Precision(args.precision),
        no_location_policy=NoLocationPolicy(args.no_location_policy),
        file_level_fallback_when_no_region=not args.no_region_fallback,
        strip_prefixes=prefixes,
        ignore_sops_encrypted=not args.no_sops_ignore,
    )


def _render_scan_note(ml_run: ml.MegaLinterRun) -> str | None:
    """One line for the job summary / PR comment describing a non-standard scan.

    A degraded scan that reports nothing is indistinguishable from a clean repo, so
    standalone runs say so on the PR — including which linters were skipped and why.
    """
    if ml_run.strategy != "standalone":
        return None
    note = (
        f"Ran on a `{ml_run.arch}` runner using MegaLinter's per-linter images "
        f"(`megalinter-only-*`) — the flavor image is `linux/amd64` only."
    )
    if ml_run.linters_skipped:
        note += (
            " Skipped: "
            + ", ".join(f"`{key}` ({reason})" for key, reason in ml_run.linters_skipped)
            + "."
        )
    return note


def cmd_ci(args: argparse.Namespace) -> int:
    mode = resolve_mode(args.mode, os.environ.get("GITHUB_EVENT_NAME"))

    # 1. Obtain the full SARIF: use a provided one, or run MegaLinter.
    megalinter_ok = True
    scanned_nothing = False
    scan_note: str | None = None
    scan_mode = "provided" if args.sarif else "flavor"
    linters_skipped: tuple[tuple[str, str], ...] = ()
    if args.sarif:
        sarif_path = Path(args.sarif)
    else:
        # Incremental (changed-files-only) scanning applies to PR/gate mode only;
        # the baseline scan is always whole-repo so its SARIF stays authoritative.
        incremental = args.incremental and mode.gates
        extra_env: dict[str, str] = {}
        if incremental and args.default_branch:
            # MegaLinter needs the base branch to compute the changed-file set.
            extra_env["DEFAULT_BRANCH"] = args.default_branch
        ml_config = ml.MegaLinterConfig(
            flavor=args.flavor,
            image_tag=args.megalinter_tag,
            workspace=args.repo,
            enable_linters=tuple(args.enable_linter or ()),
            disable_linters=tuple(args.disable_linter or ()),
            validate_all_codebase=not incremental,
            extra_env=extra_env,
            registry=args.megalinter_registry,
            namespace=args.megalinter_namespace,
            image_ref=args.megalinter_image,
            platform=args.docker_platform,
            strategy=args.arch_strategy,
            standalone_linters=tuple(args.standalone_linter or ()),
            jobs=args.jobs,
        )
        try:
            ml_run = ml.run(ml_config)
        except ml.MegaLinterError as exc:
            # The architecture guard lands here: a multi-line, actionable message that
            # replaces Docker's `exec /bin/bash: exec format error`.
            return _fail(str(exc))
        except OSError as exc:
            return _fail(f"could not run MegaLinter (is Docker available?): {exc}")
        megalinter_ok = ml_run.returncode == 0
        scan_mode = ml_run.strategy
        linters_skipped = ml_run.linters_skipped
        scan_note = _render_scan_note(ml_run)
        if ml_run.strategy == "standalone" and not args.quiet:
            _eprint(
                f"chargate: {ml_run.arch} runner — ran {len(ml_run.linters_run)} MegaLinter "
                f"standalone linter image(s): {', '.join(ml_run.linters_run)}"
            )
            for key, reason in ml_run.linters_skipped:
                _eprint(f"chargate: skipped {key} — {reason}")
        try:
            sarif_path = ml.locate_sarif(ml_config)
        except ml.MegaLinterError as exc:
            return _fail(str(exc))

    sarif = _load_sarif(sarif_path)

    # Fold "Trivy (MegaLinter REPOSITORY_TRIVY)" back to "Trivy" before anything consumes
    # the document, so the Security tab lists one entry per scanner instead of one per
    # MegaLinter descriptor key. Done here rather than per-sink so the tab, DefectDojo,
    # the artifact and the PR comments cannot disagree about a tool's name.
    canonicalize_tool_names(sarif)

    # A SARIF with no runs is indistinguishable from a clean repo at the gate, so say
    # so out loud. This is the exact shape the relative-REPORT_OUTPUT_FOLDER bug took:
    # a well-formed document that had scanned nothing, gating on nothing, for months.
    #
    # It is fatal on its own, NOT only under --strict. `--strict` means "a linter blew
    # up, decide whether that counts"; this is a different claim — the gate scanned
    # nothing at all, so a pass carries no information. Routing it through --strict
    # (default false) would have left every consumer of the org-wide required check
    # green on an empty report, which is the exact bug this repo spent months not
    # noticing. A gate that cannot fail must not be allowed to pass.
    if not args.sarif and not (sarif.get("runs") or []):
        _eprint(
            "chargate: ERROR: MegaLinter's SARIF contains no runs — nothing was scanned, "
            "so the gate cannot block anything. Check the MegaLinter output above."
        )
        megalinter_ok = False
        scanned_nothing = True

    # 2. Always preserve the full SARIF as the shippable artifact.
    if args.sarif_out:
        Path(args.sarif_out).write_text(json.dumps(sarif, indent=2), encoding="utf-8")

    # 3. Net-new gate on PR events; baseline scans never gate.
    if mode.gates:
        if not args.base:
            return _fail("PR/gate mode needs --base (the PR target ref).")
        try:
            diff_index = cgit.compute_changed_lines(
                args.base, args.head, args.repo, use_merge_base=not args.no_merge_base
            )
        except cgit.GitError as exc:
            return _fail(str(exc))
        repo_abs = str(Path(args.repo).resolve())
        policy = _policy_from_args(args, extra_prefixes=(ml.CONTAINER_WORKSPACE, repo_abs))
        sops_index = _build_sops_index(args.repo, sarif, policy)
        result = filter_sarif(sarif, diff_index, policy, sops_index)
        try:
            decision = decide_gate(result, args.fail_on)
        except ValueError as exc:
            return _fail(str(exc))
    else:
        # Baseline: count everything, gate nothing.
        result = filter_sarif(sarif, DiffIndex(()))
        decision = decide_gate(result, "none")

    if args.filtered_out:
        Path(args.filtered_out).write_text(
            json.dumps(result.filtered_sarif, indent=2), encoding="utf-8"
        )
    if args.counts_json:
        Path(args.counts_json).write_text(
            json.dumps(counts_to_dict(result), indent=2), encoding="utf-8"
        )

    # 4. Optional DefectDojo import of the FULL SARIF (never fails the gate).
    dd = _maybe_import_defectdojo(args, sarif)

    # 4b. Optional Dependency-Track upload of the CycloneDX BOM (never fails the gate).
    dt = _maybe_upload_dependencytrack(args)

    # 4c. Optional GHAS-style PR comments — net-new only (never fails the gate).
    #     The footer links to wherever the SARIF / BOM just landed.
    pr_message = _maybe_comment_pr(
        args,
        result,
        decision,
        mode,
        defectdojo_url=dd.url,
        dependency_track_url=dt.url,
        scan_note=scan_note,
    )

    # 5. Report.
    summary = report_mod.render_summary(
        result.counts,
        decision,
        mode,
        megalinter_ok=megalinter_ok,
        dd_message=dd.message,
        dt_message=dt.message,
        pr_message=pr_message,
        scan_note=scan_note,
    )
    report_mod.append_step_summary(summary)
    if not args.quiet:
        _print_summary(result, decision)
        if dd.message:
            _eprint(f"chargate: DefectDojo: {dd.message}")
        if dt.message:
            _eprint(f"chargate: Dependency-Track: {dt.message}")
        if pr_message:
            _eprint(f"chargate: PR comments: {pr_message}")
    report_mod.write_outputs(
        {
            "mode": mode.value,
            "net_new_count": str(result.counts.net_new),
            "total_count": str(result.counts.total),
            "gate_failed": "true" if decision.failed else "false",
            "gate_result": "fail" if decision.failed else "pass",
            # How the scan actually ran, so a consumer can assert it was NOT degraded
            # (e.g. fail a release job on scan_mode != 'flavor'). Kept single-line:
            # write_outputs emits bare key=value, which cannot carry a newline.
            "scan_mode": scan_mode,
            "linters_skipped": "; ".join(f"{key} ({reason})" for key, reason in linters_skipped),
        }
    )

    # 6. Exit. A scan that produced no runs always fails; a MegaLinter tool error only
    #    fails under --strict (see the runs check above for why they differ).
    if scanned_nothing:
        return _fail("MegaLinter's SARIF contains no runs — the gate scanned nothing.")
    if not megalinter_ok and args.strict:
        return _fail("MegaLinter did not complete cleanly (strict mode).")
    return decision.exit_code


class _SinkOutcome(NamedTuple):
    """A sink's human message plus a UI link to where it landed (both optional)."""

    message: str | None = None
    url: str | None = None


def _maybe_import_defectdojo(args: argparse.Namespace, sarif_doc: dict[str, Any]) -> _SinkOutcome:
    if not args.defectdojo_url:
        return _SinkOutcome()
    token = os.environ.get(args.defectdojo_token_env, "")
    if not token:
        return _SinkOutcome(f"skipped (no token in ${args.defectdojo_token_env})")
    config = dd.DefectDojoConfig(
        base_url=args.defectdojo_url,
        token=token,
        product_name=args.dd_product,
        product_type_name=args.dd_product_type,
        engagement_name=args.dd_engagement,
        engagement_id=args.dd_engagement_id,
        reimport=not args.dd_import,
        close_old_findings=not args.dd_no_close_old,
        test_title=args.dd_test_title,
        tags=tuple(args.dd_tag or ()),
        verify_ssl=not args.dd_insecure,
    )
    # Serialize the already-canonicalized in-memory document so the upload always
    # carries folded tool names regardless of whether --sarif-out was passed.
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".sarif.json", delete=False, encoding="utf-8"
    ) as f:
        json.dump(sarif_doc, f)
        tmp_path = Path(f.name)
    try:
        result = dd.import_sarif(config, tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)
    if result.ok:
        return _SinkOutcome(result.message, result.url)
    return _SinkOutcome(f"upload failed (non-blocking): {result.message}")


def _maybe_upload_dependencytrack(args: argparse.Namespace) -> _SinkOutcome:
    if not args.dependency_track_url:
        return _SinkOutcome()
    if not args.dt_project_uuid and not args.dt_project_name:
        return _SinkOutcome("skipped (need --dt-project-uuid or --dt-project-name)")
    api_key = os.environ.get(args.dt_api_key_env, "")
    if not api_key:
        return _SinkOutcome(f"skipped (no API key in ${args.dt_api_key_env})")
    config = dt.DependencyTrackConfig(
        base_url=args.dependency_track_url,
        api_key=api_key,
        project_name=args.dt_project_name,
        project_version=args.dt_project_version,
        project_uuid=args.dt_project_uuid,
        auto_create=not args.dt_no_auto_create,
        parent_name=args.dt_parent_name,
        parent_version=args.dt_parent_version,
        is_latest=args.dt_is_latest,
        verify_ssl=not args.dt_insecure,
    )

    # No --bom → don't upload (e.g. on PRs); just resolve the project link so the
    # PR comment can point at the existing (default-branch) project.
    if not args.bom:
        url, reason = dt.resolve_project_link(config)
        return _SinkOutcome("linked" if url else (reason or "no link (upload skipped)"), url)

    bom_path = Path(args.bom)
    if not bom_path.is_file():
        return _SinkOutcome(f"skipped (BOM not found: {bom_path})")
    result = dt.upload_bom(config, bom_path)
    if result.ok:
        return _SinkOutcome(result.message, result.project_url)
    return _SinkOutcome(f"upload failed (non-blocking): {result.message}")


def _resolve_head_sha(args: argparse.Namespace) -> str:
    """Resolve the PR head to a full SHA for anchoring inline comments.

    In CI ``--head`` is already the PR head SHA; ``rev-parse`` returns it unchanged
    and also handles the local ``HEAD`` case. On failure, fall back to the literal
    ref (likely already a SHA), or "" for ``HEAD`` which can't anchor inline.
    """
    try:
        return cgit.rev_parse(args.head, args.repo)
    except cgit.GitError:
        return "" if args.head == "HEAD" else args.head


def _maybe_comment_pr(
    args: argparse.Namespace,
    result: FilterResult,
    decision: Any,
    mode: Mode,
    *,
    defectdojo_url: str | None = None,
    dependency_track_url: str | None = None,
    scan_note: str | None = None,
) -> str | None:
    """Post GHAS-style PR comments for net-new findings. Never fails the gate."""
    if not args.pr_comment or not mode.gates:
        return None
    if not args.pr_number or not args.repo_slug:
        return "skipped (need --pr-number and --repo-slug)"
    token = os.environ.get(args.github_token_env, "")
    if not token:
        return f"skipped (no token in ${args.github_token_env})"

    net_new = list(result.net_new)

    # Inline comments only on findings guaranteed to sit on a changed line.
    inline_comments: list[ghc.InlineComment] | None = None
    note: str | None = None
    if args.pr_comment_mode in ("inline", "both"):
        eligible = [v for v in net_new if v.inline_safe and v.uri and v.start_line]
        dropped = max(0, len(eligible) - args.pr_comment_max_inline)
        shown = eligible[: args.pr_comment_max_inline]
        inline_comments = [
            ghc.InlineComment(
                path=v.uri,  # type: ignore[arg-type]  # filtered to truthy uri above
                line=v.start_line,  # type: ignore[arg-type]  # filtered to truthy start_line
                body=report_mod.render_inline_body(v),
            )
            for v in shown
        ]
        if dropped:
            note = (
                f"_Posted {len(shown)} inline comment(s); {dropped} more net-new "
                f"finding(s) are listed above (inline cap)._"
            )

    summary_body: str | None = None
    if args.pr_comment_mode in ("summary", "both"):
        summary_body = report_mod.render_pr_summary(
            result.counts,
            decision,
            mode,
            net_new,
            note=note,
            defectdojo_url=defectdojo_url,
            dependency_track_url=dependency_track_url,
            scan_note=scan_note,
        )

    config = ghc.GitHubCommentConfig(
        base_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        repo_slug=args.repo_slug,
        pr_number=args.pr_number,
        commit_id=_resolve_head_sha(args),
        token=token,
        verify_ssl=not args.pr_comment_insecure,
    )
    posted = ghc.post_pr_feedback(
        config, summary_body=summary_body, inline_comments=inline_comments
    )
    return posted.message if posted.ok else f"comment failed (non-blocking): {posted.message}"


def cmd_local(args: argparse.Namespace) -> int:
    files = list(args.files) if args.files else local_mod.staged_files(args.repo)
    if not files:
        if not args.quiet:
            _eprint("chargate: no staged files to check")
        return EXIT_OK
    code, outcomes = local_mod.run_local(files)
    if not args.quiet:
        for outcome in outcomes:
            marker = {"ok": "✔", "findings": "✗", "skipped": "·"}.get(outcome.status, "?")
            detail = f" ({outcome.detail})" if outcome.detail else ""
            _eprint(f"chargate {marker} {outcome.name}{detail}")
    return code


def cmd_install_hooks(args: argparse.Namespace) -> int:
    try:
        messages = install_hooks(force=args.force)
    except HookInstallError as exc:
        return _fail(str(exc))
    for message in messages:
        _eprint(f"chargate: {message}")
    return EXIT_OK


def cmd_uninstall_hooks(_args: argparse.Namespace) -> int:
    try:
        messages = uninstall_hooks()
    except HookInstallError as exc:
        return _fail(str(exc))
    for message in messages:
        _eprint(f"chargate: {message}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chargate",
        description="MegaLinter-backed security + lint gate with net-new (PR-diff) finding gating.",
    )
    parser.add_argument("--version", action="version", version=f"chargate {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    fs = sub.add_parser(
        "filter-sarif",
        help="Filter a SARIF report to net-new findings and gate on them.",
        description=(
            "Given a SARIF report and a base/head, keep only findings the diff "
            "introduces and decide pass/fail. The full SARIF is never mutated."
        ),
    )
    fs.add_argument("--sarif", required=True, help="Path to the (full) SARIF report.")
    fs.add_argument("--base", required=True, help="Base ref/SHA (PR target).")
    fs.add_argument("--head", default="HEAD", help="Head ref/SHA (default: HEAD).")
    fs.add_argument("--repo", default=".", help="Path to the git repository (default: .).")
    fs.add_argument(
        "--precision",
        choices=[p.value for p in Precision],
        default=Precision.LINE.value,
        help="Net-new precision (default: line).",
    )
    fs.add_argument(
        "--no-location-policy",
        choices=[p.value for p in NoLocationPolicy],
        default=NoLocationPolicy.IGNORE.value,
        help="Treatment of results with no file location (default: ignore = never block).",
    )
    fs.add_argument(
        "--no-region-fallback",
        action="store_true",
        help="Disable file-level fallback for changed-file results lacking a startLine.",
    )
    fs.add_argument(
        "--no-sops-ignore",
        action="store_true",
        help="Gate on secret-scanner hits even on SOPS-encrypted values (ENC[AES256_GCM,...]).",
    )
    fs.add_argument(
        "--strip-prefix",
        action="append",
        metavar="PREFIX",
        help="Path prefix to strip from SARIF URIs before matching (repeatable).",
    )
    fs.add_argument(
        "--no-merge-base",
        action="store_true",
        help="Diff base..head directly instead of merge-base(base, head)..head.",
    )
    fs.add_argument("--out", help="Write the net-new-only filtered SARIF here.")
    fs.add_argument("--full-out", help="Write a copy of the full (unfiltered) SARIF here.")
    fs.add_argument("--counts-json", help="Write the counts summary as JSON here.")
    fs.add_argument(
        "--fail-on",
        choices=list(FAIL_ON_CHOICES),
        default="any",
        help="Severity threshold that blocks (default: any net-new finding).",
    )
    fs.add_argument("--no-gate", action="store_true", help="Always exit 0 (report only).")
    fs.add_argument("--quiet", action="store_true", help="Suppress the human summary.")
    fs.set_defaults(func=cmd_filter_sarif)

    ci = sub.add_parser(
        "ci",
        help="Full CI flow: run MegaLinter, filter net-new, gate, ship full SARIF.",
        description=(
            "Run MegaLinter whole-repo (it never sets the gate), then on PR events "
            "gate on net-new findings. The full SARIF is always preserved/shipped."
        ),
    )
    ci.add_argument(
        "--mode",
        choices=["auto", *[m.value for m in Mode]],
        default="auto",
        help="auto (from GITHUB_EVENT_NAME), pr (net-new gate), or baseline (no gate).",
    )
    ci.add_argument("--base", help="Base ref/SHA (required in PR/gate mode).")
    ci.add_argument("--head", default="HEAD", help="Head ref/SHA (default: HEAD).")
    ci.add_argument("--repo", default=".", help="Path to the git repository (default: .).")
    ci.add_argument("--sarif", help="Use this existing SARIF instead of running MegaLinter.")
    ci.add_argument(
        "--flavor", default="all", help="MegaLinter flavor (default: all = full image)."
    )
    ci.add_argument(
        "--megalinter-tag",
        default=_env_default("CHARGATE_MEGALINTER_TAG", ml.DEFAULT_TAG),
        help=f"MegaLinter image tag, or a sha256: digest to pin (default: {ml.DEFAULT_TAG}).",
    )
    ci.add_argument(
        "--megalinter-registry",
        default=_env_default("CHARGATE_MEGALINTER_REGISTRY", ml.DEFAULT_REGISTRY),
        help=(
            "Registry host for the MegaLinter images (default: ghcr.io). MegaLinter froze "
            "Docker Hub publishing at v9.4.0, so docker.io cannot serve v9.5.0+."
        ),
    )
    ci.add_argument(
        "--megalinter-namespace",
        default=_env_default("CHARGATE_MEGALINTER_NAMESPACE", ml.DEFAULT_NAMESPACE),
        help="Image namespace (default: oxsecurity). Set for a mirror / pull-through cache.",
    )
    ci.add_argument(
        "--megalinter-image",
        default=_env_default("CHARGATE_MEGALINTER_IMAGE", ""),
        help=(
            "Full image reference, overriding registry/namespace/flavor/tag entirely — e.g. a "
            "custom flavor: ghcr.io/you/repo/megalinter-custom-flavor:v10.0.0."
        ),
    )
    ci.add_argument(
        "--docker-platform",
        default=_env_default("CHARGATE_DOCKER_PLATFORM", ""),
        help="Value for `docker run --platform` (e.g. linux/amd64 to force qemu emulation).",
    )
    ci.add_argument(
        "--arch-strategy",
        choices=list(ml.ARCH_STRATEGIES),
        default=_env_default("CHARGATE_ARCH_STRATEGY", "auto"),
        help=(
            "auto (default): the flavor image on amd64, MegaLinter's per-linter "
            "megalinter-only-* images on arm64. flavor: always the flavor image. "
            "standalone: always per-linter images. fail: refuse to run on a non-amd64 "
            "daemon rather than degrading."
        ),
    )
    ci.add_argument(
        "--standalone-linter",
        action="append",
        metavar="KEY",
        help="Linter key to run in standalone mode (repeatable). Default: the flavor's set.",
    )
    ci.add_argument(
        "--jobs",
        type=int,
        default=_env_int_default("CHARGATE_JOBS", 4),
        help="Standalone mode: how many linter containers to run at once (default: 4).",
    )
    ci.add_argument(
        "--enable-linter", action="append", metavar="KEY", help="Enable a linter (repeatable)."
    )
    ci.add_argument(
        "--disable-linter", action="append", metavar="KEY", help="Disable a linter (repeatable)."
    )
    ci.add_argument(
        "--incremental",
        action="store_true",
        help=(
            "PR/gate mode only: run MegaLinter over just the files changed vs the base "
            "(VALIDATE_ALL_CODEBASE=false) instead of the whole repo — faster on large "
            "repos. The net-new gate still uses chargate's own diff; the baseline (push) "
            "scan is always whole-repo."
        ),
    )
    ci.add_argument(
        "--default-branch",
        default="",
        help="Base branch for incremental change detection (sets MegaLinter DEFAULT_BRANCH).",
    )
    ci.add_argument(
        "--precision",
        choices=[p.value for p in Precision],
        default=Precision.LINE.value,
        help="Net-new precision (default: line).",
    )
    ci.add_argument(
        "--no-location-policy",
        choices=[p.value for p in NoLocationPolicy],
        default=NoLocationPolicy.IGNORE.value,
        help="Treatment of results with no file location (default: ignore).",
    )
    ci.add_argument(
        "--no-region-fallback",
        action="store_true",
        help="Disable file-level fallback for no-region results.",
    )
    ci.add_argument(
        "--no-sops-ignore",
        action="store_true",
        help="Gate on secret-scanner hits even on SOPS-encrypted values (ENC[AES256_GCM,...]).",
    )
    ci.add_argument(
        "--strip-prefix",
        action="append",
        metavar="PREFIX",
        help="Extra SARIF URI prefix to strip (repeatable).",
    )
    ci.add_argument("--no-merge-base", action="store_true", help="Diff base..head directly.")
    ci.add_argument(
        "--fail-on",
        choices=list(FAIL_ON_CHOICES),
        default="any",
        help="Severity threshold that blocks (default: any net-new).",
    )
    ci.add_argument("--sarif-out", help="Write the full (unfiltered) SARIF here (the artifact).")
    ci.add_argument("--filtered-out", help="Write the net-new-only SARIF here.")
    ci.add_argument("--counts-json", help="Write the counts summary as JSON here.")
    ci.add_argument("--strict", action="store_true", help="Fail if MegaLinter itself errors.")
    ci.add_argument(
        "--defectdojo-url", help="DefectDojo base URL (enables import of the full SARIF)."
    )
    ci.add_argument(
        "--defectdojo-token-env",
        default="DEFECTDOJO_TOKEN",
        help="Env var holding the DD API token.",
    )
    ci.add_argument("--dd-product", help="DefectDojo product name.")
    ci.add_argument(
        "--dd-product-type",
        help="DefectDojo product type name (required to auto-create a new product).",
    )
    ci.add_argument("--dd-engagement", help="DefectDojo engagement name.")
    ci.add_argument("--dd-engagement-id", type=int, help="DefectDojo engagement id.")
    ci.add_argument("--dd-test-title", help="DefectDojo test title.")
    ci.add_argument("--dd-tag", action="append", metavar="TAG", help="DefectDojo tag (repeatable).")
    ci.add_argument(
        "--dd-import", action="store_true", help="Use import-scan instead of reimport-scan."
    )
    ci.add_argument(
        "--dd-no-close-old", action="store_true", help="Do not close old findings on reimport."
    )
    ci.add_argument(
        "--dd-insecure", action="store_true", help="Disable TLS verification for DefectDojo."
    )
    ci.add_argument(
        "--dependency-track-url",
        help="Dependency-Track base URL (enables CycloneDX BOM upload).",
    )
    ci.add_argument(
        "--dt-api-key-env",
        default="DEPENDENCYTRACK_API_KEY",
        help="Env var holding the Dependency-Track API key.",
    )
    ci.add_argument("--bom", help="Path to the CycloneDX BOM to upload to Dependency-Track.")
    ci.add_argument("--dt-project-name", help="Dependency-Track project name.")
    ci.add_argument("--dt-project-version", help="Dependency-Track project version.")
    ci.add_argument(
        "--dt-project-uuid",
        help="Existing Dependency-Track project UUID (instead of name+version).",
    )
    ci.add_argument(
        "--dt-no-auto-create",
        action="store_true",
        help="Do not auto-create the project/version on first upload.",
    )
    ci.add_argument("--dt-parent-name", help="Parent project name (for project hierarchy).")
    ci.add_argument("--dt-parent-version", help="Parent project version.")
    ci.add_argument(
        "--dt-is-latest",
        action="store_true",
        help="Mark this version as the latest in Dependency-Track.",
    )
    ci.add_argument(
        "--dt-insecure", action="store_true", help="Disable TLS verification for Dependency-Track."
    )
    ci.add_argument(
        "--pr-comment",
        action="store_true",
        help="Post GHAS-style PR comments for net-new findings (PR/gate mode only).",
    )
    ci.add_argument("--pr-number", type=int, help="Pull request number to comment on.")
    ci.add_argument("--repo-slug", help="owner/repo of the pull request.")
    ci.add_argument(
        "--github-token-env",
        default="GITHUB_TOKEN",
        help="Env var holding the GitHub token (needs pull-requests: write).",
    )
    ci.add_argument(
        "--pr-comment-mode",
        choices=["summary", "inline", "both"],
        default="both",
        help="What to post: one summary comment, inline annotations, or both (default).",
    )
    ci.add_argument(
        "--pr-comment-max-inline",
        type=int,
        default=50,
        help="Cap on inline comments per run; the rest are listed in the summary.",
    )
    ci.add_argument(
        "--pr-comment-insecure",
        action="store_true",
        help="Disable TLS verification for the GitHub API (GHES testing).",
    )
    ci.add_argument("--quiet", action="store_true", help="Suppress the human summary.")
    ci.set_defaults(func=cmd_ci)

    local = sub.add_parser(
        "local",
        help="Fast staged-file checks for pre-commit (a first line, not the full CI net).",
    )
    local.add_argument("files", nargs="*", help="Files to check (pre-commit passes staged files).")
    local.add_argument("--repo", default=".", help="Path to the git repository (default: .).")
    local.add_argument("--quiet", action="store_true", help="Suppress per-check output.")
    local.set_defaults(func=cmd_local)

    install = sub.add_parser(
        "install-hooks",
        help="Install chargate's git hooks globally for all repos (via pre-commit).",
        description=(
            "Wire chargate's hooks into git globally using the pre-commit framework: "
            "generate pre-commit + pre-push dispatchers, point core.hooksPath at them "
            "(retroactive across existing repos) and set init.templateDir (for new "
            "clones), backed by a managed ~/.pre-commit-config.yaml. Requires pre-commit."
        ),
    )
    install.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing, non-chargate ~/.pre-commit-config.yaml.",
    )
    install.set_defaults(func=cmd_install_hooks)

    uninstall = sub.add_parser(
        "uninstall-hooks",
        help="Revert `install-hooks`, restoring the prior global git config.",
    )
    uninstall.set_defaults(func=cmd_uninstall_hooks)

    version = sub.add_parser("version", help="Print the chargate version.")
    version.set_defaults(func=cmd_version)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

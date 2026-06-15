"""Chargate command-line interface.

Subcommands:

* ``chargate filter-sarif`` — the pure net-new filter (SARIF + base/head →
  filtered SARIF + counts + gate exit code). Decoupled from GitHub Actions and
  unit-tested in isolation.
* ``chargate ci`` — the full CI flow (run MegaLinter, filter, gate, ship). Added
  in a later increment.
* ``chargate version`` — print the version.

Exit codes: ``0`` pass · ``1`` blocking net-new findings · ``2`` setup/usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from chargate import __version__
from chargate import defectdojo as dd
from chargate import git as cgit
from chargate import local as local_mod
from chargate import megalinter as ml
from chargate import report as report_mod
from chargate.gate import EXIT_ERROR, EXIT_OK, FAIL_ON_CHOICES, decide_gate, effective_band
from chargate.modes import Mode, resolve_mode
from chargate.sarif.diff import DiffIndex
from chargate.sarif.filter import (
    FilterPolicy,
    FilterResult,
    NoLocationPolicy,
    Precision,
    filter_sarif,
)


def _eprint(message: str) -> None:
    print(message, file=sys.stderr)


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


def counts_to_dict(result: FilterResult) -> dict[str, Any]:
    c = result.counts
    return {
        "net_new_count": c.net_new,
        "total_count": c.total,
        "pre_existing_count": c.pre_existing,
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
    )
    result = filter_sarif(sarif, diff_index, policy)

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
    )


def cmd_ci(args: argparse.Namespace) -> int:
    mode = resolve_mode(args.mode, os.environ.get("GITHUB_EVENT_NAME"))

    # 1. Obtain the full SARIF: use a provided one, or run MegaLinter.
    megalinter_ok = True
    if args.sarif:
        sarif_path = Path(args.sarif)
    else:
        ml_config = ml.MegaLinterConfig(
            flavor=args.flavor,
            image_tag=args.megalinter_tag,
            workspace=args.repo,
            enable_linters=tuple(args.enable_linter or ()),
            disable_linters=tuple(args.disable_linter or ()),
        )
        try:
            ml_run = ml.run(ml_config)
        except OSError as exc:
            return _fail(f"could not run MegaLinter (is Docker available?): {exc}")
        megalinter_ok = ml_run.returncode == 0
        try:
            sarif_path = ml.locate_sarif(ml_config)
        except ml.MegaLinterError as exc:
            return _fail(str(exc))

    sarif = _load_sarif(sarif_path)

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
        result = filter_sarif(sarif, diff_index, policy)
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
    dd_message = _maybe_import_defectdojo(
        args, sarif_path if not args.sarif_out else Path(args.sarif_out)
    )

    # 5. Report.
    summary = report_mod.render_summary(
        result.counts, decision, mode, megalinter_ok=megalinter_ok, dd_message=dd_message
    )
    report_mod.append_step_summary(summary)
    if not args.quiet:
        _print_summary(result, decision)
        if dd_message:
            _eprint(f"chargate: DefectDojo: {dd_message}")
    report_mod.write_outputs(
        {
            "mode": mode.value,
            "net_new_count": str(result.counts.net_new),
            "total_count": str(result.counts.total),
            "gate_failed": "true" if decision.failed else "false",
            "gate_result": "fail" if decision.failed else "pass",
        }
    )

    # 6. Exit. A MegaLinter tool error only fails under --strict.
    if not megalinter_ok and args.strict:
        return _fail("MegaLinter did not complete cleanly (strict mode).")
    return decision.exit_code


def _maybe_import_defectdojo(args: argparse.Namespace, sarif_path: Path) -> str | None:
    if not args.defectdojo_url:
        return None
    token = os.environ.get(args.defectdojo_token_env, "")
    if not token:
        return f"skipped (no token in ${args.defectdojo_token_env})"
    config = dd.DefectDojoConfig(
        base_url=args.defectdojo_url,
        token=token,
        product_name=args.dd_product,
        engagement_name=args.dd_engagement,
        engagement_id=args.dd_engagement_id,
        reimport=not args.dd_import,
        close_old_findings=not args.dd_no_close_old,
        test_title=args.dd_test_title,
        tags=tuple(args.dd_tag or ()),
        verify_ssl=not args.dd_insecure,
    )
    result = dd.import_sarif(config, sarif_path)
    return result.message if result.ok else f"upload failed (non-blocking): {result.message}"


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
    ci.add_argument("--megalinter-tag", default=ml.DEFAULT_TAG, help="MegaLinter image tag/digest.")
    ci.add_argument(
        "--enable-linter", action="append", metavar="KEY", help="Enable a linter (repeatable)."
    )
    ci.add_argument(
        "--disable-linter", action="append", metavar="KEY", help="Disable a linter (repeatable)."
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

    version = sub.add_parser("version", help="Print the chargate version.")
    version.set_defaults(func=cmd_version)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

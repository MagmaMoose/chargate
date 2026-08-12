# Architecture

Chargate is one `chargate` Python CLI (`src/chargate/cli.py:main`) behind two
GitHub surfaces (a composite action and a pre-commit hook). The design splits
cleanly into a **pure core** and a thin set of **side-effecting edges**.

## Module map

```
src/chargate/
  cli.py          # argparse dispatch: filter-sarif | ci | local | install-hooks | uninstall-hooks | version
  sarif/          # ★ THE PURE CORE — deterministic, no I/O, heavily tested
    diff.py       #   unified-diff text -> DiffIndex (changed files + added line ranges)
    model.py      #   defensive SARIF result accessors (uri, startLine, level, severity)
    filter.py     #   net-new classification + FilterPolicy + filter_sarif()
    counts.py     #   totals + per-severity breakdowns
    sops.py       #   detect SOPS-encrypted values so secret scanners don't gate on them
  git.py          # the ONLY git/subprocess boundary (merge-base, diff, shallow detect)
  gate.py         # net-new verdicts + fail_on threshold -> pass/fail + exit code
  megalinter.py   # build env/command, run, locate the merged SARIF
  defectdojo.py       # SARIF import/reimport client (urllib, failure-isolated, never raises)
  dependencytrack.py  # CycloneDX BOM upload client (urllib, failure-isolated, never raises)
  github_comment.py   # GHAS-style PR comment client (urllib, failure-isolated, never raises)
  install_hooks.py    # global git-hook installer (backs install-hooks / uninstall-hooks)
  modes.py        # PR (gate) vs baseline (no gate) resolution
  report.py       # GitHub job summary + PR comment bodies + step outputs
  local.py        # pre-commit fast staged-file runner
```

A structured, machine-readable version (exports, dependencies, call graph,
hotspots) lives at [`PROJECT_INDEX.json`](https://github.com/MagmaMoose/chargate/blob/main/PROJECT_INDEX.json)
in the repo root.

Separate from the CLI, the **token broker** (`broker/`) is a small FastAPI service
— see [The token broker](#the-token-broker) below.

## The design rule

`sarif/` is **pure**: it takes already-parsed data (a SARIF dict + a `DiffIndex`)
and returns verdicts. `git.py` is the only thing that shells out, so the filter is
unit-tested with synthetic diff text and SARIF dicts — no real repository
required.

!!! warning "Keep the boundary"
    Do **not** import `subprocess`, `os`, network code, or GitHub Actions into
    `sarif/`. That separation is what makes the crown-jewel filter trivially
    testable and deterministic.

## Data flow (PR / gate mode)

1. **`modes.resolve_mode`** decides PR (gate) vs baseline (no gate) from
   `GITHUB_EVENT_NAME` or an explicit flag.
2. **`megalinter.run`** runs MegaLinter whole-repo with `DISABLE_ERRORS=true` (so
   MegaLinter never sets the exit code) and locates the merged SARIF.
3. **`git.compute_changed_lines`** resolves `merge-base(base, head)`, runs
   `git diff --unified=0`, and hands the text to `sarif.diff.parse_unified_diff` →
   a `DiffIndex`.
4. **`sarif.filter.filter_sarif`** classifies every result as net-new or
   pre-existing under a `FilterPolicy`, returning a pruned deep copy (net-new
   only), per-result verdicts, and `Counts`. The input SARIF is never mutated.
5. **`gate.decide_gate`** applies the `fail_on` threshold to the net-new set →
   a `GateDecision` and exit code.
6. **`defectdojo.import_sarif`** and **`dependencytrack.upload_bom`** (both
   optional, each active iff its host/URL is set) ship the **full** SARIF and a
   CycloneDX BOM respectively. Both are failure-isolated: they never raise, so a
   sink outage can't fail the gate.
7. **`github_comment.post_pr_feedback`** (PR events, opt-out) posts the net-new
   findings as one updatable summary comment + inline review comments. Also
   failure-isolated — a GitHub API error never changes the gate outcome.
8. **`report`** writes the GitHub job summary and step outputs.

Baseline mode skips steps 3–5's gating: it counts everything against an empty
`DiffIndex` with `fail_on=none`, ships the full SARIF, and never blocks.

## Exit-code contract

| Code | Meaning |
| --- | --- |
| `0` | pass |
| `1` | blocking net-new finding(s) |
| `2` | setup / tool / usage error |

A *broken* scanner is a tool error (`2`), never a finding. A MegaLinter tool
failure only fails the job under `--strict`.

One condition is fatal **without** `--strict`: a SARIF carrying no `runs` at all.
That is not a linter misbehaving, it is the gate having scanned nothing, so a pass
carries no information — and since `strict` defaults to off, routing it through
`strict` would leave a repo green on an empty report indefinitely. That is precisely
how the relative-`REPORT_OUTPUT_FOLDER` bug survived for months.

## The token broker

To author PR comments as `Chargate[bot]` rather than `github-actions[bot]`, the
action exchanges the run's GitHub Actions **OIDC token** for a short-lived
Chargate App installation token. That exchange is done by a small **FastAPI
service in [`broker/`](https://github.com/MagmaMoose/chargate/tree/main/broker)** —
a *separate deployable*, not part of the CLI wheel (it keeps its FastAPI/httpx/PyJWT
dependencies in a dedicated `broker` dependency-group so the CLI stays
runtime-dependency-free).

`POST /token` verifies the OIDC token (issuer-pinned, audience `chargate`, and the
`repository` claim **must** equal the requested `owner/repo`) and mints a token
scoped to that repo with `pull_requests: write` only. The whole flow is
**fail-soft**: without `id-token: write`, or if the App isn't installed, the action
silently falls back to `github-actions[bot]`. The service ships as the
`ghcr.io/magmamoose/chargate` image and is deployed out-of-band (Kustomize manifests
under `k8s/`); operating it — the GitHub App, its private key in a secret store, and
installing the App on consumer orgs — is the operator's responsibility. See
[PR comments → *Comment as `Chargate[bot]`*](setup.md#pr-comments-ghas-style) for the
consumer-side setup.

## Testing

Tests mirror modules 1:1 under `tests/` (e.g. `test_sarif_filter.py`,
`test_gate.py`, `test_git.py`); the broker has its own tests under `broker/tests`.
The pure core is tested with synthetic inputs; the subprocess and HTTP boundaries
inject their runner/opener so they are exercised without Docker, git, or a live
DefectDojo / Dependency-Track.

# Net-new gating

A SARIF result is **net-new** (and therefore gate-blocking) iff its primary
location's file is in the PR diff **and** — at line precision — its `startLine`
falls inside an added/modified hunk. The diff is computed against
`merge-base(base, head)`, which is robust to base-branch rebases and force-pushes.

## Classification rules

| Case | Policy (default) | Configurable |
| --- | --- | --- |
| Brand-new file | all results net-new | — |
| Modified hunk | net-new iff `startLine` in an added range | `precision: line\|file` |
| Unchanged line in a changed file | pre-existing → never blocks | `precision: file` to flip |
| Renamed / copied file | matched by head path; content changes line-matched | — |
| Deleted file | dropped | — |
| Result with **no** file location (project-level: SBOM/license/some Trivy) | **not** net-new | `--no-location-policy block` |
| Changed file, result with no `startLine` (common for SCA on a lockfile) | net-new (file-level fallback) | `--no-region-fallback` to disable |
| Secret-scanner hit on a **SOPS-encrypted** value (`ENC[AES256_GCM,...]`) | dropped as a false positive → never blocks | `ignore_sops_encrypted: false` / `--no-sops-ignore` |
| Multiple locations | uses the **primary** (`locations[0]`) | documented |
| Missing merge-base / shallow clone | **fails loudly** — needs `fetch-depth: 0` | — |

These knobs are expressed on `FilterPolicy` in
`src/chargate/sarif/filter.py`. The file-level fallback exists so a genuinely
PR-introduced dependency vulnerability attached to a changed lockfile (no
`startLine`) still blocks, while truly project-global findings (no file at all)
fall under the no-location policy.

## SOPS-encrypted secrets

Files encrypted with [SOPS](https://github.com/getsops/sops) keep their keys
readable and seal each value in place:

```yaml
API_KEY: ENC[AES256_GCM,data:xyu...,iv:...,tag:...,type:str]
```

A secret scanner (gitleaks, trufflehog, checkov's `CKV_SECRET_*`, …) sees the
high-entropy blob and reports a hardcoded secret — but an `ENC[AES256_GCM,...]`
value is *already encrypted*, so the finding is a 100% false positive. Chargate
drops these from the net-new set **by default**: they get their own
`SOPS-encrypted` count, never gate, and still ship in the full SARIF.

The check is **per value**, so it stays safe:

- **Encrypted** value (`ENC[AES256_GCM,...]`) → dropped as a false positive.
- **Plaintext** value in the same file — a not-yet-encrypted secret, or a field
  left clear by `encrypted_regex` / `unencrypted_suffix` — → **still gates.**

Only findings from a recognized secret scanner are dropped, so a non-secret
finding that happens to land on the same line (e.g. a yamllint line-length on the
unavoidably long blob) is unaffected. Gate on encrypted values too with
`ignore_sops_encrypted: false` (action) or `--no-sops-ignore` (CLI).

!!! note "Reads the working tree"
    Detection reads the head-side file content at each finding's line, so the
    checkout Chargate scans must contain the flagged files (it does in the normal
    action flow). It never trusts SARIF snippets, which some scanners redact.

## The `fail_on` threshold

`fail_on` controls the gate over the net-new set:

- `any` (default) — any net-new finding blocks (the product's core promise).
- `critical` / `high` / `medium` / `low` — block only at or above that band.
- `none` — report-only; never blocks.

Severity uses the SARIF `security-severity` band when present
(`≥9.0` critical, `≥7.0` high, `≥4.0` medium, `>0` low), else the SARIF `level`
(`error`→high, `warning`→medium, `note`→low).

!!! tip "Full vs filtered SARIF"
    The gate only ever looks at the **net-new** subset, but the **full**,
    unfiltered SARIF is what gets shipped to DefectDojo / the Security tab /
    artifact (and a CycloneDX BOM to Dependency-Track). The input report is never
    mutated.

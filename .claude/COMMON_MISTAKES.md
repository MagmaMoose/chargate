# Common mistakes & footguns

- **Keep `sarif/` pure.** Never import `subprocess`, `os`, network, or GitHub
  Actions into `src/chargate/sarif/`. The filter is unit-tested with synthetic
  diff text + SARIF dicts; the git/IO boundary lives only in `git.py`.
- **A broken scanner is a tool error (exit 2), never a finding.** Don't let a
  MegaLinter failure synthesize or drop findings. It only fails the job under
  `--strict`.
- **Verify MegaLinter against a real run** before trusting field names/paths: the
  merged SARIF has shipped as both `megalinter-report.sarif` and
  `mega-linter-report.sarif` (`locate_sarif()` falls back to any `*.sarif`), and the
  URI shape varies (repo-relative vs `/tmp/lint/...`, which `chargate ci` strips).
  Details in `docs/setup.md`.
- **Net-new edge policies live in `FilterPolicy`** (`sarif/filter.py`). Defaults:
  line precision; no-location (project-level) results do NOT block; changed-file
  results with no `startLine` fall back to file-level (catches SCA on lockfiles).
- **Secret findings often come from KICS, not gitleaks** — one `KICS` run, UUID rule
  ids, no snippet; the signal is only in the rule name/message. So
  `model.is_secret_result` classifies by driver name **+ `CKV_SECRET_*` + `secret`
  tag + rule/message text** — don't narrow it to a driver allowlist or it silently
  no-ops. The SOPS filter (`sarif/sops.py`) reads the **working-tree** file (not the
  redacted snippet) and drops only secret findings whose value is `ENC[AES256_GCM,...]`;
  plaintext in the same file still gates. (More in `docs/net-new.md`.)
- **Net-new needs full history.** merge-base requires `fetch-depth: 0`; a shallow
  clone fails loudly by design — don't paper over it.
- **Core stays stdlib-only** (DefectDojo + Dependency-Track clients use `urllib`).
  **SHA-pin** external GitHub Actions with a `# vX.Y.Z` comment.
- **Sinks are optional + failure-isolated.** `defectdojo.import_sarif`,
  `dependencytrack.upload_bom`, `github_comment.post_pr_feedback` must NEVER raise —
  they return `ok=False` so an outage can't fail the gate. Active iff the host/URL is
  set (no on/off toggle); mirror this shape for any new sink. DT uploads on push/tags
  only (tracks shipped artifacts), never on PRs.
- **The `broker/` service is a separate deployable**, not part of the CLI: keep its
  FastAPI/httpx/pyjwt deps in the `broker` dep-group so the wheel stays dep-free.
  Ships as `ghcr.io/magmamoose/chargate`, deploys via `k8s/` + Flux; the App + OCI-Vault
  keys are operator-owned (see the token-broker design memory).

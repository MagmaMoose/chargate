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
- **DefectDojo types a Test from `runs[0]` and nothing else.** Its SARIF parser is a
  *dynamic test type* parser: `get_tests()` makes one ParserTest per run named after
  `run.tool.driver.name`, then `consolidate_dynamic_tests` does `test_raw = tests[0]` for
  the Test's type while aggregating findings from *every* run — and on reimport it 400s
  (`Test type mismatch`) if that derived name differs from the Test already there. We ship
  MegaLinter's **merged** report, whose first run is whichever linter emitted first, which
  follows the file types in the diff (`incremental` defaults to true). So the derived type
  is a property of the PR, not the repo. That killed the sink the day it started carrying
  real findings: the engagement was still typed `KICS Scan (SARIF)` from months of empty
  reports, so every upload was rejected — non-blocking by design, therefore silent. Fix
  shape: `defectdojo.with_identity_run` prepends a findings-free `chargate` run so the type
  is constant everywhere, and `import_sarif` retries once via `import-scan` to get past a
  Test some earlier tool named. Do not "simplify" either away.
- **`skips: ["tests/*"]` in `.bandit.yml` matches nothing.** bandit fnmatches the *normalised*
  filename, which carries a leading `./` — so only `*/tests/*` matches (it also covers
  `broker/tests/...` and the absolute `/tmp/lint/tests/...` form). Measured on 1.9.4:
  `tests/*` → 141 B101, `*/tests/*` → 0. More generally: reach for a linter's own config
  file (MegaLinter resolves `config_file_name` repo-root-first, before its packaged
  default) rather than `<LINTER>_ARGUMENTS: --skip X`, which is global and, in
  `.mega-linter.yml`, ships to every consumer that copies the template. And to check which
  config actually won, read the `- Command:` line's `-c` path — the `- Rules config:` label
  prints `[.bandit.yml]` for the packaged default too, because the templates dir is
  stripped out of it.
- **A runs-less SARIF must fail on its own, never behind `--strict`.** `strict` defaults to
  false and means "a linter blew up, you decide"; zero runs means the gate scanned nothing,
  so a pass is meaningless. Gating the empty-report check on `strict` reintroduces the
  original bug for every consumer who never set it.

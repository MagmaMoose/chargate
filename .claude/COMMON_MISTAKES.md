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
  pyjwt/httpx deps in `broker/pyproject.toml` so the CLI wheel stays dep-free.
  Ships as a zip in S3 and runs on AWS Lambda behind an API Gateway HTTP API; the
  module and leaf live in `magmamoose/infra` under `terraform/aws/chargate/`, and
  deploying is a reviewed one-line bump of `broker_artifact_version` there. The App
  private key and the AWS account are operator-owned (see the token-broker design memory).
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
- **`GET /healthz` proves the function booted and NOTHING else.** It returns 200 on a Lambda
  with no SSM parameters, no IAM permission to read them, and no GitHub App installed —
  because it deliberately answers before configuration is consulted (that is what makes
  "deploy, then seed the secrets" work). The failures it hides are exactly the ones this
  service has: the two-ARN SSM policy, the KMS decrypt grant, and an App that was never
  installed on the repo. Verify with a real signed `POST /token` — `.github/workflows/broker-smoke.yml`
  runs the SHIPPED `scripts/request-app-token.sh` and then hands the minted token back to
  the GitHub API, which is the only thing that exercises all of it. Nievah's first AWS front
  door deployed clean, health-checked green, and returned `InvalidSignatureException` on
  every POST.
- **`s3:GetObjectAttributes` does not authorise `HeadObject`.** Diatreme's s3 publisher
  (`package-ecosystem: s3`) calls `aws s3api head-object` to refuse overwriting a published
  key, and its AccessDenied branch is `exit 1`, not a skip — so a publish role missing
  `s3:GetObject` fails the release outright. Reported on magmamoose/infra#638, which is where
  the `artifacts` module's policy lives.
- **The broker fails soft, so a broken deployment is SILENT.** `scripts/request-app-token.sh`
  emits an empty token and `exit 0` on every error path, and the action falls back to
  `github-actions[bot]`. Nothing goes red anywhere. That is correct behaviour — a security
  gate must not break a consumer's build because a token minter is down — but it means the
  only signals that the broker is broken are the weekly smoke run and a PR comment byline.
  Never treat "no failures reported" as evidence the broker works.
- **`app/main.py` must never enter the Lambda zip.** It is the one module importing FastAPI,
  which is not in the shipped dependency set; `scripts/build_lambda_zip.py` excludes it by
  name and `tests/test_lambda_package.py` asserts its absence. Shipping it turns a clean
  deploy into a cold-start `ImportError` on the fail-soft path above — i.e. into silence.
- **Diatreme runs its own `actions/checkout`, which `git clean -ffdx`s your build output.** The
  composite action checks the repo out again internally (`fetch-depth: 0`), and
  `actions/checkout` defaults to `clean: true` — so any artifact an earlier step wrote *inside*
  the workspace is deleted before diatreme's publish step runs. A Lambda zip built to `./dist`
  disappeared exactly this way, and the symptom blames the caller:
  `s3: package-path must be the built artifact FILE. Not a file: dist/chargate-broker.zip`,
  on a run whose own log shows the build succeeding two steps earlier. Build to
  `${{ runner.temp }}` and pass that absolute path as `package-path`.
- **`.github/workflows/release.yml` is provisioned by caldrith and will be overwritten.** It is
  pushed directly as `chore: provision required workflows (caldrith)` — no in-file marker says
  so, and four such commits already exist here. Broker publish wiring added to it survived one
  release and then vanished, taking the deployment path with it and leaving no failing check
  anywhere. Chargate-specific CI belongs in a file caldrith does not own; the publish lives in
  `.github/workflows/publish-broker.yml`. `ci.yml` and `security.yml` are NOT managed.
- **Diatreme's package publishing only fires on the run that CREATES a tag** — its step is gated
  on `steps.normalize.outputs.released == 'true'`. A re-run of a failed release, or any release
  whose version was already tagged, skips the publish silently and reports success. If an upload
  fails for any other reason, you cannot simply re-run it; key the publish off the tag instead.

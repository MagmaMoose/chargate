# Common mistakes & footguns

- **Keep `sarif/` pure.** Never import `subprocess`, `os`, network, or GitHub
  Actions into `src/chargate/sarif/`. The filter is unit-tested with synthetic
  diff text + SARIF dicts; the git/IO boundary lives only in `git.py`.
- **A broken scanner is a tool error (exit 2), never a finding.** Don't let a
  MegaLinter failure synthesize or drop findings. It only fails the job under
  `--strict`.
- **Verify MegaLinter against a real run** before trusting field names/paths.
  The merged SARIF has shipped as both `megalinter-report.sarif` and
  `mega-linter-report.sarif` (`locate_sarif()` falls back to any `*.sarif`).
  Confirm the reporter env vars and the URI shape (repo-relative vs
  `/tmp/lint/...` — `chargate ci` strips the `/tmp/lint` prefix and the abs repo
  path). Details in `docs/setup.md` + `PROJECT_INDEX.json`.
- **Net-new edge policies live in `FilterPolicy`** (`sarif/filter.py`). Defaults:
  line precision; no-location (project-level) results do NOT block; changed-file
  results with no `startLine` fall back to file-level (catches SCA on lockfiles).
- **Net-new needs full history.** merge-base requires `fetch-depth: 0`; a shallow
  clone fails loudly by design — don't paper over it.
- **Core stays stdlib-only** (no runtime deps; DefectDojo client uses `urllib`).
  **SHA-pin** external GitHub Actions with a `# vX.Y.Z` comment.

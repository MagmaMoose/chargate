# SAST direction: chargate vs CodeQL, engine or orchestrator?

<!-- sources: src/chargate/linters.py, .mega-linter.yml -->

**Status:** decided · **Decision:** chargate is a SAST **orchestrator/aggregator**,
not a competing analysis engine. It owns the ground CodeQL cedes (net-new PR-diff
gating, cross-engine de-duplication, the DefectDojo/Dependency-Track bridge) and
ingests CodeQL/Semgrep/KICS/checkov/hadolint SARIF rather than reimplementing
dataflow analysis.

## Why this was open

Chargate wraps MegaLinter and adds a net-new diff gate. The question (issue #32)
was whether it should also *own an engine*, bundle Semgrep/Opengrep as a
first-class dataflow analyzer and compete with CodeQL head-to-head, or double
down on being the layer that makes any engine's output actionable on a PR.

## Steering criterion

Compare three postures on a shared corpus, recording true positives (TP), false
positives (FP), and wall-clock runtime:

- **chargate-as-is**, the MegaLinter suite (Semgrep, Bandit, checkov, hadolint,
  ShellCheck, ESLint, gosec, KICS-equivalent, …) on the languages that matter.
- **CodeQL**, GitHub's engine, default query packs.
- **Semgrep/Opengrep**, standalone, community + registry rules.

Corpus: OWASP Benchmark (Java), WebGoat, juice-shop (JS/TS), django-vulnerable
(Python), deliberately mixed-language so no single engine's home turf dominates.

## Outcome

| Posture | TP recall (dataflow-heavy) | FP rate | Runtime | Languages |
| --- | --- | --- | --- | --- |
| CodeQL | highest | low | slowest (minutes, compiled DBs) | fewer, deep |
| Semgrep/Opengrep | medium (syntactic + taut taint) | medium | fast | many |
| chargate (MegaLinter suite) | medium, **broadest surface** (SAST + IaC + secrets + SCA + Dockerfile + shell) | medium, tunable | fast | broadest |

Read: CodeQL wins deep interprocedural dataflow recall on the languages it
supports and would take real, ongoing engine investment to beat, investment that
duplicates a free-for-OSS incumbent. What CodeQL does **not** do is gate a PR on
*only the findings the diff introduced*, normalise a heterogeneous fleet of
engines into one decision, de-duplicate the same finding reported by two of them,
or bridge the result to DefectDojo/Dependency-Track. That is unowned ground.

## Decision

Own the ground CodeQL cedes (directions 2-4), **not** a competing engine
(direction 1). Concretely:

1. **Engine-agnostic net-new gating.** The introduced-vs-pre-existing logic in
   `chargate.sarif.filter` keys on SARIF results, never on the emitting tool, so
   CodeQL, Semgrep, KICS, checkov, hadolint, and MegaLinter's linters all get
   identical gating. Pre-existing debt is never blocked, whichever engine reports
   it.
2. **Cross-engine de-duplication.** `chargate.sarif.dedup` collapses net-new
   findings that share a `(rule id, fingerprint)` key, so the same logical finding
   reported by two producers, or one producer's SARIF uploaded twice, gates and
   comments once. Fingerprints prefer the tool's own
   `fingerprints`/`partialFingerprints`; otherwise they derive from location +
   message. Toggle with `FilterPolicy.deduplicate`.
3. **Aggregation, not analysis.** Any SARIF-2.1.0 producer can be layered in by
   emitting its report into the set chargate ingests; nothing reimplements
   dataflow.

Semgrep/Opengrep remains available *as one of the engines MegaLinter already
runs*, chosen for coverage, not as a chargate-owned differentiator. If a future
need for chargate-owned engine analysis appears, it enters through the same SARIF
ingestion path as an optional, opt-in producer; it does not become the product.

## When chargate is primary SAST vs a CodeQL complement

- **Primary SAST**, repos in languages CodeQL doesn't cover well, polyglot repos,
  or teams that want IaC/secrets/SCA/Dockerfile/shell coverage and PR-diff gating
  in one gate. Chargate is the whole SAST story.
- **CodeQL complement**, repos already running CodeQL for deep dataflow. Upload
  CodeQL's SARIF into chargate's ingestion set; chargate contributes the net-new
  diff gate, cross-engine de-dup, and the DefectDojo bridge on top of CodeQL's
  findings. The two compose; they don't compete.

Operators select the mode by *what SARIF they feed in*, not a runtime flag: feed
only MegaLinter's report for primary mode; add CodeQL's uploaded SARIF for
complement mode. See [net-new gating](net-new.md) for the gate semantics and the
deployment matrix in the README for wiring.

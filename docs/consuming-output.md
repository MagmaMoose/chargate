# Consuming the output

<!-- sources: src/chargate/cli.py, src/chargate/sarif/counts.py, action.yml -->

Chargate classifies; the caller decides. Every run writes two documents another tool
can read without importing any of Chargate: the **net-new SARIF** and the **counts
JSON**. The counts JSON carries a `schema_version` and is a **stable public
interface** — versioned, and broken only deliberately.

The first consumer is [brimyr](https://github.com/MagmaMoose/brimyr), a patch-coverage
gate that folds Chargate's findings into the same pull-request verdict
([MagmaMoose/brimyr#33](https://github.com/MagmaMoose/brimyr/issues/33)). It reads these
two documents rather than importing any of Chargate, which is the point on both sides:
Chargate's core stays stdlib-only and brimyr keeps its own zero-runtime-dependency rule.
A process boundary needs a documented shape, so here it is.

## Gate on the counts, display the SARIF

The counts JSON is Chargate's own document: its keys mean what this page says they
mean, and the invariants below hold. The filtered SARIF is **MegaLinter's** shape — one
`runs` entry per linter, whatever each linter chose to put in it — and it is for showing
a human what was found: rendering a summary, uploading it, attaching it to a comment.

Counting results in the SARIF to decide pass/fail is re-implementing
`sarif.counts.count_results` against a document whose shape belongs to whoever emitted
it, and it gets the suppressed / SOPS-ignored / de-duplicated buckets wrong: those
results are *gone* from the filtered SARIF, and only the counts say how many there were
and which bucket took them.

Two surfaces are deliberately **not** interface: the stderr summary lines and the
job-summary markdown. Both are written for people and change whenever a better sentence
turns up. The action's step outputs are interface — they are declared in `action.yml`
like any other.

## The command

```sh
chargate filter-sarif \
    --sarif full.sarif \
    --base "$BASE_SHA" --head "$HEAD_SHA" \
    --out net-new.sarif \
    --counts-json counts.json \
    --no-gate
```

| Flag | Why it is part of the contract |
| --- | --- |
| `--sarif` | The report to classify. Any SARIF 2.1.0 producer, not only MegaLinter. |
| `--base` / `--head` | The two ends of the diff. Classification is against `merge-base(base, head)` unless `--no-merge-base`. |
| `--out` | Where the net-new-only SARIF goes: the input document with every non-net-new result pruned. |
| `--counts-json` | Where the counts document goes. |
| `--no-gate` | Report only — Chargate stops deciding, so the caller can. |

`chargate ci` writes the same pair through `--filtered-out` and `--counts-json`. They
are the same writers over the same `FilterResult`, so the contract does not change with
the subcommand; `ci` has no `--no-gate`, its report-only equivalent is `--fail-on none`
(`fail_on: none` on the action). The composite action always passes both — see
[From the action](#from-the-action).

`--no-gate` leaves exactly two exit codes, and the difference between them matters more
than any verdict:

| Exit | Meaning under `--no-gate` |
| --- | --- |
| `0` | The classification ran. Both documents were written; the answer is in them. |
| `2` | Chargate could not classify at all — unreadable SARIF, missing merge-base, shallow clone. |

A `2` is not "no findings", it is **no answer**. A consumer that treats the two alike
ships the exact failure this project exists to remove: a gate that scanned nothing and
reported green. Without `--no-gate` the exit code also carries `1` for a net-new finding
at or above `--fail-on` — that is Chargate deciding, which a consumer running its own
gate does not want.

## The counts document

```json
{
  "schema_version": 1,
  "net_new_count": 3,
  "total_count": 128,
  "pre_existing_count": 121,
  "suppressed_count": 2,
  "sops_ignored_count": 1,
  "deduped_count": 1,
  "per_level_total": { "error": 40, "warning": 70, "note": 18 },
  "per_level_net_new": { "error": 1, "warning": 2 },
  "per_severity_total": { "high": 12, "medium": 30 },
  "per_severity_net_new": { "high": 1 }
}
```

| Key | Meaning |
| --- | --- |
| `schema_version` | The shape of this document. Read it before anything else. |
| `net_new_count` | Findings the diff introduced. The number a gate is about. |
| `total_count` | Every result in the input SARIF. |
| `pre_existing_count` | `total − net_new − suppressed − sops_ignored − deduped`. Never blocks. |
| `suppressed_count` | Author-accepted in-source suppressions. Never blocks. |
| `sops_ignored_count` | Secret-scanner hits on [SOPS-encrypted](net-new.md#sops-encrypted-secrets) values. Never blocks. |
| `deduped_count` | Net-new findings collapsed into an earlier identical one (same rule id + fingerprint). |
| `per_level_total` / `per_level_net_new` | Counts by SARIF `level`: `error`, `warning`, `note`, `none`. |
| `per_severity_total` / `per_severity_net_new` | Counts by severity band, derived from a numeric `security-severity` property: `critical`, `high`, `medium`, `low`, `none`. |

Two invariants hold for every schema-1 document, and a consumer should **assert** them
rather than trust them. A counts file that contradicts itself is a bug on this side of
the boundary, and asserting is how it surfaces as an error instead of as a number:

- `sum(per_level_net_new.values()) == net_new_count`. Every result resolves to a level,
  so the per-level map partitions the net-new set.
- The total result count across the filtered SARIF's `runs` equals `net_new_count`. The
  two files describe one set.

!!! warning "Quality linters emit no `security-severity`, so the band maps stay empty"
    The `per_severity_*` maps are populated only from a numeric `security-severity`
    property. Security scanners set it; quality linters do not — Ruff, ESLint, PMD and
    golangci-lint emit a SARIF `level` and nothing else. On a
    [`flavor: quality`](setup.md#the-quality-flavor) run `per_severity_net_new` is
    therefore `{}` while `per_level_net_new` is populated, so a consumer thresholding on
    bands over quality findings never blocks and never says why. Threshold on levels
    there; brimyr's own threshold speaks SARIF levels for exactly this reason.

    Chargate's own `fail_on` is **not** affected. `gate.effective_band` falls back to the
    level when a result carries no `security-severity` (`error`→high, `warning`→medium,
    `note`→low), so `fail_on: high` still blocks on an `error` from a quality run. It is
    the counts document's band maps that stay empty, not the gate's view of severity.

## `schema_version`, and what breaks it

| Change to the document | Breaking? |
| --- | --- |
| A key added | No. A reader that does not know it ignores it. |
| A key removed or renamed | **Yes.** |
| A key keeping its name and changing meaning | **Yes**, and the worst kind — nothing errors, the number is just wrong. |
| A new value inside an existing map (a level or band not seen before) | No. The maps are open. |

The rule on the far side follows from that table: **hard-fail on a `schema_version` you
do not recognise.** Do not fall back to a best-effort read of the keys you happen to
find, because guessing has exactly one shape of failure — a key you cannot find reads as
zero, zero net-new reads as a pass, and the gate goes green on a document it never
understood. Refusing is loud. Guessing is silent, and which of those two you get is what
this codebase is built around.

A bump is therefore a coordinated release on both sides of the boundary, not a cosmetic
edit. `COUNTS_SCHEMA_VERSION` lives beside the `Counts` dataclass in
`src/chargate/sarif/counts.py`, and `cli.counts_to_dict` emits it as the document's
first key, so a consumer reading a truncated or streamed file still gets it first.

## From the action

| Output | Path | Written |
| --- | --- | --- |
| `filtered_sarif_path` | `chargate-reports/net-new.sarif` | Every run. |
| `counts_path` | `chargate-reports/counts.json` | Every run. |

Both are workspace-relative, and both are written unconditionally — including on a
baseline (push) run, where the net-new set is empty by construction. That is deliberate:
a consumer that finds no file cannot tell "nothing was introduced" from "the step never
got that far", and one of those two must not read as a pass.

```yaml
- uses: magmamoose/chargate@v2
  id: chargate
  with:
    flavor: quality
    fail_on: none          # Chargate reports; the next step decides
- name: Gate on the net-new findings
  run: |
    counts="${{ steps.chargate.outputs.counts_path }}"
    jq -e '.schema_version == 1' "$counts" > /dev/null \
      || { echo "::error::unrecognised counts schema"; exit 2; }
    jq -e '(.per_level_net_new.error // 0) == 0' "$counts" > /dev/null \
      || { echo "::error::net-new errors introduced by this PR"; exit 1; }
```

!!! danger "A counts file is not proof that anything was scanned"
    `chargate ci` writes both documents *before* it decides its own exit code, so a run
    whose SARIF carried no `runs` at all — MegaLinter produced nothing — still leaves a
    well-formed `counts.json` full of zeros behind, and *then* exits `2` for exactly
    that reason. Read the step's outcome as well as the file. Zeros from a scan that
    never happened are indistinguishable from a clean pull request, which is the failure
    this project exists to remove. `filter-sarif` makes no such check at all: it
    classifies whatever document it is handed, empty or not, because the caller chose
    that file.

The `gate_result` / `net_new_count` / `total_count` outputs remain the quick path for a
workflow that only wants a number in a message. `counts_path` is for a tool that needs
the whole breakdown — which bucket, which level, which band — without parsing SARIF.

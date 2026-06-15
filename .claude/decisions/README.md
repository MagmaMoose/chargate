# Architectural decisions (ADRs)

One Markdown file per decision, named `NNNN-short-title.md` (zero-padded,
incrementing). Run `/adr` to record one. Load these **only** when a task relates
to a past decision — they are not auto-loaded into context.

Good ADR candidates for this repo: the pure-`sarif/` boundary, the net-new
edge-case policy defaults (`FilterPolicy`), the exit-code contract (0/1/2), the
MegaLinter-owns-scanning / chargate-owns-the-gate split, and the DefectDojo
failure-isolation guarantee.

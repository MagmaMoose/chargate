# Security Policy

## Supported versions

Chargate is released from `main` with automated Semantic Versioning. Security fixes
land on the latest `v2` release; the moving `@v2` tag always points at it.

| Version | Supported |
| --- | --- |
| `v2` (latest) | ✅ Actively supported |
| `v2.x` (older) | ⚠️ Upgrade to the latest `v2` for fixes |
| `v1` | ❌ Frozen — the legacy runtime; no security updates |

If you pin a SHA or an exact tag, upgrade to the latest `v2` release to receive
security fixes.

## Reporting a vulnerability

**Please do not open a public issue for security reports.**

Report privately via **[GitHub private vulnerability reporting](https://github.com/MagmaMoose/chargate/security/advisories/new)**
(the "Report a vulnerability" button under the repository's **Security** tab). If you
cannot use that, email **caleb@magmamoose.com** with details.

Please include:

- affected version / ref (tag or SHA),
- a description and impact assessment,
- reproduction steps or a proof of concept,
- any suggested remediation.

### What to expect

- **Acknowledgement:** within 3 business days.
- **Assessment & triage:** we will confirm the issue and determine severity.
- **Fix & disclosure:** we aim to ship a fix promptly and will coordinate a
  disclosure timeline with you, crediting you unless you prefer to remain anonymous.

## Scope

In scope: the `chargate` CLI, the composite action (`action.yml`), the pre-commit
hooks, and the token broker (`broker/`).

Out of scope: vulnerabilities in **MegaLinter** or its bundled linters (report those
upstream), and in your own workflow configuration. Note that Chargate's gate is
decided by **MegaLinter's** findings — a missed *finding* is usually a MegaLinter
matter, whereas a flaw in Chargate's **gating, filtering, or token handling** is in
scope here.

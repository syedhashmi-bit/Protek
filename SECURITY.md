# Security Policy

Protek is a security tool (a CrowdSec → MikroTik bouncer that controls a
firewall address-list), so vulnerabilities here can have real blast radius.
Reports are taken seriously.

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.**

Report privately via either:

- **GitHub Security Advisories** — the [Report a vulnerability](https://github.com/syedhashmi-bit/Protek/security/advisories/new)
  button on the repo's Security tab (preferred — keeps the report and fix
  coordinated in one place).
- **Email** — `syed@syedhashmi.trade` with subject `SECURITY: Protek`.

Please include:

- affected version / commit
- a description of the issue and its impact
- steps to reproduce (a proof-of-concept if you have one)
- any suggested remediation

## What to expect

- **Acknowledgement** within 72 hours.
- An initial assessment (severity + whether we can reproduce) within 7 days.
- Coordinated disclosure: we'll agree on a timeline before any public
  detail is published, and credit you in the advisory unless you'd rather
  stay anonymous.

## Scope

In scope — anything that can:

- bypass authentication / 2FA, session handling, or the IP whitelist
- cause Protek to write firewall entries it shouldn't, or skip/silently drop
  decisions it should enforce
- leak secrets (`.env`, bouncer/machine keys, the SQLite DB) or other
  operators' data in a federated setup
- achieve RCE, SSRF, SQL injection, or template injection
- escalate the bouncer's read-only LAPI access into write access

Out of scope:

- findings that require an already-compromised host or root on the box
- missing hardening on a deployment the operator chose to expose without TLS
  (e.g. running with `COOKIE_INSECURE=1` on the public internet)
- vulnerabilities in third-party dependencies already tracked by `pip-audit`
  — report those upstream, though a heads-up is welcome

## Supported versions

Protek ships from `main`. Security fixes land on `main`; there is no
backported release train. Run the latest commit.

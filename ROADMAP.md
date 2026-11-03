# ROADMAP.md — Protek

What's next, in priority order. Each item has an **acceptance criterion** — it
isn't done until that's green.

Everything shipped so far (arcs 1–16, phases 0–98) is recorded in
[`docs/ROADMAP-HISTORY.md`](docs/ROADMAP-HISTORY.md) and [`MEMORY.md`](MEMORY.md).
The old open items there (MaxMind GeoIP, threat-feed correlation, the 72-hour
soak run, REST adapter perf measurement, the 2.0 tag) were dropped on 2026-11-03.

| # | Item | Why it's here |
|---|------|---------------|
| 1 | [Show whether blocking is actually working](#1-show-whether-blocking-is-actually-working) | A new install can look healthy and block nothing |
| 2 | [Edit connection settings in the app](#2-edit-connection-settings-in-the-app) | Today every connection change needs a shell, `.env` and a restart |
| 3 | [Advanced view toggle](#3-advanced-view-toggle) | ~40 menu entries; a homelab user needs about ten |
| 4 | [Help toggle and guided tour](#4-help-toggle-and-guided-tour) | Nothing in the app explains what a page or setting is for |

---

## 1. Show whether blocking is actually working

**Why:** turning dry-run off and pushing IPs to the address list doesn't mean
anything is blocked. Without a firewall rule that drops traffic from that list,
the router lets it all through — and today Protek can't tell. It's the most
likely way a new install looks fine and protects nothing.

**Scope:**
- A **read-only** check, each sync cycle or on demand, of every MikroTik
  target's `/ip/firewall/filter` and `/ip/firewall/raw` for an enabled rule that
  drops or rejects `src-address-list=<configured list>` (input / forward, or raw
  prerouting).
- A clear status on the MikroTik page, the dashboard and the topbar:
  **Blocking active**, **Not blocking — no drop rule for list `crowdsec`**, or
  **Rule disabled**, plus the rule's packet counter so you can see it matching.
  Flag a rule that sits below an unconditional `accept` in the same chain, since
  it never fires.
- When it isn't blocking: show the exact RouterOS commands — the drop rule, an
  API user group with the minimum policy, and allowlisting the Protek host —
  with copy buttons. Protek doesn't write firewall rules itself; a one-click
  "add it for me" is a possible follow-up, not part of this item.
- A warning when someone turns dry-run off while the check says "not blocking".
- Covers every MikroTik target. Other target kinds (pfSense, OPNsense,
  iptables, Cloudflare) are out of scope here.

**Acceptance:**
- On a router with no drop rule, Protek shows "Not blocking" within one sync
  cycle and offers commands that work when pasted.
- After pasting them, it shows "Blocking active" with a rising packet counter, without a restart.
- A disabled rule shows as "Rule disabled", and a shadowed rule is flagged.
- Tests against a fake RouterOS API cover each state and confirm the check never writes.

---

## 2. Edit connection settings in the app

**Why:** Settings shows the LAPI URL, MikroTik host/port and bouncer key in
input boxes that are actually read-only ("set in `.env`"). Changing any of them
needs a shell, an editor and a restart. It's the most confusing part of the UI,
and it's why the installer has to ask for everything up front.

**Scope:**
- Editable in **Settings → Connection & sync**: the CrowdSec LAPI URL and bouncer key, plus the MikroTik host, port, TLS, username, password and address list.
- **Test connection** before saving, using the same checks the installer runs:
  LAPI `/v1/decisions` with the key, and `MikroTik.health()`. Save only on
  success, or on an explicit "save anyway".
- Takes effect without a restart: the poller picks up the new values on the next cycle.
- Secrets are write-only: shown masked, never sent back to the browser, and a blank field means "keep the current value".
- Admin-only. Every change goes to the audit log, without the values.
- Values in `.env` keep working as the starting point, for both bare metal and Docker (`/data/.env`).
- **Design decision to make first: where saved secrets live.** Either the UI
  writes `.env` (keeps the rule that secrets live there; needs the file writable
  by the service, and the sandbox allows `/var/www/Protek`), or they move to the
  `settings` table encrypted with a key derived from `SECRET_KEY` (changes that
  rule in `CLAUDE.md`).

**Acceptance:**
- On a fresh install with no MikroTik configured, an admin can enter the router details in the browser, see the test pass, and save. The next sync then reaches the router, with no shell and no restart.
- A wrong password fails the test with the router's own error and changes nothing.
- Secrets never appear in page source or API responses.
- Each change shows up in the audit log.

---

## 3. Advanced view toggle

**Why:** the sidebar has ~40 entries across 132 routes, including DR drill, high
availability, SIEM export, honeypot and threat-feed publishing. A homelab user
needs about ten of them, and the rest makes Protek look harder than it is.

**Scope:**
- An `advanced` flag on entries in the `NAV` list in `app.py`. `_nav_visible()`,
  which already filters by role, hides flagged entries unless the toggle is on.
  The sidebar, tab strips and command palette all follow from `NAV`.
- **Simple view** (default):
  - Monitor: Overview, Blocked IPs, Alerts, Detections.
  - Enforce: Targets (with MikroTik) and Rules → Whitelist.
  - Admin: Settings (Connection & sync, Notifications, Security, Single sign-on, Setup guide) and Users.
- **Advanced view** adds:
  - Threat intel, ASN escalations, publish feed, Alert rules and the scenario catalog.
  - Sources (federation, peers), Fleet and Approvals.
  - Activity (audit, performance, synthetic checks) and Integrations (webhooks, SIEM).
  - Honeypot, API tokens, both backup pages, DR drill and High availability.
- The switch lives in the sidebar footer / user menu and is saved per user.
- Hidden doesn't mean disabled: features keep running, and direct links still work.
- An advanced feature you've configured (a second source, a peer, off-box
  backup) stays visible in simple view; one that's failing shows with a warning
  badge.
- The command palette still finds advanced pages, labelled "advanced".
- New installs start in simple view. Existing installs start in advanced after
  the upgrade, so nobody's menu shrinks unexpectedly.

**Acceptance:**
- A fresh install shows only the simple set.
- Turning the toggle on shows every page, and the choice survives logging out.
- A configured advanced feature appears in simple view, and a failing hidden one appears with a badge.
- Every page stays reachable by URL and from the palette.
- Tests cover the `NAV` filter, including role × view combinations.

---

## 4. Help toggle and guided tour

**Why:** most pages assume you already know CrowdSec and RouterOS terms (LAPI,
scenarios, address lists, batch cap, confidence threshold). Nothing in the app
says what a page is for or what a setting does, so people either guess or go
read the docs.

**Scope:**
- A **Help** toggle (a `?` button in the topbar, and the `?` key) with two parts:
  - **Guided tour:** step-by-step highlights of what's on screen, with a
    plain-language explanation of each part and Back / Next / Skip. There's a
    tour for the current page, plus a **"Tour Protek"** run across the main
    pages in order: Overview → Blocked IPs → Alerts → Targets → Rules →
    Settings.
  - **Help mode:** while it's on, every setting, column, KPI and button shows a
    small info marker. Clicking it explains what the option does, the default,
    and when you'd change it. For example, "Batch cap: the most add/remove
    operations Protek sends the router per cycle; the rest wait for the next
    cycle."
- **One source of help text:** a single catalog keyed by the `NAV` page keys
  and field names, in the same spirit as `NAV`. The tour and help mode both
  read from it, so they can't drift apart, and a test flags any setting with
  no entry.
- **Follows the advanced view (item 3):** it explains what's currently visible,
  and the full tour covers advanced pages only when that view is on.
- **Offered once** after the Setup guide finishes, or on first login. Progress
  and "don't show again" are saved per user, and the tour can be restarted
  from the Help menu.
- **Accessible:** works with the keyboard alone (Esc closes, arrow keys move),
  readable by screen readers, and fits at phone width. It uses the existing
  design tokens and sentence case. No external tracking. A small vendored tour
  library or a hand-rolled one is fine; pick during design.

**Acceptance:**
- Starting the tour on any page in the simple view walks through every visible
  section of that page.
- "Tour Protek" covers the main pages in order and can be finished with the
  keyboard alone.
- With help mode on, every field on Settings → Connection & sync and every KPI
  on Overview has an explanation.
- A test fails if a `NAV` page or a settings field has no help entry.
- Dismissing the tour is remembered after logging out and back in.

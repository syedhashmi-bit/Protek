# UI.md — Design Language & NOC Aesthetic

Protek's UI is a **tactical NOC dashboard**, not an admin panel. This document is the visual contract — refer to it whenever you write or modify a template.

The goal is consistency across the suite: Protek must feel like it belongs next to pipsqueeze and traverse. A user moving between the three apps should not need to recalibrate.

---

## 1. Color Palette

```
--bg-deep      #14120F   /* warm near-black */
--bg-panel     #1C1917   /* panel base */
--bg-raised    #262220   /* hover / selected row */
--border       #35302B   /* dividers */
--border-soft  #282320
--border-accent #4A4038  /* focused field, active edge */

--accent       #D9975B   /* brand, links, primary action, active nav */
--ok           #86B27A   /* sage — online, success, all clear */
--warn         #E3B341   /* amber — slow, degraded, partial */
--danger       #D4736A   /* terracotta — errors, destructive, dry-run badge */
--info         #89A8B3   /* muted teal — secondary/informational */

--text         #EDE8E3
--muted        #A79E95
--muted-low    #928779   /* lowest legible tier; clears WCAG AA */
```

The warmth lives in the **neutrals**. Semantic colours stay semantic — in a
security tool, danger must read as danger, so `--danger`/`--warn`/`--ok` are not
tinted for style.

Use the tokens, never hardcoded hex. Prefer the semantic names; `--cyan`,
`--green`, `--red` and `--amber` remain as aliases only because ~600 template
references predate the rename.

All three surfaces clear WCAG AA for `--text` and `--muted`.

---

## 2. Typography

```
UI font:        'IBM Plex Sans'   (Google Fonts, weights 400/500/600)  -> var(--font-ui)
Mono font:      'IBM Plex Mono'   (Google Fonts, weights 400/500)      -> var(--font-mono)
Scale:          --fs-xs 11 · --fs-sm 12 · --fs-base 14 · --fs-md 15
                --fs-lg 18 · --fs-xl 24 · --fs-2xl 30
```

Rules:

- **Mono is for identifiers and figures only** — IPs, CIDRs, counts, timestamps,
  durations, tokens, IDs. Not buttons, labels, inputs, badges or prose. Mono on
  non-tabular content was the single biggest reason the UI read as costume.
- **Sentence case.** No uppercase labels, headers or nav. An eyebrow may use
  letter-spacing up to `.06em`; nothing goes higher.
- Use the scale tokens rather than new literal sizes.
- Avoid italics.

---

## 3. Layout

### Topbar (sticky)

- 56px tall, full-width
- Left: small logo + "PROTEK" wordmark in IBM Plex Sans, sentence case
- Center: breadcrumb / page title
- Right: status pill cluster (LAPI · MikroTik · Reconciler) + DRY-RUN badge (if active) + user menu
- Background `var(--bg-panel)`, bottom border 1px `var(--border)`

### Sidebar (left, sticky)

- 220px wide, full-height
- Sections: Dashboard · Decisions · Alerts · Scenarios · MikroTik · Federation · Notifications · Security · Settings
- Each item: icon (16px) + label, 36px tall row
- Active item: left border 3px `var(--accent)`, background `var(--bg-raised)`, text `var(--accent)`
- Hover: background `var(--bg-raised)`

### Main content

- Padded 24px, max-width 1600px, centered
- Grid: 12-column, 16px gutter
- Panels are `var(--bg-panel)` background, 1px `var(--border)` border, 4px border-radius, 16px internal padding

---

## 4. Panel Patterns

### KPI card

```
┌─────────────────────────────────┐
│  ACTIVE DECISIONS               │  ← IBM Plex Sans 500, sentence case, var(--muted), 11px
│                                 │
│  1,247                          │  ← IBM Plex Mono, 36px, var(--ok)
│  ▁▂▃▄▅▆▇ 24h                   │  ← inline-SVG sparkline, var(--ok) stroke
└─────────────────────────────────┘
```

- Title row: tiny, muted, uppercase, letter-spaced
- Big number: monospace, glowing accent color (cyan for neutral, green for "good", red for "bad")
- Sparkline directly underneath
- Optional delta indicator ("+47 vs 24h ago") in muted text

### Status pill

```
●  LAPI                 ← solid circle (8px) + label
green = healthy, amber = slow / degraded, red = down
```

Use the pulse animation only on the "current scan" indicator, never on healthy steady-state.

### Data table

- Header row: `var(--bg-deep)` background, IBM Plex Sans 600, sentence case, 11px, `var(--muted)`
- Body rows: 32px tall, alternating with `var(--bg-panel)` / `#0c1a2e`
- Hover: `var(--bg-raised)`
- Selected: `var(--bg-raised)` + left border 2px `var(--accent)`
- IPs always in IBM Plex Mono
- Timestamps relative ("3m ago") with absolute on hover tooltip
- No outer borders — let the panel border do that job

### Buttons

- Primary: solid `var(--accent)` bg, `var(--bg-deep)` text, no border, 4px radius, IBM Plex Sans 600, sentence case
- Secondary: transparent bg, `var(--accent)` text, 1px `var(--accent)` border
- Danger: `var(--danger)` variant
- Ghost: transparent bg, `var(--muted)` text, no border (for tertiary actions)
- Buttons in tables are always ghost or secondary, never primary

### Badges

- Scenario badges: rounded, 11px, uppercase, accent color matching scenario family:
  - `http-*` → cyan
  - `ssh-*` → amber
  - `lists:*` → muted slate
  - `crowdsecurity/*` → green
  - custom local scenarios → magenta
- Origin badges: pill-shaped, monospace, smaller
- Dry-run badge in topbar: solid `var(--danger)` bg, white text, pulse animation

---

## 5. Dashboard Wireframe

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ PROTEK  · Dashboard                          ● LAPI  ● MT  ● Sync  [DRY]  ☰ │
├──────┬──────────────────────────────────────────────────────────────────────┤
│      │                                                                       │
│ DASH │ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌──────────┐ │
│ DEC  │ │ ACTIVE │ │ MT LIST│ │ SYNC   │ │ SCEN'S │ │ ATTKRS │ │ TOP SCEN │ │
│ ALR  │ │ 1,247  │ │ 1,247  │ │  2s    │ │  31    │ │  142   │ │ http-prb │ │
│ SCN  │ │ ▁▃▅▇▆▄ │ │ ▁▃▅▇▆▄ │ │ ▁▂▁▂▁▂ │ │ ▁▂▄▇▅▃ │ │ ▁▂▃▅▇▇ │ │ 47 fires │ │
│ MT   │ └────────┘ └────────┘ └────────┘ └────────┘ └────────┘ └──────────┘ │
│ FED  │                                                                       │
│ NOT  │ ┌──────────────────────────────┐ ┌─────────────────────────────────┐ │
│ SEC  │ │  LIVE ATTACK FEED            │ │  WORLD MAP                      │ │
│ SET  │ │  ───────────────────────     │ │                                 │ │
│      │ │  3m  1.2.3.4  US  http-probe │ │   ●        ●                    │ │
│      │ │  4m  5.6.7.8  CN  ssh-bf     │ │      ●         ● ●              │ │
│      │ │  6m  …                       │ │       ●  ●                      │ │
│      │ │                              │ │            ●                    │ │
│      │ │  [autoscroll · pause]        │ │   [zoom +/-]                    │ │
│      │ └──────────────────────────────┘ └─────────────────────────────────┘ │
│      │                                                                       │
│      │ ┌──────────────────────────────┐ ┌─────────────────────────────────┐ │
│      │ │  SCENARIOS — TOP 10 (24h)    │ │  SYNC ACTIVITY (24h)            │ │
│      │ │  http-probing  ████████ 47   │ │      ┌─┐                        │ │
│      │ │  ssh-bf        █████    31   │ │   ┌──┘ └─┐         ┌──┐         │ │
│      │ │  http-bad-ua   ███      18   │ │ ──┘      └─────────┘  └───      │ │
│      │ │  …                           │ │                                 │ │
│      │ └──────────────────────────────┘ └─────────────────────────────────┘ │
│      │                                                                       │
└──────┴──────────────────────────────────────────────────────────────────────┘
```

---

## 6. Micro-interactions

- **Polling indicator**: a 1px-tall progress bar at the top of the live-feed panel that fills from 0→100% over the 5s polling interval, then resets. Subtle, but tells the user "this is live."
- **New row in live feed**: 200ms left-slide-in + brief cyan flash on the row.
- **Sync cycle**: bottom-right corner toast appears for 1.5s after each successful cycle: `↻ +3 –1 (412ms)`. Minimal, dismissable.
- **Health pill state change**: pill pulses once on transition, then steady.
- **Drag-to-select on tables**: shift-click range select, bulk action toolbar slides up from bottom.

Avoid: bouncing, big modals, anything that draws the eye away from the feed. The point of a NOC is to *watch*.

---

## 7. Accessibility caveats

The aesthetic uses tight contrast in places (muted slate text). Provide:

- A "high contrast" toggle in settings that swaps `var(--muted)` → `#a8bccf` and `var(--muted-low)` → `#8aa0b9`.
- Focus rings: 2px `var(--accent)` outline, never removed.
- Keyboard nav: every action reachable via Tab; bulk actions via keyboard shortcuts (documented in `?` overlay).

---

## 8. Wizards (`_wizard.html` macro set)

Arc 14 phase 81 ships a shared multi-step wizard primitive at
`templates/_wizard.html`. Use it whenever a configuration flow needs more
than one logical step (bouncer add, federation source add, first-run
setup, SSO config).

### Usage

```jinja
{% extends "base.html" %}
{% from "_wizard.html" import wizard_styles, wizard_steps, wizard_step,
                                 wizard_nav, wizard_script %}

{% block head %}{{ wizard_styles() }}{% endblock %}

{% block content %}
{{ wizard_steps(["Step A", "Step B", "Step C"]) }}
<form method="POST" action="…">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  {% call wizard_step(1, "Step A") %}
    <label>Name</label><input name="name" required>
  {% endcall %}
  {% call wizard_step(2, "Step B") %}
    <label>Key</label><input name="key" required>
  {% endcall %}
  {% call wizard_step(3, "Step C") %}
    <p>Review then save.</p>
  {% endcall %}
  {{ wizard_nav() }}
</form>
{{ wizard_script() }}
{% endblock %}
```

### CSS classes (all defined in `wizard_styles()`)

- `.wiz-steps` — the numbered step indicator at the top. Becomes the only
  scoped element that uses `<ol>`. Each child `<li>` is a `.wiz-step-pill`.
- `.wiz-step-pill.active` — current step, cyan tint, glowing number disc.
- `.wiz-step-pill.done` — earlier step, green tint, checkmark replaces the
  number. Clicking jumps back (forward jumps require validation).
- `.wiz-panel` — one per step. `.active` makes it visible; others are
  `display:none`. The `_wizard.html` JS toggles this on next/prev.
- `.wiz-panel h3` — step title; styled in cyan uppercase to match the
  topbar crumb style.
- `.wiz-panel label / input / select / textarea / .help / pre` — the
  primary control set. Help text uses `.help` for the muted explanation
  line below each field.
- `.wiz-err` — validation error banner at the top of the form. Shown by
  the JS when a required field fails `checkValidity()`.
- `.wiz-nav` — the prev/next button row at the bottom. Contains
  `#wiz-prev` (`.btn`) and `#wiz-next` (`.btn .primary`). The next button
  text flips to "Save →" on the last step.

### State model

Wizards are **purely client-side**. State lives in the form's hidden /
visible fields; navigation just toggles `.active` on the panels. On submit
the full form POSTs in one shot — no server-side draft persistence, no
session state, no autosave. A page refresh resets the wizard.

This matches the existing one-shot-form pattern; the wizard is just a
guided rendering of the same fields, not a state machine.

### Optional `?advanced=1` escape hatch

Long-form wizards should also expose a one-shot form at
`?advanced=1` for operators who already know all the values. The route
returns the wizard template by default and the advanced template when
the query param is present. POST handler is shared.

See `templates/federation_add.html` + `templates/federation_add_advanced.html`
for the canonical pattern.

---

## 9. What the UI is NOT

- **Not Bootstrap.** No Bootstrap classes, no Bootstrap defaults visible. Don't even import it.
- **Not Material.** No ripples, no FABs, no shadows that look like paper.
- **Not a SaaS dashboard.** No friendly empty-state illustrations, no marketing copy, no "Welcome 👋" headers.
- **Not Discord/Slack.** Different problem space.

A useful sniff test: if a CTO looked over the operator's shoulder, would they think this is a serious piece of security infrastructure or a Stripe-style consumer product? It should land squarely in the first bucket.

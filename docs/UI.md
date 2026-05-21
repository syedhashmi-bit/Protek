# UI.md — Design Language & NOC Aesthetic

Protek's UI is a **tactical NOC dashboard**, not an admin panel. This document is the visual contract — refer to it whenever you write or modify a template.

The goal is consistency across the suite: Protek must feel like it belongs next to pipsqueeze and traverse. A user moving between the three apps should not need to recalibrate.

---

## 1. Color Palette

```
Background (deepest):     #06101c   /* near-black with a navy lean */
Background (panel):       #0a1626   /* navy panel base */
Background (raised):      #102236   /* hover / selected row */
Border:                   #1b3050   /* subtle dividers */
Border (accent):          #00c8ff   /* active section, focused field */

Primary accent (cyan):    #00c8ff   /* links, primary buttons, active tab */
Secondary (neon green):   #00ff9d   /* online, success, "all clear" */
Danger (hot red):         #ff3860   /* banned IPs, errors, dry-run badge */
Warning (amber):          #ffb547   /* slow, degraded, partial */
Info (soft cyan):         #6ed3ff   /* secondary info text */

Text (primary):           #d6e4f0
Text (secondary):         #7d94ad
Text (muted):             #4a627e
Text (mono numbers):      #00ff9d   /* all KPI numbers in neon green mono */
```

Use exact hex codes. Do not introduce new accent colors without amending this file.

---

## 2. Typography

```
UI font:        'Rajdhani', sans-serif              (Google Fonts, weights 400/500/600/700)
Mono font:      'Share Tech Mono', monospace        (Google Fonts, single weight)
Fallback:       system sans-serif / monospace
```

Rules:

- **All numeric values use Share Tech Mono.** KPI numbers, IP addresses, counts, timestamps, durations, byte counts. Never display a number in Rajdhani.
- Headings: Rajdhani 600/700, uppercase, +0.05em letter-spacing.
- Body / table cells: Rajdhani 400/500.
- Avoid italics. NOC interfaces don't use italics.

---

## 3. Layout

### Topbar (sticky)

- 56px tall, full-width
- Left: small logo + "PROTEK" wordmark in uppercase Rajdhani
- Center: breadcrumb / page title
- Right: status pill cluster (LAPI · MikroTik · Reconciler) + DRY-RUN badge (if active) + user menu
- Background `#0a1626`, bottom border 1px `#1b3050`

### Sidebar (left, sticky)

- 220px wide, full-height
- Sections: Dashboard · Decisions · Alerts · Scenarios · MikroTik · Federation · Notifications · Security · Settings
- Each item: icon (16px) + label, 36px tall row
- Active item: left border 3px `#00c8ff`, background `#102236`, text `#00c8ff`
- Hover: background `#102236`

### Main content

- Padded 24px, max-width 1600px, centered
- Grid: 12-column, 16px gutter
- Panels are `#0a1626` background, 1px `#1b3050` border, 4px border-radius, 16px internal padding

---

## 4. Panel Patterns

### KPI card

```
┌─────────────────────────────────┐
│  ACTIVE DECISIONS               │  ← uppercase Rajdhani 500, #7d94ad, 11px
│                                 │
│  1,247                          │  ← Share Tech Mono, 36px, #00ff9d
│  ▁▂▃▄▅▆▇ 24h                   │  ← Chart.js sparkline, cyan stroke
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

- Header row: `#06101c` background, uppercase Rajdhani 600, 11px, `#7d94ad`
- Body rows: 32px tall, alternating with `#0a1626` / `#0c1a2e`
- Hover: `#102236`
- Selected: `#102236` + left border 2px `#00c8ff`
- IPs always in Share Tech Mono
- Timestamps relative ("3m ago") with absolute on hover tooltip
- No outer borders — let the panel border do that job

### Buttons

- Primary: solid `#00c8ff` bg, `#06101c` text, no border, 4px radius, uppercase Rajdhani 600
- Secondary: transparent bg, `#00c8ff` text, 1px `#00c8ff` border
- Danger: `#ff3860` variant
- Ghost: transparent bg, `#7d94ad` text, no border (for tertiary actions)
- Buttons in tables are always ghost or secondary, never primary

### Badges

- Scenario badges: rounded, 11px, uppercase, accent color matching scenario family:
  - `http-*` → cyan
  - `ssh-*` → amber
  - `lists:*` → muted slate
  - `crowdsecurity/*` → green
  - custom local scenarios → magenta
- Origin badges: pill-shaped, monospace, smaller
- Dry-run badge in topbar: solid `#ff3860` bg, white text, pulse animation

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

- A "high contrast" toggle in settings that swaps `#7d94ad` → `#a8bccf` and `#4a627e` → `#8aa0b9`.
- Focus rings: 2px `#00c8ff` outline, never removed.
- Keyboard nav: every action reachable via Tab; bulk actions via keyboard shortcuts (documented in `?` overlay).

---

## 8. What the UI is NOT

- **Not Bootstrap.** No Bootstrap classes, no Bootstrap defaults visible. Don't even import it.
- **Not Material.** No ripples, no FABs, no shadows that look like paper.
- **Not a SaaS dashboard.** No friendly empty-state illustrations, no marketing copy, no "Welcome 👋" headers.
- **Not Discord/Slack.** Different problem space.

A useful sniff test: if a CTO looked over the operator's shoulder, would they think this is a serious piece of security infrastructure or a Stripe-style consumer product? It should land squarely in the first bucket.

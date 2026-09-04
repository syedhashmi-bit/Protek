# Protek UI Style Guide (warm)

Contract for building and restyling templates. The design system lives in
**`static/app.css`** (loaded by `base.html`). Pages should *use* those
classes/variables, not reinvent them.

Updated 2026-09-03. The previous revision described a cyan/green "refined NOC"
theme; the palette is now warm and the fonts are IBM Plex. Protek deliberately
no longer matches pipsqueeze/traverse.

## Hard rules
- `templates/base.html`, `static/app.css` and `templates/dashboard.html` are the
  shared foundation. Changing them re-themes or re-navigates the whole app, so
  treat edits there as a design change, not a page tweak — but they are not
  frozen. (The earlier "do NOT edit" wording made the 2026-09-03 warm pass
  technically a rule violation, which is not a useful contract.)
- Every page `{% extends "base.html" %}` and renders inside `{% block body %}`.
- Use the CSS **variables** for all colors/spacing — never hardcode hex.
  Palette (semantic names preferred): `--accent #D9975B`, `--ok #86B27A`,
  `--warn #E3B341`, `--danger #D4736A`, `--info #89A8B3`. `--cyan`/`--green`/
  `--red`/`--amber` still resolve, as aliases, for the ~600 existing references;
  text `--text`, `--muted`, `--muted-low`; surfaces `--bg-deep/-panel/-raised`;
  borders `--border`, `--border-soft`; spacing `--gap` (18px), `--pad` (20px);
  radius `--radius` (8px), `--radius-sm` (5px).
- Keep all functionality, IDs, `{{ }}`/`{% %}`, JS, and `url_for` calls intact.
  This is a **visual** pass, not a behavioral rewrite.

## Do
- Wrap content in `<div class="panel"><h2>Title</h2> …</div>`.
- Use grids: `class="grid cols-2"` or `class="grid cols-3"` (auto-fit, responsive,
  stack on mobile). For KPI rows: `class="grid kpi-strip"` with `.kpi`/`.k`/`.v`/`.d`.
- Use `.btn`, `.btn.sec`, `.btn.ghost`, `.btn.danger` for buttons.
- Use `.badge` (+ `.http/.ssh/.cs/.cust/.list`) for tags.
- Tables: plain `<table>` (auto-styled). On mobile they become cards automatically;
  add `class="keep-table"` only if a table must stay tabular on phones.
- Prefer plain language in visible labels/headers (e.g. "Blocked IPs" over "Decisions").

## Don't
- No glows / `text-shadow` / `box-shadow` beyond `var(--shadow)`.
- No scanline or gradient background overlays.
- No heavy uppercase + wide `letter-spacing` on body text (labels/headers only,
  and keep letter-spacing ≤ .12em).
- No inline `<style>` blobs duplicating what `app.css` already provides. Small
  page-specific tweaks in a `{% block head %}<style>…</style>` are fine, but use
  variables and keep them minimal.
- Don't introduce new fonts. IBM Plex Sans (UI) + IBM Plex Mono (`.mono`, identifiers
  and figures only).

## Quick conversions you'll hit
- `style="display:grid;grid-template-columns:1fr 1fr;gap:16px"` → `class="grid cols-2"`
- hardcoded hex → the tokens: `var(--accent)`, `var(--ok)`, `var(--danger)`,
  `#ffb547` → `var(--amber)`, `#0a1626`/`#06101c` → `var(--bg-panel)`/`var(--bg-deep)`.
- `border:1px solid #1b3050` → `border:1px solid var(--border)`.
- `border-radius:4px` → `var(--radius-sm)`; big cards `var(--radius)`.


## Typography (2026-09-03)
- **IBM Plex Sans** for UI, **IBM Plex Mono** for identifiers and figures only —
  IPs, CIDRs, counts, timestamps, durations, tokens. Not buttons, labels, inputs
  or prose. Pervasive monospace on non-tabular content was the main reason the UI
  read as "vibe-coded".
- **Sentence case.** No `text-transform:uppercase` on labels, headers or nav.
  If you need an eyebrow, cap letter-spacing at `.06em`.
- Use the scales: `--fs-xs|sm|base|md|lg|xl|2xl` and `--sp-1..6`. Do not add new
  hardcoded sizes — the absence of these scales is why ~734 inline `style=`
  attributes accumulated.
- Colour on a figure means "this needs attention". A healthy number is just
  `--text`; reserve `--warn`/`--danger` for states that warrant a look.

## Navigation
- `NAV` in `app.py` is the single source of truth for the sidebar, tab strips,
  crumb and command palette. Add pages there.
- A page joins a tab group by passing the matching `active=` kwarg — no template
  change needed. Drill-down pages map to a parent via `NAV_ALIASES`.

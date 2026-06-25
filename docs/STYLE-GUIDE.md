# Protek UI Style Guide (refined NOC)

Contract for restyling templates. Goal: keep the suite's cyan/green NOC identity
but remove the "vibe-coded" noise — calmer, cleaner, more whitespace. The design
system lives in **`static/app.css`** (loaded by `base.html`). Pages should *use*
those classes/variables, not reinvent them.

## Hard rules
- **Do NOT edit** `templates/base.html`, `static/app.css`, or `templates/dashboard.html`.
  Those are the shared foundation; only the foundation owner touches them.
- Every page `{% extends "base.html" %}` and renders inside `{% block body %}`.
- Use the CSS **variables** for all colors/spacing — never hardcode hex.
  Palette: `--cyan #36c8ef`, `--green #3ee6a8`, `--red #ff5673`, `--amber #f5b552`,
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
- Don't introduce new fonts. Rajdhani (UI) + Share Tech Mono (`.mono`, numbers).

## Quick conversions you'll hit
- `style="display:grid;grid-template-columns:1fr 1fr;gap:16px"` → `class="grid cols-2"`
- hardcoded `#00c8ff` → `var(--cyan)`, `#00ff9d` → `var(--green)`, `#ff3860` → `var(--red)`,
  `#ffb547` → `var(--amber)`, `#0a1626`/`#06101c` → `var(--bg-panel)`/`var(--bg-deep)`.
- `border:1px solid #1b3050` → `border:1px solid var(--border)`.
- `border-radius:4px` → `var(--radius-sm)`; big cards `var(--radius)`.

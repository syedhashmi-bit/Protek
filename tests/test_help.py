"""Roadmap #4 — Help toggle and guided tour.

Coverage (the acceptance criteria "a test fails if a NAV page or a settings
field has no help entry", widened to every section, KPI and field):
  - every NAV page and tab has catalog help with an intro;
  - for every page the catalog covers, each <h2>, each .kpi label and each
    editable named field in its template(s) has an entry — matched the way
    static/help.js matches (heading/label by prefix, field by name or *);
  - explicitly: every field on Settings → Connection & sync and every KPI on
    Overview.
Plumbing: the page embeds the help JSON and loads help.js; the tour lists
only pages the role can open; the first-visit offer shows until the tour is
finished or declined, and that survives a new session (per user).
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

import helpdocs

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip().lower()


def nav_keys() -> list[str]:
    import app
    keys = []
    for grp in app.NAV:
        for it in grp["items"]:
            keys.append(it["key"])
            keys.extend(t["key"] for t in it.get("tabs") or [])
    return sorted(set(keys))


def template_parts(name: str) -> dict[str, list[str]]:
    """h2 leading text, KPI labels, editable field names — as help.js sees them."""
    src = (TEMPLATES / name).read_text()
    src = re.sub(r"\{#.*?#\}", "", src, flags=re.S)          # Jinja comments
    headings = []
    for m in re.finditer(r"<h2\b[^>]*>(.*?)</h2>", src, flags=re.S):
        lead = re.split(r"\{\{|\{%|<", m.group(1), maxsplit=1)[0].strip()
        if lead:
            headings.append(lead)
    # Only labels of .kpi tiles (help.js reads `.kpi .k`); some pages also use
    # .k for plain key/value rows.
    kpis = [m.strip() for m in re.findall(
        r'class="kpi[^"]*"[^>]*>\s*<div class="k">\s*([^<{]+?)\s*<', src)]
    fields = []
    for m in re.finditer(r"<(input|select|textarea)\b([^>]*)>", src, flags=re.S):
        attrs = m.group(2)
        nm = re.search(r'\bname="([^"]+)"', attrs)
        if not nm:
            continue
        typ = re.search(r'\btype="([^"]+)"', attrs)
        if (typ and typ.group(1).lower() in ("hidden", "submit")) or nm.group(1) == "csrf_token":
            continue
        pattern = re.sub(r"\{\{.*?\}\}", "*", nm.group(1))
        if pattern.strip("*"):           # a wholly generated name can't be checked statically
            fields.append(pattern)
    return {"headings": headings, "kpis": kpis, "fields": sorted(set(fields))}


def covered_by_prefix(text: str, keys) -> bool:
    t = norm(text)
    return any(norm(k) and t.startswith(norm(k)) for k in keys)


def covered_field(name: str, fields: dict) -> bool:
    if name in fields:
        return True
    for k in fields:
        if "*" in k and re.fullmatch(".*".join(map(re.escape, k.split("*"))), name):
            return True
    return False


# ── coverage ───────────────────────────────────────────────────────────────

def test_catalog_is_valid_json_with_pages():
    cat = json.loads((ROOT / "help" / "catalog.json").read_text())
    assert cat["pages"], "help/catalog.json has no pages"


@pytest.mark.parametrize("key", nav_keys())
def test_every_nav_page_has_help(key):
    assert helpdocs.has_page(key), f"no help for NAV page {key!r} in help/catalog.json"
    assert helpdocs.for_page(key)["intro"].strip(), f"empty intro for {key!r}"


def _covered_templates():
    out = []
    for key, page in sorted(helpdocs.catalog()["pages"].items()):
        for tpl in page.get("templates") or []:
            out.append((key, tpl))
    return out


@pytest.mark.parametrize("key,tpl", _covered_templates())
def test_every_section_kpi_and_field_has_help(key, tpl):
    parts = template_parts(tpl)
    page = helpdocs.for_page(key)
    missing = [f"section {h!r}" for h in parts["headings"] if not covered_by_prefix(h, page["sections"])]
    missing += [f"kpi {k!r}" for k in parts["kpis"] if not covered_by_prefix(k, page["kpis"])]
    missing += [f"field {f!r}" for f in parts["fields"] if not covered_field(f, page["fields"])]
    assert not missing, f"{key} ({tpl}) has no help for: {', '.join(missing)}"


def test_settings_connection_fields_and_overview_kpis_are_explained():
    settings = helpdocs.for_page("settings")["fields"]
    for name in template_parts("settings.html")["fields"]:
        assert covered_field(name, settings) and (settings.get(name) or "").strip(), name
    kpis = helpdocs.for_page("dashboard")["kpis"]
    for label in template_parts("dashboard.html")["kpis"]:
        assert covered_by_prefix(label, kpis), label


def test_every_main_page_template_is_covered():
    # The pages the tour walks must have their templates listed, so the
    # section/field check above actually runs on them.
    for key in helpdocs.TOUR:
        assert helpdocs.catalog()["pages"][key].get("templates"), key


def test_help_text_has_no_dev_jargon():
    blob = json.dumps(helpdocs.catalog())
    for word in ("phase ", "Phase ", "Arc ", "TODO", "lorem"):
        assert word not in blob, word


# ── plumbing ───────────────────────────────────────────────────────────────

@pytest.fixture
def make_client(monkeypatch, tmp_path):
    import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    import app
    if app.poller:
        app.poller.stop()
    app.app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False, SESSION_COOKIE_DOMAIN=None)
    monkeypatch.setitem(app.app.config, "WTF_CSRF_ENABLED", False)

    def make(role="admin", name=None):
        name = name or f"u-{role}"
        now = datetime.now(timezone.utc).isoformat()
        conn = db.get_conn()
        try:
            row = conn.execute("SELECT id FROM users WHERE username = ?", (name,)).fetchone()
            if not row:
                conn.execute("INSERT INTO users (username, password_hash, totp_secret, role, "
                             "created_at, disabled) VALUES (?, 'x', 'y', ?, ?, 0)", (name, role, now))
                row = conn.execute("SELECT id FROM users WHERE username = ?", (name,)).fetchone()
        finally:
            conn.close()
        c = app.app.test_client()
        with c.session_transaction() as s:
            s.update(logged_in=True, username=name, role=role, user_id=row["id"], last_active=now)
        return c
    return make


def help_data(html: str) -> dict:
    m = re.search(r'<script type="application/json" id="help-data">(.*?)</script>', html, flags=re.S)
    assert m, "help-data not embedded"
    return json.loads(m.group(1))


def test_page_embeds_its_help_and_the_script(make_client):
    html = make_client().get("/").get_data(as_text=True)
    d = help_data(html)
    assert d["page"] == "dashboard" and d["intro"]
    assert d["kpis"] and d["done_url"] == "/ui/tour"
    assert "help.js" in html and 'id="help-btn"' in html


def test_tour_follows_the_role(make_client):
    admin = help_data(make_client("admin").get("/").get_data(as_text=True))["tour"]
    viewer = help_data(make_client("viewer").get("/").get_data(as_text=True))["tour"]
    assert [t["key"] for t in admin] == helpdocs.TOUR
    assert "settings" not in [t["key"] for t in viewer]          # operator-only page


def test_offer_until_done_and_it_survives_a_new_session(make_client):
    c = make_client()
    assert help_data(c.get("/").get_data(as_text=True))["offer"] is True
    assert help_data(c.get("/decisions").get_data(as_text=True))["offer"] is False   # dashboard only
    assert c.post("/ui/tour", data={"done": "1"}).status_code == 204
    again = make_client()                                         # same user, new session
    assert help_data(again.get("/").get_data(as_text=True))["offer"] is False


def test_alias_pages_fall_back_to_their_owner(make_client):
    # Pages reached by drilling down use their NAV owner's help if they have
    # none of their own.
    import app
    with app.app.test_request_context("/"):
        from flask import session
        session.update(logged_in=True, role="admin")
        d = app.help_payload("federation_add")
        assert d["intro"]


def test_help_script_never_uses_innerhtml():
    js = (ROOT / "static" / "help.js").read_text()
    assert "innerHTML" not in js and "insertAdjacentHTML" not in js

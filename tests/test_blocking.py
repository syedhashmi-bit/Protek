"""ROADMAP #1 — "is the router actually blocking?" (blocking.py).

Covers:
  - analyze(): every verdict (blocking / none / disabled / shadowed /
    unverified), coverage, packet counts, IPv6, and the rules that must NOT
    count (negated list, other list, output chain, conditional accept).
  - The fetchers and adapters are read-only: only .get() on the binary API,
    only GET on the REST API.
  - check_target / summarize / refresh caching.
  - The UI: topbar pill via /api/health, the /mikrotik panel + drop-rule
    script, the dashboard banner, "Check now", and the dry-run warning.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import blocking

LIST = "crowdsec"


def rule(chain, action="drop", list_=LIST, **kw):
    r = {".id": "*1", "chain": chain, "action": action, "disabled": "false",
         "invalid": "false", "dynamic": "false", "packets": "0", "bytes": "0"}
    if list_ is not None:
        r["src-address-list"] = list_
    r.update(kw)
    return r


def accept_all(chain):
    return {".id": "*9", "chain": chain, "action": "accept", "disabled": "false",
            "invalid": "false", "dynamic": "false", "packets": "0", "bytes": "0"}


def v4(filter_=None, raw=None):
    return {"filter": filter_ or [], "raw": raw or [], "filter6": None, "raw6": None}


# ── analyze(): verdicts ─────────────────────────────────────────────────────

def test_no_rules_at_all_is_none():
    assert blocking.analyze(LIST, v4())["status"] == "none"


def test_raw_prerouting_drop_blocks_both_directions():
    r = blocking.analyze(LIST, v4(raw=[rule("prerouting", packets="1234")]))
    assert r["status"] == "blocking"
    assert r["coverage"] == ["forward", "input"]
    assert r["packets"] == 1234
    assert r["warnings"] == []


def test_filter_input_and_forward_block_both():
    r = blocking.analyze(LIST, v4(filter_=[rule("input"), rule("forward", action="reject")]))
    assert r["status"] == "blocking"
    assert r["coverage"] == ["forward", "input"]
    assert r["warnings"] == []


def test_input_only_warns_about_forwarded_traffic():
    r = blocking.analyze(LIST, v4(filter_=[rule("input")]))
    assert r["status"] == "blocking"
    assert r["coverage"] == ["input"]
    assert any("port-forwarded" in w for w in r["warnings"])


def test_forward_only_warns_about_the_router_itself():
    r = blocking.analyze(LIST, v4(filter_=[rule("forward")]))
    assert any("router itself" in w for w in r["warnings"])


def test_disabled_rule():
    r = blocking.analyze(LIST, v4(filter_=[rule("input", disabled="true")]))
    assert r["status"] == "disabled"


def test_invalid_rule_counts_as_inactive():
    r = blocking.analyze(LIST, v4(filter_=[rule("input", invalid="true")]))
    assert r["status"] == "disabled"


def test_shadowed_by_earlier_unconditional_accept():
    r = blocking.analyze(LIST, v4(filter_=[accept_all("input"), rule("input")]))
    assert r["status"] == "shadowed"
    assert r["rules"][0]["shadowed"] is True


def test_conditional_accept_does_not_shadow():
    # The default config's "accept established,related" sits above most drop
    # rules; new connections from a banned IP still hit the drop.
    est = {**accept_all("input"), "connection-state": "established,related"}
    r = blocking.analyze(LIST, v4(filter_=[est, rule("input")]))
    assert r["status"] == "blocking"


def test_accept_after_the_drop_does_not_shadow():
    r = blocking.analyze(LIST, v4(filter_=[rule("input"), accept_all("input")]))
    assert r["status"] == "blocking"


def test_accept_in_another_chain_does_not_shadow():
    r = blocking.analyze(LIST, v4(filter_=[accept_all("forward"), rule("input")]))
    assert r["status"] == "blocking"


def test_raw_accept_does_not_shadow_filter_rule():
    # raw `accept` only ends raw processing; the packet still reaches filter.
    r = blocking.analyze(LIST, v4(filter_=[rule("input"), rule("forward")], raw=[accept_all("prerouting")]))
    assert r["status"] == "blocking"


def test_one_live_rule_is_enough_even_if_another_is_shadowed():
    r = blocking.analyze(LIST, v4(filter_=[accept_all("input"), rule("input"), rule("forward")]))
    assert r["status"] == "blocking"
    assert r["coverage"] == ["forward"]


def test_custom_chain_is_unverified():
    r = blocking.analyze(LIST, v4(filter_=[rule("crowdsec-chain")]))
    assert r["status"] == "unverified"
    assert r["custom_chains"] == ["crowdsec-chain"]


def test_rules_that_dont_count():
    rules = [
        rule("input", list_="!" + LIST),        # negated: drops everyone NOT banned
        rule("input", list_="other-list"),      # a different list
        rule("output"),                         # outbound — never sees the attacker
        rule("input", action="accept"),         # not a blocking action
        rule("input", list_=None),              # no address list at all
    ]
    assert blocking.analyze(LIST, v4(filter_=rules))["status"] == "none"


def test_ipv6_missing_rule_warns_when_v4_blocks():
    tables = {"filter": [rule("input"), rule("forward")], "raw": [], "filter6": [], "raw6": []}
    r = blocking.analyze(LIST, tables)
    assert r["status"] == "blocking"
    assert r["v6_status"] == "none"
    assert any("IPv6" in w for w in r["warnings"])


def test_ipv6_rule_present():
    tables = {"filter": [], "raw": [rule("prerouting")], "filter6": [], "raw6": [rule("prerouting")]}
    r = blocking.analyze(LIST, tables)
    assert r["v6_status"] == "blocking"
    assert r["warnings"] == []


def test_no_ipv6_firewall_means_no_v6_verdict():
    r = blocking.analyze(LIST, v4(raw=[rule("prerouting")]))
    assert r["v6_status"] is None


# ── read-only fetchers ──────────────────────────────────────────────────────

class _Resource:
    def __init__(self, calls, path, rows):
        self.calls, self.path, self.rows = calls, path, rows

    def get(self, **kw):
        self.calls.append(("get", self.path))
        return self.rows

    def __getattr__(self, name):          # add / remove / set / call / …
        def write(*a, **kw):
            self.calls.append((name, self.path))
            raise AssertionError(f"write call {name} on {self.path}")
        return write


class _Api:
    def __init__(self, tables, ipv6=True):
        self.calls: list = []
        self.tables, self.ipv6 = tables, ipv6

    def get_resource(self, path):
        if path.startswith("/ipv6") and not self.ipv6:
            raise RuntimeError("no such command prefix")
        return _Resource(self.calls, path, self.tables.get(path, []))


class _MT:
    def __init__(self, api):
        self._api = None
        self._real = api
        self.connected = 0

    def connect(self):
        self.connected += 1
        self._api = self._real

    def disconnect(self):
        self._api = None


def test_api_fetch_only_reads():
    api = _Api({"/ip/firewall/raw": [rule("prerouting")]})
    mt = _MT(api)
    tables = blocking.fetch_rules_api(mt)
    assert tables["raw"] == [rule("prerouting")]
    assert tables["filter6"] == [] and tables["raw6"] == []
    assert {c[0] for c in api.calls} == {"get"}
    assert mt._api is None, "must disconnect"


def test_api_fetch_without_ipv6():
    tables = blocking.fetch_rules_api(_MT(_Api({}, ipv6=False)))
    assert tables["filter6"] is None and tables["raw6"] is None


def test_db_adapter_firewall_rules_is_read_only(monkeypatch):
    from bouncers.mikrotik_db_adapter import MikroTikDBAdapter
    b = MikroTikDBAdapter(name="edge", host="192.0.2.1", username="u", password="p")
    api = _Api({"/ip/firewall/filter": [rule("input"), rule("forward")]})
    b._mt = _MT(api)
    r = blocking.check_target(b)
    assert r["status"] == "blocking" and r["target"] == "edge" and r["list"] == LIST
    assert {c[0] for c in api.calls} == {"get"}


def test_rest_adapter_firewall_rules_only_issues_gets(monkeypatch):
    from bouncers.mikrotik_rest_adapter import MikroTikRESTAdapter
    b = MikroTikRESTAdapter(name="rest", host="192.0.2.2", username="u", password="p")
    methods = []

    class _Resp:
        def __init__(self, body):
            self._body = body
            self.content = b"x"

        def raise_for_status(self):
            pass

        def json(self):
            return self._body

    def fake_request(method, path, json=None):
        methods.append(method)
        return _Resp([rule("prerouting")] if path.endswith("ip/firewall/raw") else [])

    monkeypatch.setattr(b, "_request", fake_request)
    r = blocking.check_target(b)
    assert r["status"] == "blocking"
    assert set(methods) == {"GET"}


# ── check_target / summarize / cache ───────────────────────────────────────

class _FakeTarget:
    kind = "mikrotik"

    def __init__(self, name, tables=None, error=None, list_name=LIST):
        self.name, self._tables, self._error, self.list_name = name, tables, error, list_name

    def firewall_rules(self):
        if self._error:
            raise RuntimeError(self._error)
        return self._tables


def test_unreachable_router_is_unknown():
    r = blocking.check_target(_FakeTarget("edge", error="connect failed: timed out"))
    assert r["status"] == "unknown"
    assert "timed out" in r["error"]


def test_non_mikrotik_targets_are_skipped():
    class _Cloudflare:
        name, kind = "cf", "cloudflare"
    assert blocking.check_target(_Cloudflare()) is None


def test_summarize_picks_the_worst():
    ok = blocking.check_target(_FakeTarget("a", v4(raw=[rule("prerouting")])))
    bad = blocking.check_target(_FakeTarget("b", v4()))
    s = blocking.summarize([ok, bad])
    assert s["status"] == "none" and s["worst"] == "b"
    assert blocking.summarize([])["status"] is None


def test_refresh_caches_and_cached_reads_back(monkeypatch):
    import bouncers
    monkeypatch.setattr(bouncers, "load_all_targets",
                        lambda: [_FakeTarget("edge", v4(raw=[rule("prerouting")]))])
    out = blocking.refresh()
    assert out["status"] == "blocking"
    back = blocking.cached()
    assert back["status"] == "blocking" and back["targets"][0]["target"] == "edge"
    assert blocking.age_seconds(back) < 5


def test_pill_states():
    assert blocking.pill_state("blocking") == "ok"
    assert blocking.pill_state("unverified") == "warn"
    assert blocking.pill_state("unknown") == "warn"
    for s in ("none", "disabled", "shadowed"):
        assert blocking.pill_state(s) == "down"
    assert blocking.pill_state(None) is None


# ── UI ─────────────────────────────────────────────────────────────────────

@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    import app
    app.app.config["TESTING"] = True
    app.app.config["SESSION_COOKIE_SECURE"] = False
    app.app.config["SESSION_COOKIE_DOMAIN"] = None
    # The POST routes are CSRF-protected; these tests exercise what happens after.
    monkeypatch.setitem(app.app.config, "WTF_CSRF_ENABLED", False)
    now = datetime.now(timezone.utc).isoformat()
    conn = db.get_conn()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, totp_secret, role, "
            "created_at, disabled) VALUES ('testop', 'x', 'y', 'operator', ?, 0)", (now,))
        uid = conn.execute("SELECT id FROM users WHERE username = 'testop'").fetchone()["id"]
    finally:
        conn.close()
    c = app.app.test_client()
    with c.session_transaction() as s:
        s.update(logged_in=True, username="testop", role="operator", user_id=uid, last_active=now)
    return c


def _targets(monkeypatch, *targets):
    import bouncers
    monkeypatch.setattr(bouncers, "load_all_targets", lambda: list(targets))


def test_api_health_reports_blocking_pill(client, monkeypatch):
    _targets(monkeypatch, _FakeTarget("edge", v4()))
    blocking.refresh()
    j = client.get("/api/health").get_json()
    assert j["blocking"] == "down"
    assert j["blocking_label"].startswith("Not blocking")


def test_api_health_hides_pill_without_mikrotik_targets(client, monkeypatch):
    _targets(monkeypatch)
    blocking.refresh()
    assert client.get("/api/health").get_json()["blocking"] is None


def test_mikrotik_page_shows_fix_when_not_blocking(client, monkeypatch):
    import html as _html
    _targets(monkeypatch, _FakeTarget("edge", v4(), list_name="protek-dev"))
    html = _html.unescape(client.get("/mikrotik").get_data(as_text=True))
    assert "Is the router blocking?" in html
    assert "Not blocking" in html
    # The drop-rule script, rendered for this target's own list name.
    assert ':local listname "protek-dev"' in html
    assert "/ip firewall raw add chain=prerouting" in html


def test_mikrotik_page_when_blocking_has_no_script(client, monkeypatch):
    _targets(monkeypatch, _FakeTarget("edge", v4(raw=[rule("prerouting", packets="42")])))
    html = client.get("/mikrotik").get_data(as_text=True)
    assert "Blocking active" in html
    assert "42" in html
    assert "/ip firewall raw add" not in html


def test_check_now_refreshes(client, monkeypatch):
    _targets(monkeypatch, _FakeTarget("edge", v4(filter_=[rule("input", disabled="true")])))
    r = client.post("/mikrotik/blocking/check")
    assert r.status_code == 302
    assert blocking.cached()["status"] == "disabled"


def test_dashboard_banner_only_when_not_blocking(client, monkeypatch):
    from db import set_setting
    set_setting(blocking.SETTING_KEY, json.dumps({"status": "none", "worst": "edge", "targets": []}))
    set_setting("settings.dry_run", "0")
    assert "no active firewall rule drops traffic" in client.get("/").get_data(as_text=True)
    set_setting("settings.dry_run", "1")
    assert "when you turn dry-run off" in client.get("/").get_data(as_text=True)
    set_setting(blocking.SETTING_KEY, json.dumps({"status": "blocking", "targets": []}))
    assert "no active firewall rule drops traffic" not in client.get("/").get_data(as_text=True)


def test_turning_dry_run_off_warns_when_not_blocking(client, monkeypatch):
    from db import set_setting
    set_setting("settings.dry_run", "1")
    set_setting(blocking.SETTING_KEY, json.dumps({"status": "none", "worst": "edge", "targets": []}))
    client.post("/settings", data={"dry_run": "false", "sync_interval_sec": "10", "batch_cap": "200"})
    with client.session_transaction() as s:
        flashes = [m for _, m in s.get("_flashes", [])]
    assert any("nothing will drop them" in m for m in flashes)


def test_turning_dry_run_off_is_quiet_when_blocking(client, monkeypatch):
    from db import set_setting
    set_setting("settings.dry_run", "1")
    set_setting(blocking.SETTING_KEY, json.dumps({"status": "blocking", "targets": []}))
    client.post("/settings", data={"dry_run": "false", "sync_interval_sec": "10", "batch_cap": "200"})
    with client.session_transaction() as s:
        flashes = [m for _, m in s.get("_flashes", [])]
    assert not any("nothing will drop them" in m for m in flashes)


# ── gaps: IPv6 and partial coverage (found on a real router) ────────────────

def _v4_and_empty_v6():
    return {"filter": [rule("input"), rule("forward")], "raw": [], "filter6": [], "raw6": []}


def test_v6_gap_names_the_count():
    r = blocking.analyze(LIST, _v4_and_empty_v6(), v6_entries=1500)
    assert r["v6_gap"] is True
    assert any("1,500 IPv6 bans aren't blocked" in w for w in r["warnings"])


def test_no_v6_entries_means_no_v6_warning():
    r = blocking.analyze(LIST, _v4_and_empty_v6(), v6_entries=0)
    assert r["v6_gap"] is False and r["warnings"] == []


def test_partial_is_amber_with_its_own_label():
    t = blocking.check_target(_FakeTarget("edge", _v4_and_empty_v6()))
    s = blocking.summarize([t])
    assert s["status"] == "blocking" and s["partial"] is True
    assert blocking.pill_state(s["status"], s["partial"]) == "warn"
    assert blocking.label_for(s["status"], s["partial"]) == "Blocking — with gaps"
    assert blocking.label_for("blocking") == "Blocking active"


def test_summary_points_at_the_router_with_the_gap():
    full = blocking.check_target(_FakeTarget("a", {"filter": [], "raw": [rule("prerouting")],
                                                   "filter6": [], "raw6": [rule("prerouting")]}))
    gap = blocking.check_target(_FakeTarget("b", _v4_and_empty_v6()))
    s = blocking.summarize([full, gap])
    assert s["worst"] == "b" and s["partial"] is True


def test_note_v6_entries_writes_only_on_change(monkeypatch):
    import db
    writes = []
    real = db.set_setting
    monkeypatch.setattr(db, "set_setting", lambda k, v: (writes.append((k, v)), real(k, v)))
    blocking._V6_SEEN.clear()
    blocking.note_v6_entries("edge", 5)
    blocking.note_v6_entries("edge", 5)
    blocking.note_v6_entries("edge", 6)
    assert writes == [("blocking.v6_entries.edge", "5"), ("blocking.v6_entries.edge", "6")]
    assert blocking._v6_entries("edge") == 6


def test_check_target_uses_the_recorded_v6_count():
    blocking._V6_SEEN.clear()
    blocking.note_v6_entries("edge-v6", 42)
    t = blocking.check_target(_FakeTarget("edge-v6", _v4_and_empty_v6()))
    assert any("42 IPv6 bans" in w for w in t["warnings"])


def test_mikrotik_page_offers_ipv6_only_script_for_a_v6_gap(client, monkeypatch):
    import html as _html
    blocking._V6_SEEN.clear()
    blocking.note_v6_entries("edge", 1500)
    _targets(monkeypatch, _FakeTarget("edge", _v4_and_empty_v6()))
    page = _html.unescape(client.get("/mikrotik").get_data(as_text=True))
    assert "Blocking — with gaps" in page
    assert "/ipv6 firewall raw add chain=prerouting" in page
    assert "/ip firewall raw add" not in page        # IPv4 already covered


def test_dashboard_banner_names_the_gap(client):
    from db import set_setting
    set_setting(blocking.SETTING_KEY, json.dumps({
        "status": "blocking", "partial": True, "worst": "edge",
        "targets": [{"target": "edge", "status": "blocking",
                     "warnings": ["1,500 IPv6 bans aren't blocked — no IPv6 firewall rule drops the crowdsec list."]}]}))
    page = client.get("/").get_data(as_text=True)
    assert "Blocking — with gaps" in page
    assert "1,500 IPv6 bans" in page

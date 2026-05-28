"""Arc 16 phase 97 — per-MT routing rules.

Tests for `_filter_desired_for_bouncer`'s new `source_filter` and
`scenario_filter` kwargs. The acceptance gate from ROADMAP.md:

  with two MTs configured (`edge-mt`, `office-mt`), setting
  `office-mt.scenario_filter='http-.*'` results in `office-mt`
  receiving only http-family decisions on the next reconcile cycle.
  The other MT continues to receive the full set.
"""
from __future__ import annotations

import pytest


def _decisions():
    """Three federation sources × three scenarios = 9 decisions for
    filtering tests."""
    out = []
    for source in ("local", "vps-b", "remote-3"):
        for scenario in ("crowdsecurity/http-bf",
                          "crowdsecurity/ssh-bf",
                          "crowdsecurity/postfix-bf"):
            out.append({
                "value": f"203.0.113.{len(out) + 1}",
                "scope": "Ip",
                "scenario": scenario,
                "origin": "crowdsec",
                "origin_source": source,
                "lapi_id": len(out) + 1,
            })
    return out


class _StubBouncer:
    """Minimal Bouncer with stash-able filter attrs."""
    def __init__(self, name="mt", **attrs):
        self.name = name
        for k, v in attrs.items():
            setattr(self, k, v)


def test_no_filter_passes_through():
    from reconciler import _filter_desired_for_bouncer
    d = _decisions()
    b = _StubBouncer()
    assert _filter_desired_for_bouncer(b, d) == d


def test_source_filter_csv_string():
    """Operator types `local,vps-b` in the form; the CSV string is
    parsed at filter time."""
    from reconciler import _filter_desired_for_bouncer
    d = _decisions()
    b = _StubBouncer(source_filter="local,vps-b")
    out = _filter_desired_for_bouncer(b, d)
    sources = {x["origin_source"] for x in out}
    assert sources == {"local", "vps-b"}
    # 3 scenarios × 2 sources = 6
    assert len(out) == 6


def test_source_filter_list_input():
    """Same filter accepts list form too (for programmatic configs
    setting it via config_json)."""
    from reconciler import _filter_desired_for_bouncer
    d = _decisions()
    b = _StubBouncer(source_filter=["local"])
    out = _filter_desired_for_bouncer(b, d)
    assert all(x["origin_source"] == "local" for x in out)
    assert len(out) == 3


def test_source_filter_with_whitespace():
    """`local, vps-b` (note the space) should still parse cleanly."""
    from reconciler import _filter_desired_for_bouncer
    d = _decisions()
    b = _StubBouncer(source_filter=" local , vps-b ")
    out = _filter_desired_for_bouncer(b, d)
    assert len(out) == 6


def test_scenario_filter_regex():
    """The acceptance gate: scenario_filter='http-' narrows to http-bf only."""
    from reconciler import _filter_desired_for_bouncer
    d = _decisions()
    b = _StubBouncer(scenario_filter="http-")
    out = _filter_desired_for_bouncer(b, d)
    assert all("http-" in x["scenario"] for x in out)
    # 1 scenario × 3 sources = 3
    assert len(out) == 3


def test_scenario_filter_anchored_regex():
    """Anchored regex works as expected — `^crowdsecurity/http-` matches
    all http-bf decisions, `^crowdsecurity/ssh-` matches all ssh-bf."""
    from reconciler import _filter_desired_for_bouncer
    d = _decisions()
    assert len(_filter_desired_for_bouncer(
        _StubBouncer(scenario_filter=r"^crowdsecurity/http-"), d)) == 3
    assert len(_filter_desired_for_bouncer(
        _StubBouncer(scenario_filter=r"^crowdsecurity/ssh-"), d)) == 3


def test_invalid_regex_logs_and_passes_through():
    """A bad regex must NOT crash the reconcile loop. We log and skip
    the filter — operator sees the un-filtered set and the bad regex
    is visible on /bouncers/edit."""
    from reconciler import _filter_desired_for_bouncer
    d = _decisions()
    b = _StubBouncer(scenario_filter="[invalid(unclosed")
    out = _filter_desired_for_bouncer(b, d)
    assert out == d  # full set passed through


def test_combined_source_and_scenario_filter():
    """The acceptance gate's compound case: source=local + scenario=ssh
    yields exactly one decision (local source + ssh-bf scenario)."""
    from reconciler import _filter_desired_for_bouncer
    d = _decisions()
    b = _StubBouncer(source_filter="local", scenario_filter="ssh-")
    out = _filter_desired_for_bouncer(b, d)
    assert len(out) == 1
    assert out[0]["origin_source"] == "local"
    assert "ssh-" in out[0]["scenario"]


def test_filter_preserves_other_filters():
    """Verify the new filters compose with the existing origins/exclude_origins
    knobs without regression."""
    from reconciler import _filter_desired_for_bouncer
    d = _decisions()
    # Add a community-list decision so exclude_origins=['lists:*'] excludes it
    d.append({"value": "203.0.113.99", "scope": "Ip",
              "scenario": "crowdsecurity/http-bf", "origin": "lists:firehol",
              "origin_source": "local", "lapi_id": 999})
    b = _StubBouncer(exclude_origins=["lists:*"], scenario_filter="http-")
    out = _filter_desired_for_bouncer(b, d)
    # http-bf decisions only, AND lists:* excluded → 3 (the three original
    # crowdsec/http-bf rows, not the lists:firehol one)
    assert len(out) == 3
    assert all(x["origin"] != "lists:firehol" for x in out)


def test_two_bouncers_get_disjoint_sets():
    """Acceptance gate verbatim: edge-mt gets everything, office-mt gets
    only http-* on the next reconcile cycle. Same decision input to both."""
    from reconciler import _filter_desired_for_bouncer
    d = _decisions()
    edge_mt = _StubBouncer(name="edge-mt")
    office_mt = _StubBouncer(name="office-mt", scenario_filter="http-")
    edge_set = _filter_desired_for_bouncer(edge_mt, d)
    office_set = _filter_desired_for_bouncer(office_mt, d)
    assert len(edge_set) == 9
    assert len(office_set) == 3
    assert all("http-" in x["scenario"] for x in office_set)


def test_adapter_accepts_new_kwargs():
    """Verify the mikrotik_db_adapter wires the kwargs through to instance
    attrs — otherwise the filter never gets a chance to read them off the
    bouncer object."""
    from bouncers.mikrotik_db_adapter import MikroTikDBAdapter
    a = MikroTikDBAdapter(name="test-mt",
                            host="", username="", password="",
                            source_filter="local,vps-b",
                            scenario_filter="ssh-")
    assert a.source_filter == "local,vps-b"
    assert a.scenario_filter == "ssh-"


def test_adapter_default_filters_blank():
    """Constructor defaults: leaving filters out preserves today's
    behavior (this MT gets the full set)."""
    from bouncers.mikrotik_db_adapter import MikroTikDBAdapter
    a = MikroTikDBAdapter(name="test-mt", host="", username="", password="")
    assert a.source_filter is None
    assert a.scenario_filter is None


def test_field_schema_advertises_new_fields():
    """field_schema drives /bouncers/add wizard. Both new fields must
    be declared so they render as proper inputs (not hidden in
    config_json)."""
    from bouncers.mikrotik_db_adapter import MikroTikDBAdapter
    field_names = {f["name"] for f in MikroTikDBAdapter.field_schema}
    assert "source_filter" in field_names
    assert "scenario_filter" in field_names

"""Arc 16 phase 98 — RouterOS REST API adapter tests.

Unit-level: stub `requests.request` so the adapter can run without
a real RouterOS. Verifies the same Bouncer protocol contract as the
binary `mikrotik_db_adapter`, plus the REST-specific behaviors
(idempotent 400-on-duplicate, idempotent 404-on-remove, error
text extraction from JSON).
"""
from __future__ import annotations

import json
from typing import Any

import pytest


class _FakeResponse:
    def __init__(self, status_code: int = 200,
                 json_body: Any = None,
                 text: str = ""):
        self.status_code = status_code
        self._json = json_body
        self.text = text or (json.dumps(json_body) if json_body else "")
        self.content = self.text.encode("utf-8") if self.text else b""

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise __import__("requests").HTTPError(f"status {self.status_code}")


@pytest.fixture
def adapter(monkeypatch: pytest.MonkeyPatch):
    """Returns (adapter_instance, request_log). Every requests call goes
    into request_log so the test can assert on URL / method / body."""
    from bouncers.mikrotik_rest_adapter import MikroTikRESTAdapter
    a = MikroTikRESTAdapter(
        name="edge-rest",
        host="10.0.0.1", username="protek", password="hunter2",
        port=443, use_ssl=True, verify_tls=False,
        address_list="crowdsec",
    )
    log: list[dict] = []
    responses: list[_FakeResponse] = []

    def _record(method, url, **kwargs):
        log.append({"method": method, "url": url, **kwargs})
        if responses:
            return responses.pop(0)
        return _FakeResponse(200, json_body=[])

    import requests
    monkeypatch.setattr(requests, "request", _record)
    return a, log, responses


# ── is_configured / construction ─────────────────────────────────────────


def test_is_configured_requires_all_creds(monkeypatch: pytest.MonkeyPatch):
    from bouncers.mikrotik_rest_adapter import MikroTikRESTAdapter
    assert MikroTikRESTAdapter(host="", username="", password="").is_configured() is False
    assert MikroTikRESTAdapter(host="x", username="x", password="x").is_configured() is True


def test_field_schema_includes_required_keys():
    """field_schema drives the wizard rendering. The new REST-specific
    fields must be declared so /bouncers/add shows them."""
    from bouncers.mikrotik_rest_adapter import MikroTikRESTAdapter
    names = {f["name"] for f in MikroTikRESTAdapter.field_schema}
    for needed in ("host", "username", "password", "port", "use_ssl",
                    "verify_tls", "address_list", "page_size",
                    "source_filter", "scenario_filter"):
        assert needed in names


def test_kind_is_registered():
    """The @register('mikrotik_rest') decorator must have run at import."""
    import bouncers
    assert "mikrotik_rest" in bouncers.KINDS


def test_base_url_construction():
    from bouncers.mikrotik_rest_adapter import MikroTikRESTAdapter
    a = MikroTikRESTAdapter(host="10.0.0.1", port=443, use_ssl=True)
    assert a._base_url() == "https://10.0.0.1:443/rest"
    a = MikroTikRESTAdapter(host="rt.local", port=80, use_ssl=False)
    assert a._base_url() == "http://rt.local:80/rest"


# ── snapshot ────────────────────────────────────────────────────────────────


def test_snapshot_returns_normalized_entries(adapter):
    a, log, responses = adapter
    responses.append(_FakeResponse(200, json_body=[
        {".id": "*1", "list": "crowdsec",
         "address": "203.0.113.1", "comment": "protek:1:ssh-bf"},
        {".id": "*2", "list": "crowdsec",
         "address": "203.0.113.2", "comment": "protek:2:http-bf"},
    ]))
    snap = a.snapshot()
    assert len(snap) == 2
    assert snap[0][".id"] == "*1"
    assert snap[0]["address"] == "203.0.113.1"
    assert snap[0]["comment"] == "protek:1:ssh-bf"
    # URL contains the list name + the rest path
    assert "address-list" in log[0]["url"]
    assert "list=crowdsec" in log[0]["url"]


def test_snapshot_swallows_http_error(adapter, monkeypatch):
    a, log, responses = adapter
    import requests
    def _boom(*a, **k):
        raise requests.ConnectionError("network down")
    monkeypatch.setattr(requests, "request", _boom)
    # Errors must NOT propagate — reconciler treats empty snapshot as
    # "we don't know" and the per-bouncer ok flag handles the rest.
    assert a.snapshot() == []


def test_snapshot_handles_non_list_json(adapter):
    """If REST returns something other than a JSON list (operator pointed
    config at the wrong endpoint, etc.), return an empty list rather
    than crash."""
    a, _log, responses = adapter
    responses.append(_FakeResponse(200, json_body={"error": "bad endpoint"}))
    assert a.snapshot() == []


# ── apply ──────────────────────────────────────────────────────────────────


def test_apply_add_success(adapter):
    a, log, responses = adapter
    responses.append(_FakeResponse(201, json_body={".id": "*A"}))
    res = a.apply(to_add=[("203.0.113.5", "protek:5:test")], to_remove_ids=[])
    assert res["applied_add"] == 1
    assert res["errors"] == 0
    assert res["push_log"][0]["success"] is True
    assert log[0]["method"] == "PUT"
    assert "address-list" in log[0]["url"]
    assert log[0]["json"]["list"] == "crowdsec"
    assert log[0]["json"]["address"] == "203.0.113.5"


def test_apply_add_idempotent_on_duplicate(adapter):
    """A 400 with `already have such entry` should be treated as a
    successful add (matches the binary adapter's idempotency semantics
    from line 122 of mikrotik_db_adapter.py)."""
    a, log, responses = adapter
    responses.append(_FakeResponse(
        400, json_body={"detail": "already have such entry"}))
    res = a.apply(to_add=[("203.0.113.5", "x")], to_remove_ids=[])
    assert res["applied_add"] == 1
    assert res["errors"] == 0
    assert res["push_log"][0]["error"] == "idempotent"


def test_apply_add_real_400_is_error(adapter):
    """A 400 for any other reason (bad address, malformed comment) is
    a real error and must increment the error counter."""
    a, log, responses = adapter
    responses.append(_FakeResponse(
        400, json_body={"detail": "invalid value for address"}))
    res = a.apply(to_add=[("not-an-ip", "x")], to_remove_ids=[])
    assert res["applied_add"] == 0
    assert res["errors"] == 1
    assert res["push_log"][0]["success"] is False


def test_apply_remove_success(adapter):
    a, log, responses = adapter
    responses.append(_FakeResponse(204))
    res = a.apply(to_add=[], to_remove_ids=["*A"])
    assert res["applied_remove"] == 1
    assert res["errors"] == 0
    assert log[0]["method"] == "DELETE"


def test_apply_remove_idempotent_on_404(adapter):
    """The entry's already gone — still counts as successful remove.
    Race condition between snapshot and apply that's safe to absorb."""
    a, log, responses = adapter
    responses.append(_FakeResponse(404, text="not found"))
    res = a.apply(to_add=[], to_remove_ids=["*missing"])
    assert res["applied_remove"] == 1
    assert res["errors"] == 0
    assert res["push_log"][0]["error"] == "idempotent"


def test_apply_request_exception_is_error(adapter, monkeypatch):
    a, log, responses = adapter
    import requests
    monkeypatch.setattr(requests, "request",
                         lambda *a, **k: (_ for _ in ()).throw(
                             requests.Timeout("slow router")))
    res = a.apply(to_add=[("1.2.3.4", "x")], to_remove_ids=[])
    assert res["errors"] == 1
    assert res["applied_add"] == 0
    assert "slow router" in res["push_log"][0]["error"]


# ── health ────────────────────────────────────────────────────────────────


def test_health_returns_ok_with_version(adapter):
    a, log, responses = adapter
    responses.append(_FakeResponse(200, json_body={
        "version": "7.15.3", "uptime": "1w2d3h", "board-name": "RB5009"}))
    responses.append(_FakeResponse(200, json_body=[
        {".id": f"*{i}"} for i in range(1234)]))
    h = a.health()
    assert h["ok"] is True
    assert h["version"] == "7.15.3"
    assert h["size"] == 1234
    assert h["board"] == "RB5009"
    assert h["kind"] == "mikrotik_rest"


def test_health_returns_not_configured_when_blank():
    from bouncers.mikrotik_rest_adapter import MikroTikRESTAdapter
    a = MikroTikRESTAdapter(host="", username="", password="")
    h = a.health()
    assert h["ok"] is False
    assert "not configured" in h["error"]


def test_health_returns_error_on_network_failure(adapter, monkeypatch):
    a, _, _ = adapter
    import requests
    monkeypatch.setattr(requests, "request",
                         lambda *args, **kw: (_ for _ in ()).throw(
                             requests.ConnectionError("network unreachable")))
    h = a.health()
    assert h["ok"] is False
    assert "unreachable" in h["error"]


# ── phase 97 filter attrs flow through ────────────────────────────────────


def test_filter_attrs_set_on_instance():
    """The reconciler reads source_filter/scenario_filter via getattr —
    they MUST land on the instance for the filter to apply."""
    from bouncers.mikrotik_rest_adapter import MikroTikRESTAdapter
    a = MikroTikRESTAdapter(
        host="x", username="x", password="x",
        source_filter="local,vps-b",
        scenario_filter="http-",
    )
    assert a.source_filter == "local,vps-b"
    assert a.scenario_filter == "http-"


# ── parity with binary adapter on diff inputs ─────────────────────────────


def test_snapshot_output_is_diff_compatible(adapter):
    """The reconciler's diff (reconcile.py) reads `.id` + `address` +
    `comment` off each entry. The REST adapter's snapshot output must
    use the same key shape as the binary adapter so the diff function
    is transport-agnostic."""
    a, _log, responses = adapter
    responses.append(_FakeResponse(200, json_body=[
        {".id": "*1", "address": "1.2.3.4", "comment": "protek:1:test",
         "list": "crowdsec"},
    ]))
    snap = a.snapshot()
    assert ".id" in snap[0]
    assert "address" in snap[0]
    assert "comment" in snap[0]

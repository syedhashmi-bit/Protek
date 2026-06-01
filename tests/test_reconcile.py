"""Unit tests for reconcile.py — the only piece of logic that must be exactly
correct. Pure-function design lets us cover every branch without LAPI or MT."""

from __future__ import annotations


from reconcile import (OWNER_PREFIX, decode_comment,
                       encode_comment, is_owned, reconcile)


# ── Helpers ─────────────────────────────────────────────────────────────────

def decision(value, scenario="crowdsecurity/http-probing", lapi_id=1, src="local"):
    return {"value": value, "scenario": scenario, "lapi_id": lapi_id, "origin_source": src}


def mt(addr, comment="protek:local:crowdsecurity/http-probing:1", _id="*1"):
    return {"address": addr, "comment": comment, ".id": _id, "list": "crowdsec"}


# ── Comment encoding round-trip ─────────────────────────────────────────────

def test_encode_comment_prefix():
    c = encode_comment(decision("1.2.3.4", "crowdsecurity/ssh-bf", lapi_id=42))
    assert c.startswith(OWNER_PREFIX)


def test_encode_decode_roundtrip():
    d = decision("1.2.3.4", scenario="crowdsecurity/ssh-bf", lapi_id=99, src="remote-vps")
    c = encode_comment(d)
    parsed = decode_comment(c)
    assert parsed == {"origin_source": "remote-vps", "scenario": "crowdsecurity/ssh-bf", "lapi_id": "99"}


def test_encode_handles_empty_fields():
    c = encode_comment({"value": "1.2.3.4"})
    assert c == "protek:local::0"
    assert decode_comment(c) == {"origin_source": "local", "scenario": "", "lapi_id": "0"}


def test_decode_returns_none_for_foreign():
    assert decode_comment("manually-added") is None
    assert decode_comment("") is None
    assert decode_comment(None) is None  # type: ignore[arg-type]


def test_decode_accepts_unknown_protek_variants():
    # Forward-compatibility: future Protek versions might add fields. We
    # should still recognize the entry as owned.
    parsed = decode_comment("protek:local:scen:1:extra:more")
    assert parsed is not None
    assert parsed["origin_source"] == "local"
    assert parsed["scenario"] == "scen"
    # The "extra:more" gets folded into lapi_id because we split with maxsplit
    assert parsed["lapi_id"].startswith("1")


def test_is_owned():
    assert is_owned("protek:local::1")
    assert not is_owned("something else")
    assert not is_owned("")
    assert not is_owned(None)


def test_encode_sanitizes_colons_in_scenario():
    # A scenario name containing ":" would break our 4-field delimiter contract.
    c = encode_comment(decision("1.1.1.1", scenario="lists:firehol_attacks", lapi_id=7))
    parsed = decode_comment(c)
    # Colons are replaced with underscores so the structure stays parseable
    assert parsed["scenario"] == "lists_firehol_attacks"


# ── Edge cases on diff shape ────────────────────────────────────────────────

def test_empty_empty():
    d = reconcile([], [])
    assert d.to_add == []
    assert d.to_remove == []
    assert d.unchanged == 0
    assert d.foreign_kept == 0


def test_full_empty_first_run():
    # Bootstrap on a brand-new router.
    desired = [decision("1.1.1.1", lapi_id=1), decision("2.2.2.2", lapi_id=2)]
    d = reconcile(desired, [])
    assert len(d.to_add) == 2
    assert d.to_remove == []
    assert d.unchanged == 0


def test_empty_full_after_expiry():
    # All bans expired; MT still has stale Protek entries.
    current = [mt("1.1.1.1", _id="*A"), mt("2.2.2.2", _id="*B")]
    d = reconcile([], current)
    assert d.to_add == []
    assert sorted(d.to_remove) == ["*A", "*B"]


def test_overlap_only_adds_new():
    desired = [decision("1.1.1.1", lapi_id=1), decision("2.2.2.2", lapi_id=2)]
    current = [mt("1.1.1.1", _id="*1")]
    d = reconcile(desired, current)
    addrs_to_add = [a for (a, _c) in d.to_add]
    assert addrs_to_add == ["2.2.2.2"]
    assert d.to_remove == []
    assert d.unchanged == 1


# ── Ownership filter — the sacred rule ──────────────────────────────────────

def test_foreign_entries_never_removed():
    # Address-list has Protek entries + entries from another tool. The
    # foreign ones must survive even when the desired set is empty.
    current = [
        mt("1.1.1.1", _id="*A"),  # owned
        {"address": "9.9.9.9", "comment": "manually added", ".id": "*Z", "list": "crowdsec"},
    ]
    d = reconcile([], current)
    assert d.to_remove == ["*A"]
    assert d.foreign_kept == 1
    assert "*Z" not in d.to_remove


def test_foreign_entry_collision_does_not_remove_or_re_add():
    # If a foreign entry already has the same address Protek wants to add,
    # we still add (RouterOS will reject duplicates which the caller catches),
    # because *we don't own* the foreign entry. Treat it as if it weren't there.
    desired = [decision("9.9.9.9", lapi_id=1)]
    current = [{"address": "9.9.9.9", "comment": "other tool", ".id": "*Z", "list": "crowdsec"}]
    d = reconcile(desired, current)
    addrs_to_add = [a for (a, _c) in d.to_add]
    assert addrs_to_add == ["9.9.9.9"]
    assert d.to_remove == []
    assert d.foreign_kept == 1


def test_id_field_with_dot_or_no_dot():
    # Some routeros_api versions strip the leading dot on the .id field.
    current = [
        {"address": "1.1.1.1", "comment": "protek:local::1", "id": "*A", "list": "crowdsec"},
        {"address": "2.2.2.2", "comment": "protek:local::2", ".id": "*B", "list": "crowdsec"},
    ]
    d = reconcile([], current)
    assert sorted(d.to_remove) == ["*A", "*B"]


# ── CIDR scope and address normalization ────────────────────────────────────

def test_cidr_scope_round_trip():
    # A /24 from the LAPI matches itself in MT as a /24.
    desired = [decision("10.0.0.0/24", lapi_id=1)]
    current = [mt("10.0.0.0/24")]
    d = reconcile(desired, current)
    assert d.to_add == []
    assert d.to_remove == []
    assert d.unchanged == 1


def test_ip_with_and_without_slash_32_is_equivalent():
    # MT may store an IP as "1.2.3.4/32" while LAPI hands us "1.2.3.4".
    desired = [decision("1.2.3.4", lapi_id=1)]
    current = [mt("1.2.3.4/32")]
    d = reconcile(desired, current)
    assert d.to_add == []
    assert d.to_remove == []
    assert d.unchanged == 1


def test_ipv6_loopback_128_is_equivalent():
    desired = [decision("2001:db8::1", lapi_id=1)]
    current = [mt("2001:db8::1/128")]
    d = reconcile(desired, current)
    assert d.unchanged == 1


# ── Comment carries metadata ───────────────────────────────────────────────

def test_add_includes_owner_comment():
    desired = [decision("1.1.1.1", scenario="crowdsecurity/ssh-bf", lapi_id=42, src="local")]
    d = reconcile(desired, [])
    addr, comment = d.to_add[0]
    assert addr == "1.1.1.1"
    assert comment == "protek:local:crowdsecurity/ssh-bf:42"


# ── Federation-ready dedup ─────────────────────────────────────────────────

def test_duplicate_value_from_different_sources_dedupes():
    # Phase 2 only has one source so this isn't yet exercised in prod, but the
    # function must handle phase-7 federation already.
    desired = [
        {"value": "1.1.1.1", "lapi_id": 1, "origin_source": "local"},
        {"value": "1.1.1.1", "lapi_id": 99, "origin_source": "remote-vps"},
    ]
    d = reconcile(desired, [])
    assert len(d.to_add) == 1


# ── Idempotency invariant ──────────────────────────────────────────────────

def test_double_application_is_noop():
    desired = [decision("1.1.1.1", lapi_id=1), decision("2.2.2.2", lapi_id=2)]
    first = reconcile(desired, [])
    # Simulate MT having absorbed the adds (with our comments).
    new_current = [mt(addr, comment=cmt, _id=f"*{i}") for i, (addr, cmt) in enumerate(first.to_add)]
    second = reconcile(desired, new_current)
    assert second.to_add == []
    assert second.to_remove == []
    assert second.unchanged == 2

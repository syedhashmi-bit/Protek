#!/usr/bin/env python3
"""
run_soak.py — Arc 15 phase 90. Multi-day soak harness for Protek.

Drives a staging Protek instance with synthetic load (POST decisions via
/api/external/decisions), samples resource usage every 30 seconds (RSS,
open FDs, WAL size, sync_events rate, error rate), and asserts thresholds.
On the first sustained violation, exits non-zero so a nightly cron can
alert the operator.

Designed for nightly CI on a small VPS. See ../README.md for the spec.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import signal
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests


# ── Synthetic decision generator ──────────────────────────────────────────

def _random_test_ip() -> str:
    """Return a random IP from the RFC 5737 TEST-NET-2 (198.51.100.0/24)
    or TEST-NET-3 (203.0.113.0/24) blocks. These are documentation-only,
    reserved for testing, and will never appear in legitimate traffic."""
    block = random.choice(["198.51.100", "203.0.113"])
    return f"{block}.{random.randint(1, 254)}"


def _inject_decision(target_url: str, api_token: str) -> tuple[bool, str]:
    """POST one synthetic decision. Returns (ok, detail)."""
    ip = _random_test_ip()
    try:
        r = requests.post(
            f"{target_url.rstrip('/')}/api/external/decisions",
            headers={
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
            },
            json={
                "ip": ip,
                "reason": "soak-harness-synthetic-injection",
                "duration": "5m",
                "source": "soak-harness",
            },
            timeout=10,
        )
        if r.status_code in (200, 201, 202):
            return True, str(r.status_code)
        return False, f"HTTP {r.status_code}: {r.text[:80]}"
    except Exception as e:  # noqa: BLE001
        return False, str(e)[:120]


# ── Sampler ─────────────────────────────────────────────────────────────

def _find_protek_pid() -> int | None:
    """Look up the protek gunicorn master PID via systemctl. Returns None
    if not found — sampler skips sample with a warning."""
    try:
        import subprocess
        out = subprocess.run(
            ["systemctl", "show", "protek", "-p", "MainPID"],
            capture_output=True, text=True, timeout=3,
        )
        if out.returncode != 0:
            return None
        for line in out.stdout.splitlines():
            if line.startswith("MainPID="):
                pid = int(line.split("=", 1)[1])
                return pid if pid > 0 else None
    except Exception:  # noqa: BLE001
        return None
    return None


def _sample_rss_kb(pid: int) -> int:
    """RSS in KiB from /proc/<pid>/status. Returns 0 on failure."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except Exception:  # noqa: BLE001
        pass
    return 0


def _sample_open_fds(pid: int) -> int:
    """Count of entries in /proc/<pid>/fd."""
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except Exception:  # noqa: BLE001
        return 0


def _sample_wal_bytes(db_path: str) -> int:
    try:
        return os.stat(f"{db_path}-wal").st_size
    except OSError:
        return 0


def _sample_sync_metrics(target_url: str, api_token: str) -> dict[str, Any]:
    """Pull /api/sync/status (auth via bearer token). Returns the latest
    sync_event's added/removed/errors/duration_ms."""
    try:
        r = requests.get(
            f"{target_url.rstrip('/')}/api/v1/system/sync_status",
            headers={"Authorization": f"Bearer {api_token}"},
            timeout=5,
        )
        if r.status_code != 200:
            return {"errors": -1, "note": f"HTTP {r.status_code}"}
        d = r.json()
        # Tolerate different response shapes (api/v1 vs api/legacy).
        return {
            "errors":      int(d.get("errors") or d.get("last_errors") or 0),
            "duration_ms": int(d.get("duration_ms") or d.get("last_duration_ms") or 0),
            "added":       int(d.get("added") or d.get("last_to_add") or 0),
        }
    except Exception as e:  # noqa: BLE001
        return {"errors": -1, "note": f"sync_status fetch failed: {e}"[:120]}


# ── Threshold checker ────────────────────────────────────────────────────

class ThresholdChecker:
    """Tracks a rolling window of samples and flags sustained violations.
    Single spikes are ignored — only >=3 consecutive samples (last 90s
    at 30s sampling) trigger a fail."""

    REQUIRED_CONSECUTIVE = 3

    def __init__(self, args):
        self.args = args
        self._rss_history: deque[tuple[float, int]] = deque(maxlen=240)  # 2h at 30s
        self._violations: dict[str, int] = {}

    def check(self, sample: dict[str, Any]) -> list[dict[str, Any]]:
        """Returns list of {threshold, detail, sustained_count}. Empty if clean."""
        out = []
        now = sample["t"]
        # RSS leak: compare oldest-in-window to current
        self._rss_history.append((now, sample["rss_kb"]))
        if len(self._rss_history) >= 60:  # need at least 30 min of data
            t0, rss0 = self._rss_history[0]
            hours = (now - t0) / 3600.0
            if hours > 0:
                mb_per_hour = ((sample["rss_kb"] - rss0) / 1024.0) / hours
                if mb_per_hour > self.args.threshold_rss_growth_mb_per_hour:
                    out.append(self._bump("rss_growth",
                        f"RSS growing at {mb_per_hour:.1f} MB/h over the last "
                        f"{hours:.1f}h (threshold {self.args.threshold_rss_growth_mb_per_hour})"))
                else:
                    self._violations["rss_growth"] = 0
        # FDs
        if sample["fds"] > self.args.threshold_fds_max:
            out.append(self._bump("fds_max",
                f"open FDs={sample['fds']} > {self.args.threshold_fds_max}"))
        else:
            self._violations["fds_max"] = 0
        # WAL
        wal_mb = sample["wal_bytes"] / 1024 / 1024
        if wal_mb > self.args.threshold_wal_max_mb:
            out.append(self._bump("wal_max",
                f"WAL is {wal_mb:.1f} MB > {self.args.threshold_wal_max_mb} "
                "(WAL-truncate timer broken?)"))
        else:
            self._violations["wal_max"] = 0
        # Error rate
        if sample.get("sync_errors", 0) > self.args.threshold_error_rate_per_cycle:
            out.append(self._bump("error_rate",
                f"sync errors={sample['sync_errors']} > {self.args.threshold_error_rate_per_cycle}"))
        else:
            self._violations["error_rate"] = 0
        return [v for v in out if v["sustained_count"] >= self.REQUIRED_CONSECUTIVE]

    def _bump(self, key: str, detail: str) -> dict[str, Any]:
        n = self._violations.get(key, 0) + 1
        self._violations[key] = n
        return {"threshold": key, "detail": detail, "sustained_count": n}


# ── Orchestrator ────────────────────────────────────────────────────────

def main() -> int:
    p = argparse.ArgumentParser(description="Protek soak harness — phase 90")
    p.add_argument("--target-url", required=True,
                   help="Protek base URL, e.g. http://127.0.0.1:8090")
    p.add_argument("--api-token", required=True,
                   help="Bearer token from /admin/tokens (operator scope)")
    p.add_argument("--duration-hours", type=float, default=72.0)
    p.add_argument("--inject-rate-per-min", type=int, default=1000)
    p.add_argument("--sample-interval-s", type=int, default=30)
    p.add_argument("--db-path", default="/var/www/Protek/protek.db")
    p.add_argument("--threshold-rss-growth-mb-per-hour", type=float, default=5.0)
    p.add_argument("--threshold-fds-max", type=int, default=500)
    p.add_argument("--threshold-wal-max-mb", type=float, default=100.0)
    p.add_argument("--threshold-error-rate-per-cycle", type=int, default=5)
    p.add_argument("--output-csv", default=None,
                   help="Path to per-sample CSV log (default: ./soak-<ts>.csv)")
    args = p.parse_args()

    out_path = Path(args.output_csv or
                    f"soak-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.csv")
    print(f"[soak] target={args.target_url}  duration={args.duration_hours}h"
          f"  inject={args.inject_rate_per_min}/min  csv={out_path}", flush=True)

    pid = _find_protek_pid()
    if not pid:
        print("[soak] warning: could not find protek pid — RSS/FD samples will be 0",
              flush=True)

    deadline = time.monotonic() + args.duration_hours * 3600
    inject_interval = 60.0 / max(1, args.inject_rate_per_min)
    last_sample = 0.0
    stop_flag = threading.Event()

    def _stop(_signo, _frame):
        print("[soak] received signal, stopping cleanly", flush=True)
        stop_flag.set()
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    checker = ThresholdChecker(args)
    csv_file = out_path.open("w", newline="")
    writer = csv.DictWriter(csv_file, fieldnames=[
        "ts", "rss_kb", "fds", "wal_bytes", "sync_errors",
        "sync_duration_ms", "sync_added", "inject_ok", "inject_fail",
    ])
    writer.writeheader()
    csv_file.flush()

    inject_ok = 0
    inject_fail = 0
    last_inject = 0.0

    try:
        while not stop_flag.is_set() and time.monotonic() < deadline:
            now = time.monotonic()

            # Inject decisions at target rate (best-effort timing)
            if now - last_inject >= inject_interval:
                ok, _detail = _inject_decision(args.target_url, args.api_token)
                if ok:
                    inject_ok += 1
                else:
                    inject_fail += 1
                last_inject = now

            # Periodic sample + threshold check
            if now - last_sample >= args.sample_interval_s:
                sample = {
                    "t":             now,
                    "ts":            datetime.now(timezone.utc).isoformat(),
                    "rss_kb":        _sample_rss_kb(pid) if pid else 0,
                    "fds":           _sample_open_fds(pid) if pid else 0,
                    "wal_bytes":     _sample_wal_bytes(args.db_path),
                }
                sync = _sample_sync_metrics(args.target_url, args.api_token)
                sample["sync_errors"]      = sync.get("errors", -1)
                sample["sync_duration_ms"] = sync.get("duration_ms", 0)
                sample["sync_added"]       = sync.get("added", 0)
                sample["inject_ok"]   = inject_ok
                sample["inject_fail"] = inject_fail

                writer.writerow({k: v for k, v in sample.items() if k != "t"})
                csv_file.flush()

                violations = checker.check(sample)
                if violations:
                    for v in violations:
                        print(f"[soak][FAIL] {v['threshold']} "
                              f"(sustained {v['sustained_count']}x): {v['detail']}",
                              flush=True)
                    fail_path = out_path.with_suffix(".fail.json")
                    fail_path.write_text(json.dumps({
                        "ts": sample["ts"], "sample": {k: v for k, v in sample.items() if k != "t"},
                        "violations": violations,
                    }, indent=2))
                    print(f"[soak] failure record written to {fail_path}", flush=True)
                    return 1
                last_sample = now

                print(f"[soak] {sample['ts']}  rss={sample['rss_kb']/1024:.0f}MB"
                      f"  fds={sample['fds']}  wal={sample['wal_bytes']/1024/1024:.1f}MB"
                      f"  inject ok/fail={inject_ok}/{inject_fail}"
                      f"  sync_err={sample['sync_errors']}", flush=True)

            time.sleep(min(0.5, inject_interval / 2))

        print(f"[soak] completed cleanly after {args.duration_hours}h", flush=True)
        return 0
    finally:
        csv_file.close()


if __name__ == "__main__":
    sys.exit(main())

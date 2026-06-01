# Grafana board pack

Closes phase 33 — pairs with the `/metrics` Prometheus endpoint
shipped in arc 6.

## Files

| File | Description |
|------|-------------|
| `protek-overview.json` | Single-board overview: poller lag, reconcile timing, push errors, active decisions by origin + source, source health, hygiene KPIs |

## Prometheus scrape

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: protek
    metrics_path: /metrics
    scheme: http
    static_configs:
      - targets: ['127.0.0.1:8090']   # bare-metal default port
    bearer_token: <METRICS_TOKEN>      # the value set in .env
```

If `METRICS_TOKEN` is unset on the Protek side, scrapes from
non-localhost addresses are rejected with HTTP 403 — set the token
to allow off-box Prometheus.

## Importing the board

Two paths, pick one:

### Grafana UI
1. Dashboards → New → Import
2. Upload `protek-overview.json` (or paste the contents)
3. Select your Prometheus datasource when prompted
4. Save

### Provisioning (recommended for ops)

Drop the JSON under your Grafana provisioning dir:

```yaml
# /etc/grafana/provisioning/dashboards/protek.yaml
apiVersion: 1
providers:
  - name: protek
    folder: Protek
    type: file
    options:
      path: /etc/grafana/dashboards/protek
```

```bash
sudo mkdir -p /etc/grafana/dashboards/protek
sudo cp protek-overview.json /etc/grafana/dashboards/protek/
sudo systemctl restart grafana-server
```

The board appears under Dashboards → Protek → Overview after restart
and auto-updates whenever the JSON file changes (Grafana watches the
provisioning dir).

## Panels at a glance

- **Service strip** — Poller lag · Last reconcile · Active decisions ·
  DRY/LIVE state · Bouncer count · Push-error 5m rate. All
  threshold-coloured (green/yellow/red) so the operator can see
  health at a glance.
- **Reconcile timing & throughput** — Reconcile duration vs configured
  interval, per-cycle add/remove/error counts, cycle rate, push
  errors rate by bouncer.
- **Decisions** — Active total, by-origin top-10, by-federation-source,
  source health.
- **Hygiene** — Whitelist rule count, pending approvals, login attempt
  rate, geo-cache size.

## Tuning the thresholds

Hardcoded today:
- Poller lag: green ≤ 30s, yellow 30–60s, red > 60s
- Reconcile duration: green ≤ 5s, yellow 5–30s, red > 30s
- Push errors rate: green = 0/s, yellow > 0.05/s, red > 0.5/s
- Approvals pending: yellow > 5

These match the phase 91 SLO defaults. If your deployment runs longer
cycles (community blocklists), edit the JSON's `thresholds.steps`
arrays inline rather than tuning settings keys — the board is
operator-tunable, not a single source of truth.

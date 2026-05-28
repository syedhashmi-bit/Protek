# syntax=docker/dockerfile:1.6
#
# Protek — multi-stage Dockerfile, Arc 16 phase 95.
#
# Stage 1 (`builder`): Python 3.12-slim + build-essential, installs the
# venv into /opt/venv. The build stage carries the apt + pip caches that
# we drop on the way out.
#
# Stage 2 (`runtime`): same Python 3.12-slim base, no build-essential.
# Copies the venv + app code, runs as non-root uid 1000. The container
# is stateless — protek.db lives on a volume mounted at /data.
#
# Multi-arch: python:3.12-slim ships amd64 + arm64, so the same image
# runs on Hetzner CAX (arm64), Pi 5, AWS Graviton, and the typical x86
# cloud VPS without per-arch builds.

FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt


FROM python:3.12-slim AS runtime

# Non-root user. UID 1000 matches the default first non-system user on
# Ubuntu, so a bind-mounted ./data from an Ubuntu host has matching
# ownership without an explicit chown.
RUN groupadd -r protek --gid 1000 \
 && useradd -r -g protek --uid 1000 --home /app --shell /usr/sbin/nologin protek \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        sqlite3 \
        ca-certificates \
        curl \
        tini \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=protek:protek . /app

# State volume — protek.db, .protek.db-litestream, and (optionally) .env
# all live here. PROTEK_DB_PATH points db.py at the volumed location;
# bare-metal installs leave it unset and the default parent-dir layout
# still works.
RUN mkdir -p /data && chown protek:protek /data
VOLUME ["/data"]

USER protek

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PROTEK_DB_PATH=/data/protek.db \
    SYNC_INTERVAL_SEC=10 \
    DRY_RUN=true \
    COOKIE_INSECURE=1

EXPOSE 8090

# /health is the same liveness endpoint nginx-based deploys use. The
# 15s start-period lets the first poller cycle complete before the
# health check counts misses.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8090/health > /dev/null || exit 1

# tini handles SIGTERM forwarding to gunicorn so `docker stop` is graceful
# (otherwise gunicorn worker processes orphan and reconcile mid-cycle).
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["gunicorn", "--workers", "2", "--bind", "0.0.0.0:8090", \
     "--access-logfile", "-", "--error-logfile", "-", \
     "--timeout", "120", "app:app"]

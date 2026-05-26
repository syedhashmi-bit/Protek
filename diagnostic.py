"""
diagnostic.py — Arc 14 phase 84.

Structured ladder probe: DNS → TCP → TLS → auth → API smoke. Each rung
returns one row in the result; the operator sees exactly where things
break instead of a generic "connection error".

Used by `/bouncers/add`, `/bouncers/<id>`, `/federation/add`,
`/federation/<id>`, and the phase-86 first-run wizard.

The probe is shallow on purpose — every call has a small timeout, and
the whole ladder completes in ~3 seconds even for fully-broken hosts.
That way the operator can re-run it as often as they want without
waiting on long timeouts.
"""

from __future__ import annotations

import socket
import ssl
import time
from typing import Any
from urllib.parse import urlparse

import requests

# Each rung returns:
#   {step: str, status: 'ok' | 'fail' | 'skip', detail: str, hint: str, ms: int}
# `hint` is only populated on `fail` and is the operator-actionable
# guess at the likely cause.


def _ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


def _step(name: str, status: str, detail: str = "", hint: str = "", ms: int = 0):
    return {"step": name, "status": status, "detail": detail, "hint": hint, "ms": ms}


def diagnose_url(url: str, *, api_key: str | None = None,
                 auth_header: str = "X-Api-Key",
                 expect_status_lt: int = 500,
                 api_smoke_path: str = "/v1/decisions/stream",
                 api_smoke_query: dict | None = None,
                 timeout: float = 3.0) -> list[dict[str, Any]]:
    """Run the DNS → TCP → TLS → auth → API smoke ladder against a URL.

    Returns a list of step dicts in execution order. Later steps are
    'skip' if an earlier step failed (we never claim the API smoked OK
    if we never even resolved DNS). This makes the result deterministic
    in the UI: row N is always step N.
    """
    out: list[dict[str, Any]] = []
    try:
        u = urlparse(url)
    except Exception:  # noqa: BLE001
        return [_step("parse url", "fail",
                      detail=f"could not parse {url!r}",
                      hint="URL should look like 'http://host:port' or 'https://host'")]

    scheme = (u.scheme or "").lower()
    host = u.hostname or ""
    port = u.port or (443 if scheme == "https" else 80 if scheme == "http" else 0)

    if scheme not in ("http", "https"):
        return [_step("parse url", "fail",
                      detail=f"unsupported scheme {scheme!r}",
                      hint="Use http:// or https://. SFTP/other schemes are not LAPI transports.")]
    if not host:
        return [_step("parse url", "fail",
                      detail="missing host",
                      hint="URL needs a host — e.g. http://<vps-b-wg-ip>:8080")]

    out.append(_step("parse url", "ok",
                     detail=f"scheme={scheme} host={host} port={port}"))

    # 1. DNS — only meaningful for names; literal IPs skip.
    t0 = time.monotonic()
    try:
        socket.inet_aton(host)
        is_literal = True
    except OSError:
        is_literal = False
    if is_literal:
        out.append(_step("DNS", "skip", detail=f"{host} is a literal IPv4", ms=_ms(t0)))
    else:
        try:
            t0 = time.monotonic()
            resolved = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            ips = sorted({r[4][0] for r in resolved})
            out.append(_step("DNS", "ok",
                             detail=f"{host} → {', '.join(ips[:3])}",
                             ms=_ms(t0)))
        except socket.gaierror as e:
            out.append(_step("DNS", "fail",
                             detail=str(e),
                             hint=f"hostname '{host}' doesn't resolve — typo, "
                                  "DNS down, or remote not provisioned yet",
                             ms=_ms(t0)))
            return _pad_skip(out, ["TCP", "TLS", "auth", "API"])
        except Exception as e:  # noqa: BLE001
            out.append(_step("DNS", "fail", detail=str(e),
                             hint="DNS resolver returned an unexpected error", ms=_ms(t0)))
            return _pad_skip(out, ["TCP", "TLS", "auth", "API"])

    # 2. TCP connect
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            out.append(_step("TCP", "ok",
                             detail=f"connected to {host}:{port}", ms=_ms(t0)))
    except (TimeoutError, socket.timeout) as e:
        out.append(_step("TCP", "fail",
                         detail=f"timeout after {timeout}s",
                         hint=f"firewall is silently dropping TCP {port} from this host, "
                              "or the remote service isn't bound on that port",
                         ms=_ms(t0)))
        return _pad_skip(out, ["TLS", "auth", "API"])
    except ConnectionRefusedError:
        out.append(_step("TCP", "fail",
                         detail=f"connection refused on {host}:{port}",
                         hint=f"nothing listening on TCP {port} — service down, "
                              "wrong port, or bound on a different interface",
                         ms=_ms(t0)))
        return _pad_skip(out, ["TLS", "auth", "API"])
    except Exception as e:  # noqa: BLE001
        out.append(_step("TCP", "fail", detail=str(e),
                         hint="check that the host is reachable from this Protek instance "
                              "(WG/Tailscale up? VPN routed?)",
                         ms=_ms(t0)))
        return _pad_skip(out, ["TLS", "auth", "API"])

    # 3. TLS handshake (only for https://)
    if scheme == "https":
        t0 = time.monotonic()
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cn = ""
                    for tup in cert.get("subject", []):
                        for k, v in tup:
                            if k == "commonName":
                                cn = v
                                break
                    out.append(_step("TLS", "ok",
                                     detail=f"cert CN={cn or '?'}, cipher={ssock.cipher()[0]}",
                                     ms=_ms(t0)))
        except ssl.SSLCertVerificationError as e:
            out.append(_step("TLS", "fail",
                             detail=f"cert verify failed: {e.reason}",
                             hint="self-signed / expired / hostname-mismatched cert. "
                                  "Set verify_tls=false in the bouncer config if expected.",
                             ms=_ms(t0)))
            return _pad_skip(out, ["auth", "API"])
        except ssl.SSLError as e:
            out.append(_step("TLS", "fail", detail=str(e),
                             hint="TLS handshake error — protocol/cipher mismatch, or the "
                                  "remote isn't actually serving TLS on this port",
                             ms=_ms(t0)))
            return _pad_skip(out, ["auth", "API"])
        except Exception as e:  # noqa: BLE001
            out.append(_step("TLS", "fail", detail=str(e),
                             hint="unexpected TLS error", ms=_ms(t0)))
            return _pad_skip(out, ["auth", "API"])
    else:
        out.append(_step("TLS", "skip", detail="plaintext HTTP — no TLS step"))

    # 4. Auth — issue a HEAD/GET to the API root with the credential. We
    # treat 401/403 specifically; 2xx-4xx<500 means the server accepted
    # the connection and replied semantically.
    base = url.rstrip("/")
    headers = {api_smoke_path: api_smoke_path}  # noqa: F841 (unused)
    auth_headers: dict[str, str] = {}
    if api_key:
        auth_headers[auth_header] = api_key

    t0 = time.monotonic()
    try:
        r = requests.get(f"{base}{api_smoke_path}",
                         params=api_smoke_query or {"startup": "true"},
                         headers=auth_headers,
                         timeout=timeout, verify=False)
    except requests.exceptions.ConnectionError as e:
        out.append(_step("auth", "fail", detail=str(e)[:200],
                         hint="HTTP request failed after TCP succeeded — check the path "
                              f"({api_smoke_path}) is correct on the remote",
                         ms=_ms(t0)))
        return _pad_skip(out, ["API"])
    except Exception as e:  # noqa: BLE001
        out.append(_step("auth", "fail", detail=str(e)[:200],
                         hint="unexpected HTTP error", ms=_ms(t0)))
        return _pad_skip(out, ["API"])

    if r.status_code in (401, 403):
        out.append(_step("auth", "fail",
                         detail=f"HTTP {r.status_code}",
                         hint="API key is wrong, revoked, or lacks the required scope. "
                              "Regenerate with `cscli bouncers add` (federation) or the "
                              "provider's API key UI and paste the new value.",
                         ms=_ms(t0)))
        return _pad_skip(out, ["API"])
    if r.status_code >= 500:
        out.append(_step("auth", "fail",
                         detail=f"HTTP {r.status_code}: {r.text[:120]}",
                         hint="remote returned a server error — its API is up but unhealthy",
                         ms=_ms(t0)))
        return _pad_skip(out, ["API"])
    out.append(_step("auth", "ok",
                     detail=f"HTTP {r.status_code} ({len(r.content)}B)",
                     ms=_ms(t0)))

    # 5. API smoke — interpret the body. Subclasses can extend this for
    # bouncer-specific assertions; the default checks the response is
    # parseable as JSON OR is plaintext-OK.
    t0 = time.monotonic()
    if r.status_code >= expect_status_lt:
        out.append(_step("API", "fail",
                         detail=f"HTTP {r.status_code}",
                         hint=f"expected <{expect_status_lt}, got {r.status_code}",
                         ms=_ms(t0)))
        return out
    body_preview = ""
    try:
        if r.headers.get("content-type", "").startswith("application/json"):
            body_preview = f"JSON: {list(r.json().keys() if isinstance(r.json(), dict) else [])[:5]}"
        else:
            body_preview = f"non-JSON, {len(r.content)}B"
    except Exception:  # noqa: BLE001
        body_preview = f"un-parseable, {len(r.content)}B"
    out.append(_step("API", "ok",
                     detail=f"HTTP {r.status_code} · {body_preview}", ms=_ms(t0)))
    return out


def _pad_skip(out: list[dict[str, Any]], rest: list[str]) -> list[dict[str, Any]]:
    """Append skip rows for ladder rungs we never reached."""
    for s in rest:
        out.append(_step(s, "skip", detail="earlier step failed"))
    return out


def summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Distill the ladder into a one-line headline for the UI banner."""
    fails = [r for r in rows if r["status"] == "fail"]
    if not fails:
        last_ok = [r for r in rows if r["status"] == "ok"]
        return {"ok": True,
                "headline": f"OK — last good rung: {last_ok[-1]['step']}",
                "fail_step": None, "fail_hint": ""}
    f = fails[0]
    return {"ok": False,
            "headline": f"failed at {f['step']}: {f['detail']}",
            "fail_step": f["step"], "fail_hint": f["hint"]}

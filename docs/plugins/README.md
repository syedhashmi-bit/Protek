# Writing a Protek bouncer plugin

Protek ships with adapters for MikroTik, iptables/ipset, Cloudflare,
pfSense, and OPNsense. To add a new one **without forking Protek**,
drop a Python file into one of:

- `~/.config/protek/adapters/` (default)
- `$PROTEK_PLUGIN_DIR/` (env var override, for system-wide installs)

Restart `protek` — your adapter shows up at `/bouncers` as a new "kind"
the operator can configure.

## Skeleton

```python
# ~/.config/protek/adapters/sophos.py
from bouncers import register


@register("sophos")
class SophosBouncer:
    name = ""

    # Optional manifest — surfaced in /bouncers UI for provenance + config hints.
    PROTEK_MANIFEST = {
        "author":   "you@example.com",
        "version":  "1.0.0",
        "summary":  "Sophos XG firewall web filtering address list",
        "required": ["api_key", "endpoint"],
    }

    def __init__(self, name: str, **config):
        self.name = name
        self.api_key  = config["api_key"]
        self.endpoint = config["endpoint"]

    def is_configured(self) -> bool:
        return bool(self.api_key and self.endpoint)

    def health(self) -> dict:
        # Cheap reachability probe. Return {"ok": True, ...} or {"ok": False, ...}.
        ...

    def snapshot(self) -> list[dict]:
        # Return the entries CURRENTLY in your remote, filtered to those
        # Protek owns (comment starts with "protek:"). Each dict needs at
        # least: {"address": "1.2.3.4", ".id": "remote-id", "comment": "..."}.
        ...

    def apply(self, to_add: list[tuple[str, str]],
              to_remove_ids: list[str]) -> dict:
        # to_add:        [(ip_or_cidr, comment_starting_with_protek:), ...]
        # to_remove_ids: [".id" handles from snapshot(), ...]
        # Return: {"applied_add": n, "applied_remove": m, "errors": e,
        #          "push_log": [{"ip": ..., "action": "add", "success": bool, "error": ""}]}
        ...
```

## The five things you MUST get right

1. **Comment ownership.** Every entry your `apply()` writes must have a
   comment starting with `protek:` — Protek's reconcile only deletes
   entries with this prefix. `snapshot()` must filter to those entries
   only. If you delete a non-`protek:` entry, you've eaten someone's
   manual rule and the operator will revoke your plugin.
2. **Idempotency.** Re-adding an address that already exists must be a
   silent no-op or a caught duplicate error — never raise.
3. **Bounded batch.** Don't push 30k IPs in one call to a remote API.
   Pre-chunk to 100-1000 per request, and cooperate with phase-68
   `ratelimit.acquire("bouncer.<kind>")` for backpressure.
4. **Comment encoding.** Use exactly `protek:<origin_source>:<scenario>:<lapi_id>`
   so other tools (federation peers, intel exporters) can round-trip the
   ownership info. The `reconcile.build_comment()` helper does this for
   you when called from the diff engine.
5. **No `time.sleep()` in apply().** Apply runs in the reconcile thread.
   If your remote is slow, return early with whatever you couldn't push
   — the next cycle picks it up.

## Manifest fields

| Field | Type | Use |
|-------|------|-----|
| `author` | str | Email or GitHub handle |
| `version` | str | Semver |
| `summary` | str | One-line description for the /bouncers UI |
| `required` | list[str] | Config keys the operator must provide when adding a target |

Required keys are validated client-side in the "add bouncer target" form
(if your manifest is present). Missing-key errors return before the form
submits, so the operator can't save a bouncer that will boot-loop.

## Testing your plugin locally

```bash
mkdir -p ~/.config/protek/adapters/
cp my_plugin.py ~/.config/protek/adapters/
sudo systemctl restart protek
sudo journalctl -u protek -n 50 | grep plugin
```

You should see `INFO protek.plugin_loader: plugin loaded: kind=<your_kind> path=...`.
If you see `WARNING protek.plugin_loader: plugin <path> failed to load: ...`,
fix the syntax/import error and restart.

After loading, `/bouncers` will list your kind as an option in the add-target form.

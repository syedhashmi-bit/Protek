# Multi-region Protek deployment

Reference Terraform module for spinning up a 3-region Protek cluster on
Hetzner with a private WireGuard mesh. The hub aggregates peer dashboards
via the phase-76 `/peers` feature.

## Single-region (the simple case)

If you just want one VPS, skip Terraform — follow the README install.sh path:

```bash
curl -fsSL https://raw.githubusercontent.com/syedhashmi-bit/Protek/main/install.sh | sudo bash
```

## Multi-region (this directory)

### Prerequisites

- Terraform >= 1.5
- Hetzner Cloud API token: https://console.hetzner.cloud → Security → API Tokens
- An SSH public key

### Apply

```bash
cd deploy/terraform
terraform init

export TF_VAR_hcloud_token='HCLD_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
export TF_VAR_ssh_pubkey="$(cat ~/.ssh/id_ed25519.pub)"
terraform apply -var 'regions=["nbg1","ash","sin"]'
```

Output is the IPv4 of each instance plus the WireGuard mesh IP.

### Post-apply

The first region (`var.regions[0]`) is the **hub**. The others register to
it as peers.

For each peer:
1. SSH in (`ssh root@<peer-ipv4>`).
2. Read the admin creds from `/var/log/protek/init.log` — capture them, then
   delete the file (it's chmod 0600 but never trust a setup log on disk).
3. Log into that peer's `/admin/tokens`, issue a `read`-scoped token.
4. On the **hub**, go to `/peers` → "Add peer" → paste the URL + token.

Within 60s the hub's `/peers` page lights up with the peer's KPIs.

### What this gets you

- **Geographic redundancy:** CrowdSec runs on each instance, detecting
  attacks in its region. Cross-region visibility via the mesh.
- **Independent bouncers:** each region pushes to its own MikroTik /
  CF List. No cross-region decision propagation in 2.0 — that's deferred
  to a future phase. If you want decisions to propagate, configure each
  peer as a *CrowdSec federation source* (phase 7) on the hub.
- **Mesh privacy:** internal aggregation traffic stays on the WireGuard
  mesh (10.77.0.0/24). Public-facing dashboards are HTTPS+TLS over the
  public IPv4.

### TLS

Each region's nginx site is created but **TLS is not auto-issued** — you
need DNS pointing to each public IPv4 first. After DNS:

```bash
certbot --nginx -d protek-nbg1.example.com
```

### Caveat

This is a **reference template**. Adapt it to your cloud (AWS, GCP,
DigitalOcean — providers all have analogous resources) and to your DNS /
secrets management. Treat the `cloud-init.yaml` as docs in YAML form
rather than a turnkey script — it boots a Protek node but the post-install
operator steps remain manual (token issuance, peer registration, TLS).

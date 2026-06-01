# Multi-region Protek cluster — Hetzner reference. Adapt providers per cloud.
#
# Brings up N VPS instances in N regions, each running Protek + CrowdSec.
# A WireGuard mesh connects them privately; one is elected hub (the others
# add themselves as peers via /peers — done via cloud-init).
#
# Usage:
#   terraform init
#   export TF_VAR_hcloud_token=...
#   export TF_VAR_ssh_pubkey="$(cat ~/.ssh/id_ed25519.pub)"
#   terraform apply -var 'regions=["nbg1","ash","sin"]'
#
# Acceptance: 3 instances up + meshed + visible in the hub's /peers page
# within ~10 min of `terraform apply`.

terraform {
  required_version = ">= 1.5"
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.45"
    }
  }
}

variable "hcloud_token"   { type = string, sensitive = true }
variable "ssh_pubkey"     { type = string }
variable "regions"        { type = list(string), default = ["nbg1", "ash"] }
variable "server_type"    { type = string, default = "cpx21" }   # 3 vCPU, 4 GB
variable "image"          { type = string, default = "ubuntu-24.04" }
variable "domain"         { type = string, default = "" }        # optional: register $region.protek.example.com

provider "hcloud" {
  token = var.hcloud_token
}

resource "hcloud_ssh_key" "deploy" {
  name       = "protek-deploy"
  public_key = var.ssh_pubkey
}

resource "hcloud_network" "mesh" {
  name     = "protek-mesh"
  ip_range = "10.66.0.0/16"
}

resource "hcloud_network_subnet" "regional" {
  for_each     = toset(var.regions)
  network_id   = hcloud_network.mesh.id
  type         = "cloud"
  network_zone = lookup(local.network_zone_for_region, each.value, "eu-central")
  ip_range     = "10.66.${index(var.regions, each.value)}.0/24"
}

resource "hcloud_server" "protek" {
  for_each    = toset(var.regions)
  name        = "protek-${each.value}"
  server_type = var.server_type
  image       = var.image
  location    = each.value
  ssh_keys    = [hcloud_ssh_key.deploy.id]

  network {
    network_id = hcloud_network.mesh.id
    ip         = "10.66.${index(var.regions, each.value)}.10"
  }

  user_data = templatefile("${path.module}/cloud-init.yaml", {
    region       = each.value
    region_index = index(var.regions, each.value)
    is_hub       = each.value == var.regions[0]
    hub_url      = "https://protek-${var.regions[0]}${var.domain != "" ? "." + var.domain : ""}"
    mesh_peers   = [for r in var.regions : "10.66.${index(var.regions, r)}.10" if r != each.value]
  })

  depends_on = [hcloud_network_subnet.regional]
}

locals {
  network_zone_for_region = {
    "nbg1" = "eu-central"
    "fsn1" = "eu-central"
    "hel1" = "eu-central"
    "ash"  = "us-east"
    "hil"  = "us-west"
    "sin"  = "ap-southeast"
  }
}

output "instances" {
  value = {
    for r in var.regions : r => {
      ipv4    = hcloud_server.protek[r].ipv4_address
      ipv6    = hcloud_server.protek[r].ipv6_address
      mesh_ip = "10.66.${index(var.regions, r)}.10"
      role    = r == var.regions[0] ? "hub" : "peer"
    }
  }
}

output "hub_url" {
  value = "https://${hcloud_server.protek[var.regions[0]].ipv4_address}/  (set up DNS + TLS, see deploy/README.md)"
}

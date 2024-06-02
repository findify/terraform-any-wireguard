# Prepare wireguard server and clients configs
module "wg_configs" {
  source = "../wg-configs"

  server_public_ip   = google_compute_address.this.address
  server_private_key = var.server_private_key
  server_public_key  = var.server_public_key
  clients            = var.clients
  network_cidr       = var.network_cidr
  dns                = var.dns
  use_gsm            = var.use_gsm
  gsm_secret         = var.gsm_secret
}

# Create firewall rules allowing access to the instance
resource "google_compute_firewall" "this" {
  name        = "${var.name}-firewall-rule"
  project     = var.project_id
  network     = var.vpc_network
  description = "Wireguard instance inbound/outbound rules"

  allow {
    protocol = "udp"
    ports    = [var.server_port]
  }

  dynamic "allow" {
    for_each = length(var.ssh_keys) > 0 ? [1] : []

    content {
      ports    = [22]
      protocol = "tcp"
    }
  }

  source_ranges = var.ingress
  target_tags   = ["wireguard", var.name]
}

# create static/elastic IP and attach to wireguard server instance
resource "google_compute_address" "this" {
  name    = "${var.name}-static-ip-address"
  project = var.project_id
  region  = var.region
}

# Provision wireguard server instance
resource "google_compute_instance" "this" {
  name         = var.name
  project      = var.project_id
  machine_type = var.instance_type
  zone         = var.zone
  boot_disk {
    initialize_params {
      image = var.ubuntu_version
    }
  }

  network_interface {
    network = var.vpc_network
    subnetwork = var.vpc_subnetwork != "" ? var.vpc_subnetwork : null
    access_config {
      nat_ip = google_compute_address.this.address
    }
  }

  metadata_startup_script = module.wg_configs.startup_script

  tags = ["wireguard", var.name]

  metadata = {
    ssh-keys = join("\n", [for ssh in var.ssh_keys : "${ssh.username}:${ssh.public_key}"])
  }

  dynamic "service_account" {
    for_each = var.use_gsm ? [1] : []
    content {
      email  = google_service_account.this[0].email
      scopes = ["cloud-platform"]
    }
  }
}

resource "google_service_account" "this" {
  count        = var.use_gsm ? 1 : 0
  account_id   = "wireguard-sa"
  display_name = "WireGuard Service Account"
  project      = var.project_id
}

resource "google_project_iam_member" "this" {
  count   = var.use_gsm ? 1 : 0
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.this[0].email}"
}

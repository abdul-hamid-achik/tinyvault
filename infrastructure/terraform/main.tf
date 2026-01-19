terraform {
  required_version = ">= 1.0.0"

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.45"
    }
  }
}

provider "hcloud" {
  token = var.hcloud_token
}

# SSH Key - use existing key from Hetzner account
data "hcloud_ssh_key" "main" {
  fingerprint = "eb:98:ba:14:e3:db:49:6e:f6:92:29:1f:85:83:52:6c"
}

# Firewall
resource "hcloud_firewall" "main" {
  name = "tinyvault-${var.environment}"

  # SSH
  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "22"
    source_ips = [
      "0.0.0.0/0",
      "::/0"
    ]
  }

  # HTTP
  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "80"
    source_ips = [
      "0.0.0.0/0",
      "::/0"
    ]
  }

  # HTTPS
  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "443"
    source_ips = [
      "0.0.0.0/0",
      "::/0"
    ]
  }

  # Allow all outbound
  rule {
    direction = "out"
    protocol  = "tcp"
    port      = "any"
    destination_ips = [
      "0.0.0.0/0",
      "::/0"
    ]
  }

  rule {
    direction = "out"
    protocol  = "udp"
    port      = "any"
    destination_ips = [
      "0.0.0.0/0",
      "::/0"
    ]
  }

  rule {
    direction = "out"
    protocol  = "icmp"
    destination_ips = [
      "0.0.0.0/0",
      "::/0"
    ]
  }
}

# PostgreSQL Volume
resource "hcloud_volume" "postgres" {
  name      = "tinyvault-postgres-${var.environment}"
  size      = var.postgres_volume_size
  location  = var.location
  format    = "ext4"
  automount = false

  labels = {
    environment = var.environment
    service     = "postgres"
  }
}

# Data Volume
resource "hcloud_volume" "data" {
  name      = "tinyvault-data-${var.environment}"
  size      = var.data_volume_size
  location  = var.location
  format    = "ext4"
  automount = false

  labels = {
    environment = var.environment
    service     = "app"
  }
}

# Main Server
resource "hcloud_server" "main" {
  name        = "tinyvault-${var.environment}"
  image       = "ubuntu-24.04"
  server_type = var.server_type
  location    = var.location

  ssh_keys = [data.hcloud_ssh_key.main.id]

  firewall_ids = [hcloud_firewall.main.id]

  labels = {
    environment = var.environment
  }

  user_data = <<-EOF
    #cloud-config
    package_update: true
    package_upgrade: true

    packages:
      - docker.io
      - docker-compose
      - curl
      - jq
      - htop

    runcmd:
      - systemctl enable docker
      - systemctl start docker
      - usermod -aG docker ubuntu
      - mkdir -p /opt/tinyvault
      - mkdir -p /mnt/postgres
      - mkdir -p /mnt/data
  EOF

  lifecycle {
    ignore_changes = [user_data]
  }
}

# Attach PostgreSQL volume
resource "hcloud_volume_attachment" "postgres" {
  volume_id = hcloud_volume.postgres.id
  server_id = hcloud_server.main.id
  automount = true
}

# Attach data volume
resource "hcloud_volume_attachment" "data" {
  volume_id = hcloud_volume.data.id
  server_id = hcloud_server.main.id
  automount = true
}

# Outputs
output "server_ip" {
  description = "Public IP address of the server"
  value       = hcloud_server.main.ipv4_address
}

output "server_ipv6" {
  description = "IPv6 address of the server"
  value       = hcloud_server.main.ipv6_address
}

output "postgres_volume_id" {
  description = "ID of the PostgreSQL volume"
  value       = hcloud_volume.postgres.id
}

output "data_volume_id" {
  description = "ID of the data volume"
  value       = hcloud_volume.data.id
}

output "ssh_command" {
  description = "SSH command to connect to the server"
  value       = "ssh root@${hcloud_server.main.ipv4_address}"
}

output "postgres_volume_device" {
  description = "Device path for PostgreSQL volume (mount to /mnt/postgres)"
  value       = "/dev/disk/by-id/scsi-0HC_Volume_${hcloud_volume.postgres.id}"
}

output "data_volume_device" {
  description = "Device path for data volume (mount to /mnt/data)"
  value       = "/dev/disk/by-id/scsi-0HC_Volume_${hcloud_volume.data.id}"
}

output "dns_config" {
  description = "DNS configuration hint"
  value       = "Create A record: ${var.domain} -> ${hcloud_server.main.ipv4_address}"
}

output "server_status" {
  description = "Current server status"
  value       = hcloud_server.main.status
}

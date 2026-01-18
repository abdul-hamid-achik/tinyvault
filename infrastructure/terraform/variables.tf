variable "hcloud_token" {
  description = "Hetzner Cloud API token"
  type        = string
  sensitive   = true
}

variable "ssh_public_key" {
  description = "SSH public key for server access"
  type        = string
}

variable "environment" {
  description = "Environment name (e.g., production, staging)"
  type        = string
  default     = "production"
}

variable "location" {
  description = "Hetzner datacenter location"
  type        = string
  default     = "hil"  # Hillsboro, US West

  validation {
    condition     = contains(["nbg1", "fsn1", "hel1", "ash", "hil"], var.location)
    error_message = "Location must be one of: nbg1 (Nuremberg), fsn1 (Falkenstein), hel1 (Helsinki), ash (Ashburn), hil (Hillsboro)."
  }
}

variable "server_type" {
  description = "Hetzner server type"
  type        = string
  default     = "cx22"  # 2 vCPU, 4GB RAM, ~$4.50/mo

  validation {
    condition     = contains(["cx11", "cx21", "cx22", "cx31", "cx32", "cx41", "cx42", "cx51", "cx52"], var.server_type)
    error_message = "Server type must be a valid Hetzner CX type."
  }
}

variable "postgres_volume_size" {
  description = "Size of the PostgreSQL volume in GB"
  type        = number
  default     = 20

  validation {
    condition     = var.postgres_volume_size >= 10 && var.postgres_volume_size <= 10240
    error_message = "Volume size must be between 10 and 10240 GB."
  }
}

variable "data_volume_size" {
  description = "Size of the data volume in GB"
  type        = number
  default     = 10

  validation {
    condition     = var.data_volume_size >= 10 && var.data_volume_size <= 10240
    error_message = "Volume size must be between 10 and 10240 GB."
  }
}

variable "domain" {
  description = "Domain name for the application"
  type        = string
  default     = "tinyvault.dev"
}

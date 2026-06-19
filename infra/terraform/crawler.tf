# DWITP Crawler VM — Terraform Definition
# Disposable infrastructure: destroy-and-redeploy on compromise.
# No SSH, no persistent state, no dev tooling.

terraform {
  required_version = ">= 1.6"
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

variable "deploy_id" {
  description = "Unique deployment identifier for traceability"
  type        = string
}

variable "crawler_image_tag" {
  description = "Docker image tag for the crawler"
  type        = string
  default     = "latest"
}

provider "docker" {
  # Assumes Docker socket is available
}

# Internal network for crawler isolation
resource "docker_network" "crawler_tor" {
  name       = "dwitp-crawler-tor-${var.deploy_id}"
  internal   = true
  driver     = "bridge"
  ipam_config {
    subnet = "10.0.100.0/24"
  }
}

resource "docker_network" "crawler_queue" {
  name       = "dwitp-crawler-queue-${var.deploy_id}"
  internal   = true
  driver     = "bridge"
  ipam_config {
    subnet = "10.0.101.0/24"
  }
}

# Tor container - routes all crawler traffic
resource "docker_container" "tor" {
  name    = "dwitp-tor-${var.deploy_id}"
  image   = "dwitp/tor:latest"
  restart = "no"

  networks_advanced {
    name    = docker_network.crawler_tor.name
    aliases = ["tor"]
  }

  capabilities {
    add  = ["NET_BIND_SERVICE"]
    drop = ["ALL"]
  }

  security_opts = ["no-new-privileges:true"]
  read_only     = true
  tmpfs         = { "/tmp" = "size=64m,noexec,nosuid,nodev" }

  ports {
    internal = 9050
    external = 1270
    protocol = "tcp"
  }
}

# Crawler container - no persistent storage, no SSH, no exec
resource "docker_container" "crawler" {
  name    = "dwitp-crawler-${var.deploy_id}"
  image   = "dwitp/crawler:${var.crawler_image_tag}"
  restart = "no"

  networks_advanced {
    name    = docker_network.crawler_tor.name
    aliases = ["crawler"]
  }

  networks_advanced {
    name    = docker_network.crawler_queue.name
    aliases = ["crawler"]
  }

  capabilities {
    drop = ["ALL"]
  }

  security_opts = [
    "no-new-privileges:true",
    "seccomp:../config/seccomp/crawler.json",
  ]
  read_only = true
  tmpfs = {
    "/tmp" = "size=64m,noexec,nosuid,nodev"
  }

  env = [
    "TOR_PROXY_HOST=tor",
    "TOR_PROXY_PORT=9050",
    "TOR_CONTROL_PORT=9051",
    "RABBITMQ_HOST=rabbitmq",
    "RABBITMQ_PORT=5672",
    "CRAWLER_IDENTITY=crawler-${var.deploy_id}",
    "DWITP_AUDIT_LOG=/var/log/dwitp/audit.log",
  ]

  depends_on = [docker_container.tor]
}

output "crawler_container_id" {
  value = docker_container.crawler.id
}

output "deploy_id" {
  value = var.deploy_id
}

terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

provider "docker" {}

resource "docker_network" "app_network" {
  name = "app_network"
}

resource "local_file" "compose" {
  content = templatefile("${path.module}/docker-compose.yml.tpl", {
    POSTGRES_DB       = var.POSTGRES_DB
    POSTGRES_USER     = var.POSTGRES_USER
    POSTGRES_PASSWORD = var.POSTGRES_PASSWORD
    CONNECTION_STRING = var.CONNECTION_STRING
  })

  filename = "${path.module}/docker-compose.generated.yml"
}
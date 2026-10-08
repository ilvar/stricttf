locals {
  bucketName = "kitchen-sink-${var.region}"
  unused_tag = "never-read"
  name       = "${local.bucketName}"
}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "Logs" {
  bucket = "${local.name}-${random_id.suffix.hex}"

  tags = {
    created_at = timestamp()
    settings   = jsonencode(var.settings)
  }

  lifecycle {
    ignore_changes = all
  }
}

resource "null_resource" "bootstrap" {
  count = var.instanceCount

  triggers = {
    password_hash = sha256(var.db_password)
  }

  provisioner "local-exec" {
    command = "echo bootstrapping"
  }
}

data "external" "lookup" {
  program = ["python3", "${path.module}/lookup.py"]
}

resource "google_storage_bucket" "archive" {
  name     = "kitchen-sink-archive"
  location = "EU"
}

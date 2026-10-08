locals {
  common_tags = merge(var.tags, {
    environment = var.environment
    managed_by  = "terraform"
  })
}

resource "aws_s3_bucket" "logs" {
  bucket = var.bucket_name
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

module "log_alerts" {
  source  = "terraform-aws-modules/sns/aws"
  version = "6.1.2"

  name = "${var.bucket_name}-alerts"
}

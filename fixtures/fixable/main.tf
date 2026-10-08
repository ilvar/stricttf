provider "aws" {
  region = "eu-west-1"
}

resource "aws_s3_bucket" "artifacts" {
  bucket = "${var.bucket_name}"
}

output "bucket_arn" {
  description = "ARN of the artifacts bucket."
  value       = "${aws_s3_bucket.artifacts.arn}"
}

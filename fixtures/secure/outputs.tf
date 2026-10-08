output "bucket_arn" {
  description = "ARN of the log bucket."
  value       = aws_s3_bucket.logs.arn
}

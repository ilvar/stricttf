output "bucket_arn" {
  description = "ARN of the site bucket."
  value       = aws_s3_bucket.site.arn
}

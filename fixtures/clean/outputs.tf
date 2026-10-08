output "bucket_arn" {
  description = "ARN of the log bucket."
  value       = aws_s3_bucket.logs.arn
}

output "bucket_id" {
  description = "Name of the log bucket."
  value       = aws_s3_bucket.logs.id
}

output "alerts_topic_arn" {
  description = "ARN of the SNS topic that receives log alerts."
  value       = module.log_alerts.topic_arn
}

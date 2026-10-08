output "bucket_arn" {
  value = aws_s3_bucket.Logs.arn
}

output "first_setting_suffix" {
  description = "Suffix generated for the first setting."
  value       = random_id.per_setting.0.hex
}

output "setting_suffixes" {
  description = "Suffixes generated for every setting."
  value       = random_id.per_setting.*.hex
}

output "network_vpc_id" {
  description = "VPC identifier published by the network stack."
  value       = data.terraform_remote_state.network.outputs.vpc_id
}

output "db_password" {
  description = "Database password for downstream stacks."
  value       = var.db_password
}

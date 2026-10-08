output "name" {
  description = "Name of the object this module manages."
  value       = terraform_data.this.input.name
}

output "tags" {
  description = "Effective tags: the module defaults with the caller's tags merged over them."
  value       = terraform_data.this.input.tags
}

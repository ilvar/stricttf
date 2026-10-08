terraform {
  required_version = ">= 1.6.0, < 2.0.0"
}

variable "name" {
  type        = string
  description = "Name recorded by the example resource."
}

resource "terraform_data" "example" {
  input = {
    name  = var.name
    owner = local.nope
  }
}

output "name" {
  description = "The name the example resource recorded."
  value       = terraform_data.example.output
}

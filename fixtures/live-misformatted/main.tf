terraform {
  required_version = ">= 1.6.0"
}

variable "name" {
  type = string
  description = "Name recorded by the example resource."
}

resource "terraform_data" "example" {
    input = var.name
}

output "name" {
  description = "The name the example resource recorded."
  value = terraform_data.example.output
}

terraform {
  required_version = ">= 1.6.0"
}

variable "name" {
  type        = string
  description = "Name of the example."
}

resource "terraform_data" "example" {
  input = { label = "café", ref = local.nope }
}

resource "terraform_data" "after" {
  depends_on = ["terraform_data.example"]
  input      = var.name
}

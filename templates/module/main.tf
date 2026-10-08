locals {
  default_tags = {
    module = "__MODULE__"
  }

  tags = merge(local.default_tags, var.tags)
}

# terraform_data is Terraform's builtin resource: it stores a value in
# state and needs no provider. Replace it with the real resources this
# module manages, keeping every input flowing through a typed variable.
resource "terraform_data" "this" {
  input = {
    name = var.name
    tags = local.tags
  }
}

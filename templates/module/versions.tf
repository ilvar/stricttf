# No required_providers block: the module is built on the builtin
# terraform_data resource, so it needs no provider download and no lock
# file, and `terraform init` works offline. Add providers here, each with
# an explicit source and a bounded version constraint, when the module
# grows real infrastructure.
terraform {
  required_version = ">= 1.6.0, < 2.0.0"
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
}

module "dns" {
  source  = "terraform-aws-modules/route53/aws"
  version = "~> 3.0"
}

module "network_policy" {
  source = "git::https://example.com/network-policy.git?ref=main"
}

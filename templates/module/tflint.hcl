# The terraform ruleset is pinned so `tflint --init` installs the same
# rules everywhere; bump the version deliberately, never implicitly.
plugin "terraform" {
  enabled = true
  preset  = "recommended"
  version = "0.15.0"
  source  = "github.com/terraform-linters/tflint-ruleset-terraform"
}

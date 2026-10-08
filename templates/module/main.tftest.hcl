# `terraform test` suite. Every run uses `command = plan`, so the suite
# creates nothing and needs no credentials.

variables {
  name = "example"
}

run "default_tags_are_applied" {
  command = plan

  assert {
    condition     = output.name == "example"
    error_message = "The name output must echo the name variable."
  }

  assert {
    condition     = output.tags == { module = "__MODULE__" }
    error_message = "With no caller tags, only the module's default tags are applied."
  }
}

run "caller_tags_are_merged_over_defaults" {
  command = plan

  variables {
    tags = {
      module = "override"
      team   = "platform"
    }
  }

  assert {
    condition     = output.tags["team"] == "platform"
    error_message = "Caller tags must be present in the effective tags."
  }

  assert {
    condition     = output.tags["module"] == "override"
    error_message = "A caller tag must override the default tag with the same key."
  }
}

run "invalid_name_is_rejected" {
  command = plan

  variables {
    name = "Invalid_Name"
  }

  expect_failures = [
    var.name,
  ]
}

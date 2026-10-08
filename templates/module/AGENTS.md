# AGENTS.md

Rules for coding agents working on the `__MODULE__` Terraform module.

## The loop

1. Run `stricttf --help` and treat its embedded manual as the source of
   truth for every rule and diagnostic code.
2. Make the smallest coherent change.
3. Run `stricttf check .` and parse the single JSON document on stdout.
4. Fix every diagnostic whose `level` is `error`. Apply a diagnostic's
   `fixes` only when they say exactly what you intended.
5. Re-check. Repeat until `ok` is `true`.
6. Run `scripts/check.sh` before proposing the change.

Do not read past the JSON document for status. `ok`, `error_count`, and the
exit code are the contract; anything printed on stderr is for a human.

Never suppress a check to get a green run: no deleting tests, no skipping
stages, no loosening a validation or a version constraint to silence a
diagnostic. Fix the configuration instead.

## Module rules

- `versions.tf` keeps a bounded `required_version`. Every provider added
  to `required_providers` gets an explicit `source` and a bounded
  `version`, and the lock file is committed with it.
- Every variable has a `type` and a `description`; never use `any`. Add a
  `validation` block wherever the accepted values are narrower than the
  type.
- Every output has a `description`.
- Every variable and every local is used. Delete what you stop using.
- Names are `snake_case`.
- No `timestamp()`, `uuid()`, or other function whose result changes
  between runs: a plan must depend only on the configuration and its
  inputs.
- No provisioners and no `external` data sources.
- Write `var.name`, not `"${var.name}"`.
- No literal secrets anywhere. Credentials arrive through variables
  marked `sensitive = true`.

## Tests

`tests/*.tftest.hcl` are `terraform test` suites using `command = plan`.
Every behaviour change needs a run that asserts on it, and every
`validation` block needs an `expect_failures` run proving it rejects bad
input. Assert on the property that matters rather than restating the
configuration.

## Before you push

- `scripts/check.sh` ends with `all checks passed`.
- No `.terraform/`, state file, plan file, or scratch file is staged.

---
name: stricttf
description: Use stricttf to create, check, and conservatively fix Terraform modules with deterministic JSON diagnostics, strict-subset rules, resource-policy checks, and terraform fmt/validate normalisation.
---

# stricttf

Use this skill whenever you create or modify a Terraform module in a
project that uses `stricttf`.

## Required workflow

1. Run `stricttf --help` and treat its embedded manual as the current
   source of truth.
2. Inspect the module and make the smallest coherent change that advances
   the task.
3. Run `stricttf check <path>` and parse the single JSON document on
   stdout.
4. Address every diagnostic whose `level` is `error`. Match on `code`,
   never on message text.
5. Use `stricttf fix <path>` only for diagnostics that carry a `fixes`
   entry. Never invent a fix.
6. Repeat from step 3 until `ok` is `true`.
7. Run the module's own gate — `make check` or `scripts/check.sh`, which
   include `terraform test`.
8. Read the plan, not only the configuration diff, and do not submit known
   failures.

Exit code `0` means no errors, `1` means errors remain, and `2` means the
check did not complete. Never read `2` as a clean module.

A path names one module directory. Nested modules are not descended into;
check each one separately.

## Strict-subset expectations

Every module declares `terraform { required_version }`, and every provider
it uses appears in `required_providers` with a `source` and a `version`
that has an upper bound:

```hcl
terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
```

Commit the `.terraform.lock.hcl` that `terraform init` writes.

Every variable has a `type` (never `any`) and a `description`; a variable
whose name ends in `password`, `token`, `client_secret`, `api_key`, and
similar is marked `sensitive = true` unless its type is `bool` or
`number`. Every output has a `description`. Every
declared variable and local is read. Names are `snake_case`.

Registry module calls pin one exact `version`; git module sources carry a
`?ref=` naming a tag or commit, never a branch. Expressions are written
bare (`var.name`, not `"${var.name}"`), types unquoted (`string`, not
`"string"`). `timestamp()`, `uuid()`, `bcrypt()`, `plantimestamp()`,
provisioners, and `data "external"` are rejected, and
`lifecycle { ignore_changes = all }` is a warning.

Literal credentials anywhere in configuration or `.tfvars`, world-open
ingress to SSH, RDP, or every port, public S3 ACLs, publicly accessible
databases, and IAM `Allow` statements granting `"*"` are rejected.

## Generated modules

Use `stricttf new <name>` for a provider-free module that already passes
`stricttf check`, with `terraform test` files, pre-commit hooks, a
Makefile, `scripts/check.sh`, and a CI workflow running the same gate.

## Without a terraform binary

`stricttf check --source-only <path>` runs the module-structure,
configuration-source, and resource-policy layers alone. Use it only when
Terraform is genuinely unavailable, and say so — it is a smaller check,
not an equivalent one.

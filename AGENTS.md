# AGENTS.md

Repository-specific rules for coding agents working on `stricttf`.

## Project intent

`stricttf` is not a new configuration language. It is:

1. a strict subset of Terraform;
2. a tooling layer around Terraform's existing capabilities;
3. a deterministic feedback contract for an agent-driven
   check → patch → re-check loop.

Do not introduce a Terraform evaluator, a type checker, a policy language,
a plan or state reader, or any check that needs cloud credentials.

## Layer discipline

The check pipeline has five layers and they are ordered by cost:

1. module structure;
2. configuration source;
3. resource policy;
4. terraform (`fmt`, `init -backend=false`, `validate -json`);
5. security scan (`trivy config`).

Rules belong to the earliest layer that can decide them. A rule that can be
decided from source must not wait for Terraform; a rule that needs
Terraform's evaluation must not be guessed at from source. Every layer
reports everything it finds — never stop at the first defect. Layers 4 and
5 are skipped only when layer 1 proves a `.tf` file is not HCL.

Rules decide only from literals. When a value is computed by an expression,
the rule cannot know it and must stay silent.

## Trivy discipline

Trivy is the authority for broad cloud-misconfiguration policy. Do not
re-implement a check trivy's embedded set already has; a resource-policy
rule belongs here only when trivy lacks it, or when the defect is severe
enough to catch with no trivy installed. Before adding an AWS rule, run the
pinned trivy over a reproducing module and record whether it fires.

The scan must stay deterministic and unweakenable: embedded checks only
(`--skip-check-update`), the module's `.trivyignore` ignored, findings
outside the module's own files dropped. Trivy's absence is the warning
`trivy::unavailable`, never a silent skip. Bumping the pinned trivy changes
the reported set; update CI, the generated workflow, help, README, and the
goldens in one change.

The terraform layer must leave the module exactly as it found it:
`TF_DATA_DIR` points into a per-module cache outside the module, an existing
lock file is used with `-lockfile=readonly`, and a lock file `init` created
is removed afterwards. `tests/terraform_live.rs` pins this.

## Diagnostic contract

The JSON shape is the public API between the tool and coding agents. Treat
incompatible changes as breaking changes.

Required properties:

- output exactly one JSON document on stdout;
- `source` is `stricttf`, `terraform`, or `trivy`;
- `code` is stable; message text is not, and rules must be matched by code;
- every diagnostic carries a located `at` span with 1-based positions,
  character columns, and an exclusive `end_col`;
- include `fixes` entries only when a replacement is span-exact,
  unambiguous, and idempotent;
- never invent a replacement or an applicability;
- order deterministically by `(file, line, col, code, message)`;
- exit `0` only when `error_count == 0`.

Internal metadata such as byte offsets may be retained with `#[serde(skip)]`,
but must not alter the public shape.

## Capability discipline

Every filesystem and process effect lives in `src/capability.rs`, behind the
marked `effects` module. Nothing else in the crate may call `std::fs`,
`std::net`, or `std::process`; `main.rs` confines the process
exit status the same way. This is what makes the rule set testable without
a disk or a Terraform binary — do not weaken it for convenience.

`stricttf` is written in the `strictrs` strict subset and CI enforces it:
no `unsafe`, no panic APIs outside tests, no numeric `as` casts, no glob
imports, no mutable globals, explicit return types on public functions.

## Rule rules

A new rule needs, in the same change:

- a stable `stricttf::` code, listed in `src/help.txt`;
- a positive test proving it fires;
- a negative test proving the nearest legitimate construct does not;
- a fixture entry when it belongs to the kitchen-sink or insecure module;
- an entry in `README.md` and, when it changes what agents must write,
  in `skills/stricttf/SKILL.md`.

`tests/help.rs` enforces the manual in both directions: every code the crate
emits must be documented, and every code the manual lists must be emittable.

Prefer a rule that is precise over one that is broad. A false positive costs
an agent a wasted edit and teaches it to distrust the report; a false
negative costs one missed defect. When a construct cannot be decided from
the available evidence, do not report it.

## Fix rules

Fixes are deliberately conservative:

- attach a fix only when the correct replacement is unambiguous —
  unquoting `"string"` qualifies, choosing what `"list"` meant does not;
- retain and use byte offsets rather than reconstructing edits from columns;
- never edit a path outside the requested module root;
- validate byte ranges and UTF-8 boundaries before modifying content;
- group edits by file and apply them back to front;
- deduplicate identical edits and keep the first of overlapping alternatives;
- re-run the full check after every pass;
- stop when clean, when no applicable edit remains, when a pass makes no
  progress, or at the iteration cap;
- keep the final stdout value the ordinary report, not a fix-result schema.

## Generated-module rules

`stricttf new` output must:

- pass `stricttf check` with zero errors **and zero warnings**;
- pass `terraform fmt -check`, `init -backend=false`, `validate`, and
  `terraform test` with the pinned Terraform, offline;
- read every variable and local it declares;
- be written through a staging directory and renamed only after every file
  succeeds;
- refuse invalid module names and existing destinations;
- name every skipped stage in `scripts/check.sh` rather than passing quietly.

The generated CI installs `stricttf` with `--tag v<crate version>`, the
release that generated it. A version bump in `Cargo.toml` therefore ships
with a matching `v<version>` git tag in the same release, or every module
generated from it has a CI that cannot install its gate.

When adding a generated file, add it to `FILES` in `src/template.rs`; the
generator tests compare the produced tree against that list in both
directions.

## Test rules

Every behaviour change needs a fixture or a focused test.

- Parsers over external text (Terraform's output) are golden-tested against
  captured fixtures, so the contract is exercised without Terraform.
- When a golden file changes, explain why the contract changed. Do not
  refresh a snapshot to make a test pass.
- Keep `tests/terraform_live.rs` the suite that needs a Terraform binary, and
  keep its skip loud: CI sets `STRICTTF_REQUIRE_TERRAFORM=1` so a skip
  becomes a failure.
- Preserve the kitchen-sink fixture proving many simultaneous defects across
  several files are all reported, not just the first.
- Preserve the clean and secure fixtures proving the rules do not fire on a
  correct module.
- Property tests cover what cases cannot: the rules must never panic on
  arbitrary input and a check must be a pure function of its input.

## Validation and commit discipline

Run the full set with Rust 1.97.1 before committing or pushing:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
STRICTTF_REQUIRE_TERRAFORM=1 cargo test --all-targets --all-features --locked
strictrs check .
```

With Terraform 1.16.5 on `PATH`, also generate a module and run its own
`scripts/check.sh`. If your system Terraform differs, download the pinned
release from `releases.hashicorp.com` into a scratch directory and put it
first on `PATH` rather than pushing a Terraform-dependent change unverified.

- Assemble a complete logical change before committing.
- Inspect the full diff and the staged file list before the commit.
- Do not commit or push known formatting, compilation, lint, or test failures.
- Batch related corrections and push them together after validating.
- Remove temporary modules, logs, and scratch files before the final push.
- Use CI to verify a validated change, not as a substitute for validation
  available locally.

## Scope discipline

Keep diagnostic-contract, rule, fix, generated-module, help, and
installation changes separable enough to review directly. Avoid unrelated
refactors.

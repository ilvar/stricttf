# Every target here is also a step in CI and in scripts/check.sh. If it
# passes locally it passes there, and nothing in CI runs a command this
# file does not.

.PHONY: all check strict fmt init validate test tflint clean

## Full gate. Run this before every commit.
all: check

check: strict fmt init validate test tflint

## stricttf is the fast oracle: one deterministic JSON report covering
## the strict subset plus terraform fmt, init, and validate.
strict:
	stricttf check .

fmt:
	terraform fmt -check -recursive

init:
	terraform init -backend=false -input=false

validate: init
	terraform validate

## Plan-only `terraform test` runs from tests/*.tftest.hcl.
test: init
	terraform test

## Optional deeper lint; skipped loudly when the binary is absent.
tflint:
	@if command -v tflint >/dev/null 2>&1; then \
		tflint --init && tflint --format compact; \
	else \
		echo "tflint SKIPPED (not installed)"; \
	fi

clean:
	rm -rf .terraform

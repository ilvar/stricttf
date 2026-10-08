#!/usr/bin/env bash
# The whole gate, in the order that surfaces the cheapest error first.
#
# Each optional stage is skipped with a loud notice rather than silently
# when its tool is missing, so a green run never means "nothing was
# checked".
set -euo pipefail

module_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$module_dir"

export TF_IN_AUTOMATION=1

have() { command -v "$1" >/dev/null 2>&1; }

require() {
  if ! have "$1"; then
    echo "error: $1 is required but not installed" >&2
    exit 2
  fi
}

require terraform
require stricttf

if have trivy; then
  echo "==> stricttf check (with the trivy security scan)"
else
  echo "==> stricttf check (trivy security scan SKIPPED: trivy not installed)"
fi
stricttf check .

echo "==> terraform fmt -check"
terraform fmt -check -recursive

echo "==> terraform init"
terraform init -backend=false -input=false

echo "==> terraform validate"
terraform validate

echo "==> terraform test"
terraform test

if have tflint; then
  echo "==> tflint"
  tflint --init
  tflint --format compact
else
  echo "==> tflint SKIPPED (not installed)"
fi

echo "==> all checks passed"

#!/bin/bash
# Taken from https://github.com/cloudposse/build-harness/blob/master/bin/terraform-docs.sh

which awk 2>&1 >/dev/null || (
  echo "awk not available"
  exit 1
)
which terraform 2>&1 >/dev/null || (
  echo "terraform not available"
  exit 1
)
which terraform-docs 2>&1 >/dev/null || (
  echo "terraform-docs not available"
  exit 1
)

if [[ "$(terraform version | head -1)" =~ 0\.12 ]]; then
  TMP_FILE="$(mktemp /tmp/terraform-docs-XXXXXXXXXX)"
  awk -f $(git rev-parse --show-toplevel)/scripts/terraform-doc.awk $2 ./*.tf >${TMP_FILE}
  terraform-docs $1 ${TMP_FILE}
  rm -f ${TMP_FILE}
else
  echo "Using terraform-docs since your terraform version is < 0\.12"
  terraform-docs $1 $2
fi

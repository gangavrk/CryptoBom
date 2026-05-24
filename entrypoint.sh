#!/bin/sh
# Entrypoint for the cryptobom GitHub Action. Args are supplied by action.yml:
#   $1 = path to scan, $2 = SARIF output file, $3 = CBOM output file.
set -e

SCAN_PATH="${1:-.}"
SARIF_FILE="${2:-cryptobom.sarif}"
CBOM_FILE="${3:-cryptobom.cbom.json}"

cryptobom scan --no-color \
  --sarif "$SARIF_FILE" \
  --cbom "$CBOM_FILE" \
  "$SCAN_PATH"

if [ -n "$GITHUB_OUTPUT" ]; then
  {
    echo "sarif-file=$SARIF_FILE"
    echo "cbom-file=$CBOM_FILE"
  } >> "$GITHUB_OUTPUT"
fi

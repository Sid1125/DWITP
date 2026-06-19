#!/bin/bash
# Hash-pin dependencies: generates requirements.txt with --hash entries
# Run this before production deployment. Requires pip-tools.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v pip-compile &>/dev/null; then
    echo "pip-tools is required. Install with: pip install pip-tools"
    exit 1
fi

echo "=== Hash-pinning dependencies ==="
pip-compile \
    --generate-hashes \
    --allow-unsafe \
    --output-file=requirements.txt \
    requirements.in

echo "=== Verification ==="
pip install --require-hashes --no-deps -r requirements.txt --dry-run 2>&1 | head -5
echo "Hash-pinned requirements.txt generated successfully."
echo ""
echo "Next step: rebuild Docker images with the new requirements.txt"

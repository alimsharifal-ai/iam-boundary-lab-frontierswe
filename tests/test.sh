#!/usr/bin/env bash
set -euo pipefail
mkdir -p /logs/verifier
cd /app
PYTHONPATH=/app python3 /tests/verify.py | tee /logs/verifier/details.txt

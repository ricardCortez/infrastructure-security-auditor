#!/bin/bash
cd "$(dirname "$0")/.."
echo "Running integration tests (requires API at localhost:8000)..."
pytest tests/integration/ -v -m integration --tb=short "$@"

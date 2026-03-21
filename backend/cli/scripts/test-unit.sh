#!/bin/bash
cd "$(dirname "$0")/.."
echo "Running unit tests..."
pytest tests/test_*.py -v --tb=short "$@"

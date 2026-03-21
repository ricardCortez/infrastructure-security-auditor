#!/bin/bash
cd "$(dirname "$0")/.."
echo "Running network tests..."
pytest tests/network/ -v -m network --tb=short "$@"

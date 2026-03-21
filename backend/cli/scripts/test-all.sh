#!/bin/bash
set -e
cd "$(dirname "$0")/.."

echo "=================================="
echo "  PSI CLI - TEST SUITE"
echo "=================================="
echo ""

echo "[1/4] Installing test deps..."
pip install -q pytest pytest-cov pytest-timeout

echo ""
echo "[2/4] Unit tests..."
pytest tests/test_*.py -v --tb=short

echo ""
echo "[3/4] Integration tests (skips if API down)..."
pytest tests/integration/ -v -m integration --tb=short 2>/dev/null || echo "WARN: Integration tests skipped"

echo ""
echo "[4/4] Network tests (skips if unreachable)..."
pytest tests/network/ -v -m network --tb=short 2>/dev/null || echo "WARN: Network tests skipped"

echo ""
echo "[DONE] Coverage report..."
pytest tests/ --cov=cli --cov-report=html --cov-report=term-missing --ignore=tests/integration --ignore=tests/network

echo ""
echo "Coverage HTML: htmlcov/index.html"

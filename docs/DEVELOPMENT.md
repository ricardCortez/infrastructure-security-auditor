# Development Guide

## Prerequisites
- Python 3.11+
- Docker & Docker Compose
- Git

## Setup

```bash
git clone <repo>
cd security-platform
cp .env.example .env
docker-compose up -d postgres redis elasticsearch
cd backend/core-api
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Running Tests

```bash
cd backend/core-api
pytest tests/ -v --cov=app
```

## Code Standards
- PEP 8 compliance (flake8)
- Black formatting
- Type hints required
- Docstrings on all public functions

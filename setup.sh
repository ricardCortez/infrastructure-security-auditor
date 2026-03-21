#!/bin/bash
set -e

echo "╔════════════════════════════════════════════╗"
echo "║  PSI Security Platform – Setup Script      ║"
echo "╚════════════════════════════════════════════╝"
echo ""

echo "1️⃣  Checking Python 3.11+..."
python3 --version

echo "2️⃣  Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate 2>/dev/null || . venv/Scripts/activate

echo "3️⃣  Installing dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo "4️⃣  Setting up environment file..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "     .env created – add your CLAUDE_API_KEY and DB credentials."
fi

echo "5️⃣  Starting Docker services..."
docker-compose -f docker/docker-compose.yml up -d

echo "6️⃣  Waiting for services to become healthy..."
sleep 10

echo ""
echo "✅ Setup complete!"
echo ""
echo "  Auditor (standalone)  →  python auditor.py --help"
echo "  Auditor TUI           →  python auditor.py interactive"
echo "  PSI CLI               →  python psi.py menu"
echo "  API docs              →  http://localhost:8000/docs"
echo "  Grafana               →  http://localhost:3000"
echo ""

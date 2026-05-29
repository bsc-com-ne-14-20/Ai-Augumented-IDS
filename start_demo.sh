#!/bin/bash
# AA-IDS Demo Startup Script
# Starts all components in the correct order

MAIN=~/Documents/FYP/Ai-Augumented-IDS
GREEN='\033[92m'
RESET='\033[0m'

echo "Starting AA-IDS Demo..."

# Activate venv
source $MAIN/venv/bin/activate

# Environment
export IDS_API_KEY="ids-demo-key-2024"
export IDS_BACKEND_URL="http://localhost:5000/api/v1/analyse"

# Kill anything on our ports
fuser -k 5000/tcp 2>/dev/null
fuser -k 8080/tcp 2>/dev/null
sleep 1

# 1. Start Flask IDS backend
echo -e "${GREEN}[1/3] Starting Flask IDS backend on :5000...${RESET}"
cd $MAIN
python app.py &
sleep 5

# 2. Create DB tables
python3 -c "
import sys; sys.path.insert(0,'.')
from backend.database import Base, engine
Base.metadata.create_all(engine)
" 2>/dev/null

# 3. Start Django dummy site
echo -e "${GREEN}[2/3] Starting Django dummy site on :8080...${RESET}"
cd $MAIN/dummy_site/django-blog-main
python manage.py runserver 8080 &
sleep 3

echo -e "${GREEN}[3/3] All services running!${RESET}"
echo ""
echo "  Dummy site  →  http://localhost:8080"
echo "  IDS API     →  http://localhost:5000/api/v1/health"
echo "  IDS stats   →  http://localhost:5000/api/v1/stats"
echo "  API key     →  ids-demo-key-2024"
echo ""
echo "Flutter dashboard: cd $MAIN/Dashboard/aa_ids_dashboard && flutter run -d chrome"

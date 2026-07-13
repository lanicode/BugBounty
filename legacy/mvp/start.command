#!/bin/bash
set -e
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
pip install -r requirements.txt
npm install
npx playwright install chromium
printf '\nInstallation abgeschlossen.\n'
printf '1. config/scope.yaml bearbeiten\n'
printf '2. npm run record:a\n'
printf '3. npm run record:b\n'
printf '4. python tools/run_review.py\n'

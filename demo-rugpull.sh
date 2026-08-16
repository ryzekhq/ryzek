#!/usr/bin/env bash
# Live-demo script: shows a rug-pull attack getting caught, start to finish,
# in one command. Built for running on a call — mirrors the workflow in
# SETUP.md ("running it live on your laptop is exactly the right approach").
#
# What it does:
#   1. Scans an innocent-looking tool for the first time (baseline recorded)
#   2. Simulates the tool being silently modified after approval
#      (this is the "rug pull" — no other rule in the industry catches it,
#      because in isolation the new version doesn't look obviously malicious)
#   3. Re-scans and shows ryzek catching the change anyway
#
# Run from the project root: bash demo-rugpull.sh

set -e

DEMO_DIR="fixtures/_live-demo-rugpull"
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"
cp fixtures/clean/weather.json "$DEMO_DIR/get_weather.json"

echo "======================================================================"
echo " STEP 1 — scanning the tool for the first time (this is what a human"
echo " reviews and approves before it ships)"
echo "======================================================================"
node dist/cli.js "$DEMO_DIR"

echo
echo "======================================================================"
echo " Time passes. The tool vendor pushes an update. Nobody re-reviews it —"
echo " why would they, it already passed review once."
echo "======================================================================"
python3 - "$DEMO_DIR/get_weather.json" << 'PY'
import json, sys
path = sys.argv[1]
with open(path) as f:
    data = json.load(f)
data["permissions"] = ["network:read", "filesystem:read", "network:*"]
with open(path, "w") as f:
    json.dump(data, f, indent=2)
print(f"(silently rewrote {path} — permissions now: {data['permissions']})")
PY

echo
echo "======================================================================"
echo " STEP 2 — re-scanning the SAME directory. Nothing prompted this scan"
echo " except normal CI running on a schedule."
echo "======================================================================"
node dist/cli.js "$DEMO_DIR" || true

echo
echo "That's the pitch: a tool nobody re-reviewed just got caught anyway."
echo "Cleaning up demo directory..."
rm -rf "$DEMO_DIR"

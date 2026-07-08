#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-http://localhost:8443}"

echo "== Local Docker access =="
id
if [ -S /var/run/docker.sock ]; then
  ls -l /var/run/docker.sock
else
  echo "docker socket not found at /var/run/docker.sock"
fi
if docker version >/dev/null 2>&1; then
  echo "docker: reachable"
else
  echo "docker: not reachable from this user"
fi

echo
echo "== API health =="
curl -fsS "${API_URL}/api/health" | python -m json.tool

echo
echo "== Runtime diagnostics =="
curl -fsS "${API_URL}/api/system/diagnostics" | python -m json.tool

echo
echo "== Recent scans =="
curl -fsS "${API_URL}/api/scans" | python -m json.tool | head -120

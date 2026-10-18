#!/usr/bin/env bash
set -e

echo "=== Bootstrapping Docker Containers ==="
docker compose -f infra/compose/docker-compose.yml up -d --build

echo "=== Waiting for services to be ready ==="
sleep 5

echo "=== Running Bridge Test Suite ==="
python -m pytest tests/ -v -o "pythonpath=. bridge"

#!/usr/bin/env bash
set -e

echo "=== ShuaBao Subscription Lab: Bootstrap & Test Harness ==="
python -m pip install -q pytest pytest-asyncio pydantic cryptography fastapi uvicorn httpx

echo "=== Running 14 Contract, Lifecycle, Fault, and Idempotency Tests ==="
python -m pytest tests/ -v -o "pythonpath=. bridge"

echo "=== Test Harness Completed Successfully ==="

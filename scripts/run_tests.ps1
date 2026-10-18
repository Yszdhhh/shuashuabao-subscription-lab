# ShuaBao Subscription Lab: Bootstrap & Test Harness for PowerShell
$ErrorActionPreference = "Stop"

Write-Host "=== ShuaBao Subscription Lab: Bootstrap & Test Harness ===" -ForegroundColor Cyan
python -m pip install -q pytest pytest-asyncio pydantic cryptography fastapi uvicorn httpx

Write-Host "=== Running 14 Contract, Lifecycle, Fault, and Idempotency Tests ===" -ForegroundColor Cyan
python -m pytest tests/ -v -o "pythonpath=. bridge"

Write-Host "=== Test Harness Completed Successfully ===" -ForegroundColor Green

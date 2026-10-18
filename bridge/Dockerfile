FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn pydantic cryptography pytest pytest-asyncio httpx

COPY contracts/ /app/contracts/
COPY bridge/ /app/bridge/
COPY tests/ /app/tests/
COPY pytest.ini /app/pytest.ini

ENV PYTHONPATH=".:bridge"

EXPOSE 8000

CMD ["uvicorn", "bridge.app.main:app", "--host", "0.0.0.0", "--port", "8000"]

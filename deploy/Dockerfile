# AEGIS gateway container. Multi-stage: install deps, then run uvicorn.
FROM python:3.12-slim AS base

WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY aegis/ ./aegis/
COPY policy/ ./policy/

EXPOSE 8080
# Readiness/liveness probes: GET /readyz and /healthz.
CMD ["uvicorn", "aegis.gateway.main:app", "--host", "0.0.0.0", "--port", "8080"]

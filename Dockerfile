# KeyCrawl - Railway-ready Docker image
# Web UI + API by default (FastAPI + uvicorn)
# You can also exec the CLI inside the container: python -m keycrawl scan https://...

FROM python:3.11-slim

WORKDIR /app

# System deps (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Default: run the web service.
# Railway will set $PORT. Procfile or CMD can be overridden in dashboard.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]

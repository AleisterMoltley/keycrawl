# KeyCrawl - Railway-ready Docker image
# Web UI + API by default (FastAPI + uvicorn)
# You can also exec the CLI inside the container: python -m keycrawl scan https://...

FROM python:3.11-slim

WORKDIR /app

# System deps for lxml + build (needed for scanner)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Use $PORT for Railway
CMD uvicorn app:app --host 0.0.0.0 --port $PORT

FROM python:3.11-slim

WORKDIR /app

# Install system deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY server/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

# Copy environment code
COPY models.py /app/models.py
COPY client.py /app/client.py
COPY server/ /app/server/
COPY openenv.yaml /app/openenv.yaml

# Python path is /app (WORKDIR), so "from models import ..." works
ENV DEPVULN_TASK=single_cve

# HF Spaces uses port 7860
ENV PORT=7860

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

EXPOSE ${PORT}

CMD uvicorn server.app:app --host 0.0.0.0 --port ${PORT}

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates tini curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# /data guarda o sqlite. Em K8s monte um PVC aqui; em compose, um volume.
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -fsS http://127.0.0.1:8090/healthz || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8090"]

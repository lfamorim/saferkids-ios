FROM python:3.12-slim

# wireguard-tools fornece o binário `wg`, usado para ler `latest_handshake`
# direto da interface wg0 do host (compartilhada via hostNetwork no K8s e
# network_mode: host no docker-compose).
RUN apt-get update && apt-get install -y --no-install-recommends \
        wireguard-tools \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY monitor.py .

ENTRYPOINT ["/usr/bin/tini", "--", "python", "-u", "monitor.py"]

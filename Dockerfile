# NyxStrike agent API (Flask on :8888). Python deps + optional common CLI tools.
# Full `nyxstrike.sh -t` (100+ apt packages) is not run at build — use INSTALL_TOOLS=1 for a subset.

FROM python:3.12-slim-bookworm

ARG INSTALL_TOOLS=0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NYXSTRIKE_HOST=0.0.0.0 \
    NYXSTRIKE_PORT=8888 \
    REDIS_URL=redis://host.docker.internal:6379/0

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    && if [ "$INSTALL_TOOLS" = "1" ]; then apt-get install -y --no-install-recommends \
      nmap \
      nikto \
      sqlmap \
      gobuster \
      ffuf \
      hydra \
      john \
      hashcat \
      tcpdump \
      dnsutils \
      whois \
      ; fi \
    && rm -rf /var/lib/apt/lists/*

COPY dependencies/requirements.txt dependencies/pip_constraints.txt ./
COPY requirements.txt ./requirements-root.txt

RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir -r requirements-root.txt

COPY . .

# Persist config / run data on a volume (mount at /app/.nyxstrike_data)
RUN mkdir -p .nyxstrike_data/config

EXPOSE 8888

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -sf "http://127.0.0.1:${NYXSTRIKE_PORT}/health" || exit 1

CMD ["python3", "nyxstrike_server.py"]

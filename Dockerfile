# NyxStrike agent API (Flask on :8888). INSTALL_TOOLS=1 runs scripts/docker_install_tools.sh
# (apt + git/go fallbacks for tools missing from Debian bookworm, e.g. nikto).

FROM python:3.13-slim-bookworm

ARG INSTALL_TOOLS=0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NYXSTRIKE_HOST=0.0.0.0 \
    NYXSTRIKE_PORT=8888 \
    REDIS_URL=redis://host.docker.internal:6379/0

WORKDIR /app

COPY scripts/docker_install_tools.sh scripts/docker_install_tools.sh

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    && if [ "$INSTALL_TOOLS" = "1" ]; then \
      chmod +x scripts/docker_install_tools.sh \
      && scripts/docker_install_tools.sh; \
    fi \
    && rm -rf /var/lib/apt/lists/* /root/go/pkg /tmp/*

COPY dependencies/requirements.txt dependencies/pip_constraints.txt ./
COPY requirements.txt ./requirements-root.txt

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt -c pip_constraints.txt \
    && pip install --no-cache-dir -r requirements-root.txt -c pip_constraints.txt

COPY . .

# Persist config / run data on a volume (mount at /app/.nyxstrike_data)
RUN mkdir -p .nyxstrike_data/config

EXPOSE 8888

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -sf "http://127.0.0.1:${NYXSTRIKE_PORT}/health" || exit 1

CMD ["python3", "nyxstrike_server.py"]

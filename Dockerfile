# Vrika Agent Dockerfile
# Optimized with layers for faster builds and better caching.

FROM python:3.13-slim-bookworm

ARG INSTALL_TOOLS=0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VRIKA_HOST=0.0.0.0 \
    VRIKA_PORT=8888 \
    REDIS_URL=redis://host.docker.internal:6379/0 \
    GOPATH=/root/go \
    PATH="/usr/local/bin:/usr/local/go/bin:/root/go/bin:/root/.cargo/bin:${PATH}"

WORKDIR /app

# 1. Install System Build Dependencies & Modern Go
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git ca-certificates wget unzip gcc make libc6-dev perl libnet-ssleay-perl openssl \
    ruby-full pkg-config patch elfutils patchelf default-jre-headless \
    && if [ "$INSTALL_TOOLS" = "1" ]; then \
      wget -q https://go.dev/dl/go1.23.0.linux-amd64.tar.gz \
      && rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz \
      && rm go1.23.0.linux-amd64.tar.gz; \
    fi \
    && rm -rf /var/lib/apt/lists/*

# 2. Install Apt-based Pentest Tools
RUN if [ "$INSTALL_TOOLS" = "1" ]; then \
    sed -i 's/ main$/ main contrib non-free/g' /etc/apt/sources.list 2>/dev/null || true; \
    apt-get update && apt-get install -y --no-install-recommends \
    nmap hydra john hashcat tcpdump dnsutils whois gobuster \
    aircrack-ng whatweb wafw00f dnsenum fierce \
    binwalk gdb \
    && rm -rf /var/lib/apt/lists/*; \
    fi

# 3. Install Special Tools (Binaries/GitHub)
RUN if [ "$INSTALL_TOOLS" = "1" ]; then \
    # Nikto from GitHub
    git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl; \
    # SQLmap from GitHub
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap; \
    # Radare2 from source
    git clone --depth 1 https://github.com/radareorg/radare2.git /opt/radare2 \
    && cd /opt/radare2 && sys/install.sh && cd /app; \
    # Checksec
    git clone --depth 1 https://github.com/slimm609/checksec.sh.git /opt/checksec \
    && ln -sf /opt/checksec/checksec /usr/local/bin/checksec; \
    # Feroxbuster
    wget -q https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb.zip \
    && unzip -q feroxbuster_amd64.deb.zip && dpkg -i feroxbuster_*.deb && rm -f feroxbuster*; \
    # Rustscan
    wget -q https://github.com/RustScan/RustScan/releases/download/2.3.0/rustscan_2.3.0_amd64.deb \
    && dpkg -i rustscan_2.3.0_amd64.deb && rm -f rustscan*; \
    # Amass
    wget -q https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_linux_amd64.zip \
    && unzip -q amass_linux_amd64.zip && mv amass_Linux_amd64/amass /usr/local/bin/ && rm -rf amass_Linux_amd64*; \
    # Libc Database
    git clone --depth 1 https://github.com/niklasb/libc-database.git /opt/libc-database; \
    # One-gadget (Ruby)
    gem install one_gadget; \
    # Pwninit (Rust/Cargo) via Rustup
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    && export PATH="/root/.cargo/bin:${PATH}" \
    && cargo install pwninit \
    && ln -sf /root/.cargo/bin/pwninit /usr/local/bin/pwninit; \
    # Ghidra
    wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1.2_build/ghidra_11.1.2_PUBLIC_20240709.zip \
    && unzip -q ghidra_11.1.2_PUBLIC_20240709.zip -d /opt/ \
    && ln -sf /opt/ghidra_11.1.2_PUBLIC/support/analyzeHeadless /usr/local/bin/ghidra \
    && rm -f ghidra_*.zip; \
    fi


# 4. Install Go-based Tools
RUN if [ "$INSTALL_TOOLS" = "1" ]; then \
    go install github.com/ffuf/ffuf/v2@latest \
    && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install github.com/tomnomnom/assetfinder@latest \
    && go install github.com/tomnomnom/qsreplace@latest \
    && rm -rf /root/go/pkg; \
    fi

# 5. Install Python Dependencies & Python Tools
COPY dependencies/requirements.txt dependencies/pip_constraints.txt ./
COPY requirements.txt ./requirements-root.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt -c pip_constraints.txt \
    && pip install --no-cache-dir -r requirements-root.txt -c pip_constraints.txt \
    && if [ "$INSTALL_TOOLS" = "1" ]; then \
      pip install --no-cache-dir dirsearch uro schemathesis pwntools ropper ROPGadget angr; \
    fi

# 6. Copy Application Source
COPY . .
RUN mkdir -p .nyxstrike_data/config

EXPOSE 8888
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -sf "http://127.0.0.1:${VRIKA_PORT}/health" || exit 1

CMD ["python3", "nyxstrike_server.py"]

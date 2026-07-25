#!/bin/bash
# Install pentest CLI tools inside the agent image.
# Apt where Debian provides packages; git/go fallbacks for tools missing from bookworm (e.g. nikto, ffuf).

set -euo pipefail

apt_has_candidate() {
  local pkg="$1" candidate
  candidate="$(LC_ALL=C apt-cache policy "$pkg" 2>/dev/null | sed -n 's/^[[:space:]]*Candidate:[[:space:]]*//p' | head -n1)"
  [[ -n "$candidate" && "$candidate" != "(none)" ]]
}

apt_install_if_available() {
  local pkg="$1"
  if apt_has_candidate "$pkg"; then
    apt-get install -y --no-install-recommends "$pkg"
    return 0
  fi
  return 1
}

enable_contrib_nonfree() {
  if [[ -f /etc/apt/sources.list.d/debian.sources ]]; then
    sed -i -E 's/(Components: )main/\1main contrib non-free non-free-firmware/' /etc/apt/sources.list.d/debian.sources 2>/dev/null || true
  fi
  if [[ -f /etc/apt/sources.list ]]; then
    sed -i 's/ main$/ main contrib non-free/g' /etc/apt/sources.list 2>/dev/null || true
  fi
}

install_nikto() {
  if command -v nikto >/dev/null 2>&1; then
    return 0
  fi
  echo "Installing nikto from GitHub (not in Debian bookworm apt)..."
  git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto
  # Wrapper so FindBin resolves plugins under /opt/nikto/program (not /usr/local/bin).
  cat > /usr/local/bin/nikto <<'EOF'
#!/bin/sh
cd /opt/nikto/program || exit 1
exec /usr/bin/perl ./nikto.pl "$@"
EOF
  chmod +x /usr/local/bin/nikto /opt/nikto/program/nikto.pl
}

install_go_tool() {
  local bin="$1" pkg="$2"
  if command -v "$bin" >/dev/null 2>&1; then
    return 0
  fi
  echo "Installing $bin via go install..."
  export GOPATH="/root/go"
  export PATH="${PATH}:${GOPATH}/bin"
  go install "$pkg"
  ln -sf "${GOPATH}/bin/$bin" "/usr/local/bin/$bin"
}

# Nuclei embeds bytedance/sonic SIMD JSON (amd64). On CPUs/VMs without PCLMULQDQ
# (common under QEMU without host-passthrough), sonic's SSE path SIGILLs with
# instruction 0x66 0x0f 0x3a 0x44. Build with -tags gofuzz so nuclei uses the
# go-json fallback in pkg/utils/json instead of sonic.
install_nuclei() {
  export GOPATH="/root/go"
  export PATH="${PATH}:${GOPATH}/bin"
  echo "Installing nuclei via go install -tags gofuzz (sonic SIGILL workaround)..."
  go install -tags gofuzz github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  ln -sf "${GOPATH}/bin/nuclei" "/usr/local/bin/nuclei"
}

install_sqlmap() {
  if command -v sqlmap >/dev/null 2>&1; then
    return 0
  fi
  echo "Installing sqlmap from GitHub..."
  git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap
  cat > /usr/local/bin/sqlmap <<'EOF'
#!/bin/sh
exec python3 /opt/sqlmap/sqlmap.py "$@"
EOF
  chmod +x /usr/local/bin/sqlmap
}

install_modern_go() {
  if command -v go >/dev/null 2>&1; then
    local current_version
    current_version=$(go version | awk '{print $3}' | sed 's/go//')
    if [[ "$current_version" > "1.22" ]]; then
       return 0
    fi
  fi
  echo "Installing modern Go (1.23.0)..."
  wget -q https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
  rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
  rm go1.23.0.linux-amd64.tar.gz
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
}

install_feroxbuster() {
  if command -v feroxbuster >/dev/null 2>&1; then
    return 0
  fi
  echo "Installing feroxbuster..."
  wget -q https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb.zip
  unzip -q feroxbuster_amd64.deb.zip
  dpkg -i feroxbuster_*.deb
  rm -f feroxbuster*
}

install_rustscan() {
  if command -v rustscan >/dev/null 2>&1; then
    return 0
  fi
  echo "Installing rustscan..."
  wget -q https://github.com/RustScan/RustScan/releases/download/2.3.0/rustscan_2.3.0_amd64.deb
  dpkg -i rustscan_2.3.0_amd64.deb
  rm -f rustscan*
}

install_amass() {
  if command -v amass >/dev/null 2>&1; then
    return 0
  fi
  echo "Installing amass..."
  wget -q https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_linux_amd64.zip
  unzip -q amass_linux_amd64.zip
  mv amass_Linux_amd64/amass /usr/local/bin/
  rm -rf amass_Linux_amd64*
}

install_zaproxy() {
  if command -v zaproxy >/dev/null 2>&1; then
    return 0
  fi
  echo "Installing OWASP ZAP 2.17.0..."
  wget -q https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz -O /tmp/zap.tar.gz
  tar -xzf /tmp/zap.tar.gz -C /opt/
  rm /tmp/zap.tar.gz
  ln -sf /opt/ZAP_2.17.0/zap.sh /usr/local/bin/zaproxy
}

install_wordlists() {
  echo "Downloading standard wordlists..."
  mkdir -p /usr/share/wordlists/api /usr/share/wordlists/dirb
  
  # Basic API wordlist
  wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt -O /usr/share/wordlists/api/api-endpoints.txt
  
  # Common Web wordlist
  wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -O /usr/share/wordlists/dirb/common.txt
  
  # If first one fails, create a minimal fallback
  if [ ! -s /usr/share/wordlists/api/api-endpoints.txt ]; then
    cat > /usr/share/wordlists/api/api-endpoints.txt <<'EOF'
v1
v2
api
admin
login
auth
EOF
  fi
}

echo "Enabling Debian contrib/non-free for hashcat and related packages..."
enable_contrib_nonfree
apt-get update

echo "Installing build/runtime dependencies..."
apt-get install -y --no-install-recommends \
  perl \
  libjson-perl \
  libwww-perl \
  libnet-ssleay-perl \
  openssl \
  python3 \
  python3-pip \
  git \
  curl \
  wget \
  ca-certificates \
  unzip \
  gcc \
  make \
  libc6-dev \
  default-jre-headless

install_modern_go

APT_TOOLS=(
  nmap
  hydra
  john
  hashcat
  tcpdump
  dnsutils
  whois
  sqlmap
  gobuster
  aircrack-ng
  whatweb
  wafw00f
  dnsenum
  fierce
  nikto
)

for pkg in "${APT_TOOLS[@]}"; do
  if apt_install_if_available "$pkg"; then
    echo "apt installed: ${pkg}"
  else
    echo "apt has no candidate: ${pkg} (will try fallback if available)"
  fi
done

install_nikto
install_sqlmap

# Go tools
export GOPATH="/root/go"
mkdir -p "$GOPATH/bin"
export PATH="${PATH}:${GOPATH}/bin"

install_go_tool ffuf github.com/ffuf/ffuf/v2@latest
install_go_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
install_go_tool assetfinder github.com/tomnomnom/assetfinder@latest
install_nuclei
install_go_tool httpx github.com/projectdiscovery/httpx/cmd/httpx@latest
install_go_tool katana github.com/projectdiscovery/katana/cmd/katana@latest
install_go_tool qsreplace github.com/tomnomnom/qsreplace@latest
install_go_tool dalfox github.com/hahwul/dalfox/v2@latest
install_go_tool gospider github.com/jaeles-project/gospider@latest

install_feroxbuster
install_rustscan
install_amass
install_zaproxy

# Python tools
# setuptools 82+ removed pkg_resources; dirsearch still imports it at startup.
pip install "setuptools>=70,<82" dirsearch uro schemathesis

install_wordlists

REQUIRED_BINS=(nmap nikto sqlmap gobuster ffuf hydra john hashcat tcpdump dig whois subfinder assetfinder nuclei httpx katana feroxbuster rustscan dirsearch amass qsreplace zaproxy dalfox gospider)
MISSING=()
for bin in "${REQUIRED_BINS[@]}"; do
  if ! command -v "${bin}" >/dev/null 2>&1; then
    MISSING+=("${bin}")
  fi
done

if ((${#MISSING[@]} > 0)); then
  echo "ERROR: required tools missing after install: ${MISSING[*]}"
  exit 1
fi

echo "All required tools installed: ${REQUIRED_BINS[*]}"

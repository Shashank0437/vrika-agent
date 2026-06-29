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
  ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto
  chmod +x /opt/nikto/program/nikto.pl
}

install_ffuf() {
  if command -v ffuf >/dev/null 2>&1; then
    return 0
  fi
  echo "Installing ffuf via go install..."
  export GOPATH="/root/go"
  export PATH="${PATH}:${GOPATH}/bin"
  go install github.com/ffuf/ffuf/v2@latest
  ln -sf "${GOPATH}/bin/ffuf" /usr/local/bin/ffuf
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

echo "Enabling Debian contrib/non-free for hashcat and related packages..."
enable_contrib_nonfree
apt-get update

echo "Installing build/runtime dependencies..."
apt-get install -y --no-install-recommends \
  golang-go \
  perl \
  libnet-ssleay-perl \
  openssl \
  python3 \
  python3-pip \
  git \
  curl \
  wget \
  ca-certificates \
  unzip

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
install_go_tool amass github.com/owasp-amass/amass/v4/...@latest || echo "Failed to install amass via go, skipping"
install_go_tool assetfinder github.com/tomnomnom/assetfinder@latest
install_go_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
install_go_tool httpx github.com/projectdiscovery/httpx/cmd/httpx@latest

REQUIRED_BINS=(nmap nikto sqlmap gobuster ffuf hydra john hashcat tcpdump dig whois subfinder assetfinder nuclei httpx)
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

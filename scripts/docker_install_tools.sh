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
  export GOPATH="${GOPATH:-/root/go}"
  export PATH="${PATH}:${GOPATH}/bin"
  go install github.com/ffuf/ffuf/v2@latest
  ln -sf "${GOPATH}/bin/ffuf" /usr/local/bin/ffuf
}

install_gobuster() {
  if command -v gobuster >/dev/null 2>&1; then
    return 0
  fi
  echo "Installing gobuster via go install..."
  export GOPATH="${GOPATH:-/root/go}"
  export PATH="${PATH}:${GOPATH}/bin"
  go install github.com/OJ/gobuster/v3@latest
  ln -sf "${GOPATH}/bin/gobuster" /usr/local/bin/gobuster
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
  python3-pip

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
install_gobuster
install_ffuf

REQUIRED_BINS=(nmap nikto sqlmap gobuster ffuf hydra john hashcat tcpdump dig whois)
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

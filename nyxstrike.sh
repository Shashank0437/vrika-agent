#!/usr/bin/env bash
set -euo pipefail

# NyxStrike — main entrypoint
#
# Usage:
#   ./nyxstrike.sh                        # MCP launcher mode (default, used by 5ire)
#   ./nyxstrike.sh -a                     # Update + start server  (recommended)
#   ./nyxstrike.sh -a -ai                 # Same + Gemini LLM defaults + warmup (needs GOOGLE_API_KEY or GEMINI_API_KEY)
#
#   ./nyxstrike.sh --server               # Start server only (no update/install)
#   ./nyxstrike.sh --mcp                  # Start MCP client only
#   ./nyxstrike.sh --server --mcp         # Start server in background + MCP client
#
#   ./nyxstrike.sh -s                     # Update repo only
#   ./nyxstrike.sh -t                     # Install external tools only
#   ./nyxstrike.sh -t -b                  # Install tools + heavy Python extras
#   ./nyxstrike.sh -u                     # Update already-cloned git_tools
#   ./nyxstrike.sh -y                     # Force reinstall Python requirements
#   ./nyxstrike.sh -ai                    # Write Gemini defaults to config + enable LLM warmup

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${ROOT_DIR}/nyxstrike-env"
PYTHON_BIN="python3"
GIT_TOOLS_DIR="${ROOT_DIR}/git_tools"

# --- install flags ---
INSTALL_TOOLS=false
INSTALL_BIG_PACKAGES=false
UPDATE_GIT_TOOLS=false
UPDATE_SELF=false
UPDATE_PYTHON_PACKAGES=false
PIP_BOOTSTRAPPED=false
CONFIGURE_GEMINI_LLM=false
GEMINI_DEFAULT_MODEL="gemini-2.5-flash"

# --- run flags ---
RUN_SERVER=false
RUN_MCP=false
SERVER_URL="http://127.0.0.1:8888"
PROFILE="default"

# --- do any setup at all? ---
DO_SETUP=false

# External tools to install
# Format: "apt_package:expected_binary"
APT_PACKAGES=(
  "aircrack-ng:aircrack-ng",
  "amass:amass",
  "arjun:arjun",
  "arp-scan:arp-scan",
  "autopsy:autopsy",
  "binutils:binutils",
  "binwalk:binwalk",
  "bulk-extractor:bulk-extractor",
  "bettercap:bettercap",
  "checksec:checksec",
  "dirb:dirb",
  "dirsearch:dirsearch",
  "enum4linux:enum4linux",
  "enum4linux-ng:enum4linux-ng",
  "eaphammer:eaphammer",
  "feroxbuster:feroxbuster",
  "ffuf:ffuf",
  "file:file",
  "foremost:foremost",
  "gdb:gdb",
  "gobuster:gobuster",
  "hashcat:hashcat",
  "hashcat-utils:hashcat-utils",
  "hashid:hashid",
  "hydra:hydra",
  "john:john",
  "kismet:kismet",
  "masscan:masscan",
  "mdk4:mdk4",
  "medusa:medusa",
  "nbtscan:nbtscan",
  "nikto:nikto",
  "nmap:nmap",
  "ophcrack:ophcrack",
  "paramspider:paramspider",
  "patator:patator",
  "radare2:radare2",
  "responder:responder",
  "scalpel:scalpel",
  "sleuthkit:sleuthkit",
  "smbmap:smbmap",
  "sqlmap:sqlmap",
  "steghide:steghide",
  "subfinder:subfinder",
  "tcpdump:tcpdump",
  "testdisk:testdisk",
  "tshark:tshark",
  "wireshark:wireshark",
  "wpscan:wpscan",
  "xxd:xxd",
  "python3-ldapdomaindump:python3-ldapdomaindump",
  "commix:commix",
  "theharvester:theharvester",
  "sublist3r:sublist3r",
  "parsero:parsero",
  "joomscan:joomscan"
)

# Format: "go_module@version:expected_binary"
GO_PACKAGES=(
)

# Format: "cargo_package:expected_binary"
CARGO_PACKAGES=(
  "x8:x8"
)

# Git repos to clone into git_tools.
# Format: "repo_url|requirements_file_relpath"
# Leave requirements file empty when no extra setup is needed.
GIT_REPOS=(
#  "https://github.com/nsonaniya2010/SubDomainizer.git|requirements.txt"
#  "https://github.com/rastating/dnmasscan.git|"
#  "https://github.com/hannob/tlshelpers.git|"
)

# ---------------------------------------------------------------------------
# Setup functions (formerly install.sh)
# ---------------------------------------------------------------------------

is_apt_package_installed() {
  local package_name="$1"
  dpkg -s "${package_name}" >/dev/null 2>&1
}

# True when apt can install a real version (not missing, not Candidate: (none), e.g. radare2 on some distros).
apt_has_install_candidate() {
  local package_name="$1" candidate
  candidate="$(LC_ALL=C apt-cache policy "$package_name" 2>/dev/null | sed -n 's/^[[:space:]]*Candidate:[[:space:]]*//p' | head -n1)"
  [[ -n "$candidate" && "$candidate" != "(none)" ]]
}

update_self_repo() {
  if [[ "${UPDATE_SELF}" != true ]]; then
    return
  fi

  if ! command -v git >/dev/null 2>&1; then
    echo "Skipping self update: git is not installed."
    return
  fi

  if [[ ! -d "${ROOT_DIR}/.git" ]]; then
    echo "Skipping self update: repository metadata not found."
    return
  fi

  if ! git -C "${ROOT_DIR}" diff --quiet || \
     ! git -C "${ROOT_DIR}" diff --cached --quiet || \
     [[ -n "$(git -C "${ROOT_DIR}" ls-files --others --exclude-standard)" ]]; then
    echo "Skipping self update: local changes detected in project repo."
    return
  fi

  echo "Updating project repository..."
  if ! git -C "${ROOT_DIR}" pull --ff-only --quiet; then
    echo "Self update failed (non-fast-forward or remote issue). Continuing."
  fi
}

install_external_tools() {
  if [[ ${#APT_PACKAGES[@]} -eq 0 && ${#GO_PACKAGES[@]} -eq 0 && ${#CARGO_PACKAGES[@]} -eq 0 ]]; then
    return
  fi

  if [[ ${#APT_PACKAGES[@]} -gt 0 ]]; then
    if ! command -v apt >/dev/null 2>&1; then
      echo "Skipping apt packages: apt is not available on this system."
    else
      echo "Updating apt package lists..."
      sudo apt-get update -qq

      local apt_to_install=()
      local apt_entry="" apt_pkg="" apt_bin=""

      for apt_entry in "${APT_PACKAGES[@]}"; do
        apt_pkg="${apt_entry%%:*}"
        apt_bin="${apt_entry##*:}"
        if command -v "${apt_bin}" >/dev/null 2>&1 || is_apt_package_installed "${apt_pkg}"; then
          continue
        fi
        apt_to_install+=("${apt_pkg}")
      done

      if [[ ${#apt_to_install[@]} -gt 0 ]]; then
        local apt_ok=() apt_skipped=0
        for apt_pkg in "${apt_to_install[@]}"; do
          if apt_has_install_candidate "${apt_pkg}"; then
            apt_ok+=("${apt_pkg}")
          else
            ((apt_skipped++)) || true
            echo "No apt install candidate (skipped): ${apt_pkg} — add repos/snap, or install manually if needed."
          fi
        done
        if [[ ${#apt_ok[@]} -gt 0 ]]; then
          echo "Installing apt packages: ${apt_ok[*]}"
          if ! sudo apt install -y -qq "${apt_ok[@]}"; then
            echo "Batch install failed; installing remaining packages one at a time..."
            for apt_pkg in "${apt_ok[@]}"; do
              if is_apt_package_installed "${apt_pkg}"; then
                continue
              fi
              for apt_entry in "${APT_PACKAGES[@]}"; do
                if [[ "${apt_entry%%:*}" == "${apt_pkg}" ]]; then
                  if command -v "${apt_entry##*:}" &>/dev/null; then
                    continue 2
                  fi
                  break
                fi
              done
              if ! sudo apt install -y -qq "${apt_pkg}"; then
                echo "apt install failed (non-fatal): ${apt_pkg}"
              fi
            done
          fi
        fi
        if ((apt_skipped > 0)); then
          echo "Skipped ${apt_skipped} package(s) with no apt candidate. On Ubuntu, try: sudo add-apt-repository universe; sudo add-apt-repository multiverse; sudo apt-get update"
        fi
      fi
    fi
  fi

  if [[ ${#GO_PACKAGES[@]} -gt 0 ]]; then
    if ! command -v go >/dev/null 2>&1; then
      echo "Skipping Go packages: go is not installed."
    else
      local go_entry="" go_pkg="" go_bin=""
      for go_entry in "${GO_PACKAGES[@]}"; do
        go_pkg="${go_entry%%:*}"
        go_bin="${go_entry##*:}"
        if command -v "${go_bin}" >/dev/null 2>&1; then
          continue
        fi
        echo "Installing Go package: ${go_pkg}"
        go install "${go_pkg}"
      done
    fi
  fi

  if [[ ${#CARGO_PACKAGES[@]} -gt 0 ]]; then
    if ! command -v cargo >/dev/null 2>&1; then
      echo "Skipping Cargo packages: cargo is not installed."
    else
      local cargo_entry="" cargo_pkg="" cargo_bin=""
      for cargo_entry in "${CARGO_PACKAGES[@]}"; do
        cargo_pkg="${cargo_entry%%:*}"
        cargo_bin="${cargo_entry##*:}"
        if command -v "${cargo_bin}" >/dev/null 2>&1; then
          continue
        fi
        cargo install --quiet "${cargo_pkg}"
      done
    fi
  fi
}

setup_git_repo() {
  local repo_dir="$1"
  local requirements_rel="$2"

  if [[ -z "${requirements_rel}" ]]; then
    return
  fi

  local repo_name
  repo_name="$(basename "${repo_dir}")"
  local requirements_file="${repo_dir}/${requirements_rel}"

  if [[ ! -f "${requirements_file}" ]]; then
    echo "Repo setup skipped (missing requirements): ${requirements_file}"
    return
  fi

  local stamp_file="${repo_dir}/.app_setup_$(basename "${requirements_rel}").stamp"
  if [[ -f "${stamp_file}" && "${stamp_file}" -nt "${requirements_file}" ]]; then
    echo "Repo already prepared, skipping: ${repo_name}"
    return
  fi

  local python_minor
  python_minor="$(${VENV_DIR}/bin/python3 -c 'import sys; print(sys.version_info.minor)')"
  if [[ "${repo_name}" == "SubDomainizer" && "${python_minor}" -ge 13 ]]; then
    echo "Repo setup skipped for ${repo_name}: not compatible with Python 3.13+ (cgi module removed)."
    echo "Use a Python 3.12 or older venv inside ${repo_dir} if you need it locally."
    return
  fi

  echo "Preparing repo: ${repo_name}"
  if ! "${VENV_DIR}/bin/python3" -m pip --disable-pip-version-check install  -r "${requirements_file}"; then
    echo "Repo setup failed for ${repo_name}; continuing."
    echo "You can run setup manually inside ${repo_dir}."
    return
  fi

  touch "${stamp_file}"
}

ensure_pip_ready() {
  if [[ "${PIP_BOOTSTRAPPED}" == true ]]; then
    return
  fi
  "${VENV_DIR}/bin/python3" -m pip --disable-pip-version-check install --quiet --upgrade pip
  PIP_BOOTSTRAPPED=true
}

install_requirements_file() {
  local requirements_file="$1"
  local requirements_name
  requirements_name="$(basename "${requirements_file}")"
  local stamp_file="${VENV_DIR}/.app_python_deps_${requirements_name}.stamp"

  if [[ "${UPDATE_PYTHON_PACKAGES}" != true && -f "${stamp_file}" && "${stamp_file}" -nt "${requirements_file}" ]]; then
    return
  fi

  ensure_pip_ready
  echo "Installing Python deps from: ${requirements_name}"
  local pip_constraint=()
  if [[ -f "${ROOT_DIR}/dependencies/pip_constraints.txt" ]]; then
    pip_constraint=(-c "${ROOT_DIR}/dependencies/pip_constraints.txt")
  fi
  "${VENV_DIR}/bin/python3" -m pip --disable-pip-version-check install  "${pip_constraint[@]}" -r "${requirements_file}"
  touch "${stamp_file}"
}

write_gemini_llm_config_local() {
  local model="${1:-${GEMINI_DEFAULT_MODEL}}"
  local data_dir="${NYXSTRIKE_DATA_DIR:-${ROOT_DIR}/.nyxstrike_data}"
  local config_file="${NYXSTRIKE_CONFIG_FILE:-${data_dir}/config/config_local.json}"
  local config_dir
  config_dir="$(dirname "${config_file}")"

  if ! command -v python3 >/dev/null 2>&1; then
    echo "Warning: python3 not found; merge these into ${config_file} manually:"
    echo '  NYXSTRIKE_LLM_PROVIDER=gemini, NYXSTRIKE_LLM_MODEL='"${model}"', NYXSTRIKE_LLM_URL=""'
    return
  fi

  local existing="{}"
  if [[ -f "${config_file}" ]]; then
    existing="$(cat "${config_file}")"
  else
    mkdir -p "${config_dir}"
  fi

  python3 - "${config_file}" "${model}" "${existing}" <<'PYEOF'
import sys, json
config_file, model, existing_json = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    data = json.loads(existing_json)
except Exception:
    data = {}
data["NYXSTRIKE_LLM_PROVIDER"] = "gemini"
data["NYXSTRIKE_LLM_MODEL"] = model
data["NYXSTRIKE_LLM_URL"] = ""
with open(config_file, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
PYEOF
  echo "Gemini LLM configured in ${config_file} (provider=gemini, model=${model})."
  echo "Set an API key before starting the server, e.g.: export GOOGLE_API_KEY=\"<key from https://ai.google.dev/ >\""
}

clone_or_update_git_tools() {
  if [[ ${#GIT_REPOS[@]} -eq 0 ]]; then
    return
  fi

  if ! command -v git >/dev/null 2>&1; then
    echo "Skipping git repo sync: git is not installed."
    return
  fi

  mkdir -p "${GIT_TOOLS_DIR}"

  local repo_entry="" repo_url="" repo_requirements="" repo_name="" repo_dir=""

  for repo_entry in "${GIT_REPOS[@]}"; do
    IFS='|' read -r repo_url repo_requirements <<< "${repo_entry}"
    repo_name="$(basename "${repo_url}" .git)"
    repo_dir="${GIT_TOOLS_DIR}/${repo_name}"

    if [[ -d "${repo_dir}/.git" ]]; then
      if [[ "${UPDATE_GIT_TOOLS}" == true ]]; then
        echo "Updating git repo: ${repo_name}"
        git -C "${repo_dir}" pull --ff-only --quiet
      fi
    elif [[ -e "${repo_dir}" ]]; then
      echo "Path exists and is not a git repo, skipping: ${repo_dir}"
    else
      echo "Cloning git repo: ${repo_name}"
      git clone --quiet "${repo_url}" "${repo_dir}"
    fi

    if [[ -d "${repo_dir}/.git" ]]; then
      setup_git_repo "${repo_dir}" "${repo_requirements}"
    fi
  done
}

run_setup() {
  update_self_repo

  echo "[1/4] Preparing virtual environment..."
  if [[ ! -d "${VENV_DIR}" ]]; then
    "${PYTHON_BIN}" -m venv "${VENV_DIR}"
  fi

  echo "[2/4] Syncing Python dependencies... (may take a while on first run)"
  install_requirements_file "${ROOT_DIR}/dependencies/requirements.txt"

  if [[ "${INSTALL_TOOLS}" == true && -f "${ROOT_DIR}/dependencies/requirements-extra.txt" ]]; then
    install_requirements_file "${ROOT_DIR}/dependencies/requirements-extra.txt"
  fi

  if [[ "${INSTALL_TOOLS}" == true && "${INSTALL_BIG_PACKAGES}" == true && -f "${ROOT_DIR}/dependencies/requirements-big.txt" ]]; then
    echo "Installing big optional Python packages..."
    install_requirements_file "${ROOT_DIR}/dependencies/requirements-big.txt"
  fi

  if [[ "${INSTALL_TOOLS}" == true ]]; then
    echo "[3/4] Installing external tools..."
    install_external_tools
  else
    echo "[3/4] Skipping external tools (use -t to enable)."
  fi

  if [[ "${INSTALL_TOOLS}" == true ]]; then
    echo "[4/4] Syncing git tool repositories..."
    clone_or_update_git_tools
  else
    echo "[4/4] Skipping git tool repositories (use -t to enable)."
  fi

  if [[ "${CONFIGURE_GEMINI_LLM}" == true ]]; then
    echo "[5/5] Configuring Google Gemini LLM defaults..."
    write_gemini_llm_config_local "${GEMINI_DEFAULT_MODEL}"
  fi

  echo "Setup complete."
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--python)
      PYTHON_BIN="$2"
      shift 2
      ;;
    -s|--update-self)
      UPDATE_SELF=true
      DO_SETUP=true
      shift
      ;;
    -t|--install-tools)
      INSTALL_TOOLS=true
      DO_SETUP=true
      shift
      ;;
    -b|--install-big-packages)
      INSTALL_BIG_PACKAGES=true
      INSTALL_TOOLS=true
      DO_SETUP=true
      shift
      ;;
    -u|--update-git-tools)
      UPDATE_GIT_TOOLS=true
      INSTALL_TOOLS=true
      DO_SETUP=true
      shift
      ;;
    -y|--update-python-packages)
      UPDATE_PYTHON_PACKAGES=true
      DO_SETUP=true
      shift
      ;;
    -a|--all)
      UPDATE_SELF=true
      DO_SETUP=true
      RUN_SERVER=true
      shift
      ;;
    -ai)
      CONFIGURE_GEMINI_LLM=true
      export NYXSTRIKE_LLM_WARMUP=1
      DO_SETUP=true
      shift
      ;;
    --server)
      RUN_SERVER=true
      shift
      ;;
    --mcp)
      RUN_MCP=true
      shift
      ;;
    --server-url)
      SERVER_URL="$2"
      shift 2
      ;;
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    -h|--help)
      echo "NyxStrike"
      echo ""
      echo "Setup:"
      echo "  -a, --all               Start here — update repo + start server"
      echo "  -s, --update-self       git pull this repo (skips if local changes present)"
      echo "  -t, --install-tools     Install external apt/go/cargo tools and clone git_tools"
      echo "  -b, --install-big-packages  Install heavy optional Python extras (implies -t)"
      echo "  -u, --update-git-tools  Pull latest for already-cloned git_tools repos (implies -t)"
      echo "  -y, --update-python-packages  Force reinstall of Python requirements"
      echo "  -p, --python <bin>      Python binary to use (default: python3)"
    echo "  -ai                     Configure Gemini (writes config_local.json; set GOOGLE_API_KEY or GEMINI_API_KEY)"
      echo ""
      echo "Run:"
      echo "  --server                Start the NyxStrike API server"
      echo "  --mcp                   Start the MCP client (default when no flags given)"
      echo "  --server --mcp          Start server in background + MCP client"
      echo "  --server-url <url>      MCP target server URL (default: ${SERVER_URL})"
      echo "  --profile <name>        MCP profile (default: ${PROFILE})"
      echo ""
      echo "Examples:"
      echo "  ./nyxstrike.sh -a               # start here (first run + daily driver)"
      echo "  ./nyxstrike.sh -a -ai           # with Gemini defaults + LLM warmup"
      echo "  ./nyxstrike.sh --server         # just start the server"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Run with --help for usage."
      exit 1
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Default: no args → MCP launcher mode (preserves 5ire compatibility)
# ---------------------------------------------------------------------------

if [[ "${DO_SETUP}" == false && "${RUN_SERVER}" == false && "${RUN_MCP}" == false ]]; then
  RUN_MCP=true
fi

# ---------------------------------------------------------------------------
# Resolve venv (must exist before we can run anything)
# ---------------------------------------------------------------------------

if [[ ! -x "${VENV_DIR}/bin/python3" ]]; then
  if [[ "${DO_SETUP}" == true ]]; then
    # venv will be created inside run_setup
    true
  else
    echo "No virtualenv found. Run: ./nyxstrike.sh -a"
    exit 1
  fi
fi

export PATH="${VENV_DIR}/bin:${PATH}"
cd "${ROOT_DIR}"

# ---------------------------------------------------------------------------
# Run setup phase if requested
# ---------------------------------------------------------------------------

if [[ "${DO_SETUP}" == true ]]; then
  run_setup
fi

# ---------------------------------------------------------------------------
# Run phase
# ---------------------------------------------------------------------------

if [[ "${RUN_SERVER}" == true && "${RUN_MCP}" == true ]]; then
  echo "Starting API server in background..."
  "${VENV_DIR}/bin/python3" "${ROOT_DIR}/nyxstrike_server.py" &
  server_pid=$!

  cleanup() {
    kill "${server_pid}" >/dev/null 2>&1 || true
  }
  trap cleanup EXIT

  echo "Starting MCP client..."
  exec "${VENV_DIR}/bin/python3" "${ROOT_DIR}/nyxstrike_mcp.py" --server "${SERVER_URL}" --profile "${PROFILE}"
fi

if [[ "${RUN_SERVER}" == true ]]; then
  exec "${VENV_DIR}/bin/python3" "${ROOT_DIR}/nyxstrike_server.py"
fi

if [[ "${RUN_MCP}" == true ]]; then
  exec "${VENV_DIR}/bin/python3" "${ROOT_DIR}/nyxstrike_mcp.py" --server "${SERVER_URL}" --profile "${PROFILE}"
fi


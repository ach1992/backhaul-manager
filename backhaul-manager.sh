#!/usr/bin/env bash
set -Eeuo pipefail

# ==========================================
# Backhaul Manager (v1.0.1)
# Manager Repo: https://github.com/ach1992/backhaul-manager/
# Core Repo:    https://github.com/Musixal/Backhaul
# ==========================================

MANAGER_VERSION="1.0.1"
MANAGER_REPO_URL="https://github.com/ach1992/backhaul-manager/"
CORE_REPO_URL="https://github.com/Musixal/Backhaul"

# Raw URL for self-install/update (critical for curl|bash installs)
MANAGER_RAW_URL="https://raw.githubusercontent.com/ach1992/backhaul-manager/main/backhaul-manager.sh"

APP_NAME="Backhaul Manager"
APP_CMD="backhaul-manager"
APP_DIR="/opt/backhaul-manager"
APP_SCRIPT="${APP_DIR}/backhaul-manager.sh"
APP_SYMLINK="/usr/local/bin/${APP_CMD}"

CORE_BIN="/usr/local/bin/backhaul"

CONF_DIR="/etc/backhaul-manager"
TUNNELS_DIR="${CONF_DIR}/tunnels"
STATE_DIR="/var/lib/backhaul-manager"
DB_FILE="${STATE_DIR}/tunnels.db"

LOG_DIR="/var/log/backhaul-manager"
LOG_FILE="${LOG_DIR}/manager.log"

SYSTEMD_DIR="/etc/systemd/system"

OFFLINE_DIR="/root/backhaul-manager"

CORE_REPO_OWNER="Musixal"
CORE_REPO_NAME="Backhaul"
CORE_RELEASES_URL="https://github.com/${CORE_REPO_OWNER}/${CORE_REPO_NAME}/releases"
CORE_API_LATEST="https://api.github.com/repos/${CORE_REPO_OWNER}/${CORE_REPO_NAME}/releases/latest"

# Colors
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[34m"; MAGENTA="\033[35m"; CYAN="\033[36m"; GRAY="\033[90m"; NC="\033[0m"; BOLD="\033[1m"

# ---------- logging ----------
mkdir -p "${LOG_DIR}" 2>/dev/null || true
log() { echo -e "[$(date '+%F %T')] $*" | tee -a "${LOG_FILE}" >/dev/null; }
die() { echo -e "${RED}ERROR:${NC} $*" >&2; log "ERROR: $*"; exit 1; }

on_err() {
  local ec=$?
  local line=${BASH_LINENO[0]:-?}
  local cmd=${BASH_COMMAND:-?}
  echo -e "${RED}UNEXPECTED ERROR${NC} (exit ${ec}) at line ${line}\nCommand: ${cmd}" >&2
  log "UNEXPECTED ERROR ec=${ec} line=${line} cmd=${cmd}"
  exit $ec
}
trap on_err ERR

# ---------- helpers ----------
is_root() { [[ "${EUID}" -eq 0 ]]; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }
pause() { read -r -p "Press Enter to continue..." _; }

need_systemd() {
  have_cmd systemctl || die "systemctl not found. This tool requires systemd."
}

os_ok() {
  [[ "$(uname -s)" == "Linux" ]] || die "Unsupported OS: $(uname -s). Linux required."
}

detect_pkg_mgr() {
  if have_cmd apt-get; then echo "apt"
  elif have_cmd dnf; then echo "dnf"
  elif have_cmd yum; then echo "yum"
  elif have_cmd pacman; then echo "pacman"
  else echo "unknown"
  fi
}

pkg_install() {
  local pkgs=("$@")
  local mgr; mgr="$(detect_pkg_mgr)"
  case "${mgr}" in
    apt)
      DEBIAN_FRONTEND=noninteractive apt-get -y install "${pkgs[@]}" >/dev/null
      ;;
    dnf)
      dnf -y install "${pkgs[@]}" >/dev/null
      ;;
    yum)
      yum -y install "${pkgs[@]}" >/dev/null
      ;;
    pacman)
      pacman -Sy --noconfirm "${pkgs[@]}" >/dev/null
      ;;
    *)
      die "No supported package manager found. Install required tools manually: ${pkgs[*]}"
      ;;
  esac
}

ensure_deps() {
  local missing=()
  have_cmd curl || missing+=("curl")
  have_cmd tar  || missing+=("tar")
  have_cmd awk  || missing+=("gawk")
  have_cmd sed  || missing+=("sed")
  have_cmd grep || missing+=("grep")
  have_cmd ss   || missing+=("iproute2")

  if (( ${#missing[@]} > 0 )); then
    echo -e "${YELLOW}Installing missing dependencies:${NC} ${missing[*]}"
    pkg_install "${missing[@]}" || die "Failed to install dependencies: ${missing[*]}"
  fi
}

ensure_dirs() {
  mkdir -p "${APP_DIR}" "${CONF_DIR}" "${TUNNELS_DIR}" "${STATE_DIR}" "${LOG_DIR}"
  touch "${DB_FILE}"
  chmod 700 "${APP_DIR}" "${STATE_DIR}" || true
  chmod 755 "${CONF_DIR}" "${TUNNELS_DIR}" || true
}

realpath_soft() {
  # best-effort realpath without requiring coreutils realpath
  local p="$1"
  if have_cmd readlink; then
    readlink -f "$p" 2>/dev/null || echo "$p"
  else
    echo "$p"
  fi
}

core_version() {
  if [[ -x "${CORE_BIN}" ]]; then
    "${CORE_BIN}" -v 2>/dev/null || true
  else
    echo ""
  fi
}

print_header() {
  clear || true
  echo -e "${BOLD}${CYAN}================================================${NC}"
  echo -e "${BOLD}${CYAN}                 ${APP_NAME}${NC}"
  echo -e "${BOLD}${CYAN}================================================${NC}"
  echo -e "${GRAY}Manager repo:${NC} ${MANAGER_REPO_URL}"
  echo -e "${GRAY}Core repo:   ${NC} ${CORE_REPO_URL}"
  echo -e "${GRAY}Manager ver: ${NC} ${BOLD}${MANAGER_VERSION}${NC}"
  echo -e "${GRAY}Core binary: ${NC} ${CORE_BIN}  $( [[ -x "${CORE_BIN}" ]] && echo -e "${GREEN}[INSTALLED]${NC}" || echo -e "${RED}[NOT INSTALLED]${NC}" )"
  local ver; ver="$(core_version)"
  [[ -n "${ver}" ]] && echo -e "${GRAY}Core ver:    ${NC} ${BOLD}${ver}${NC}"
  echo
}

ask_yes_no() {
  local prompt="$1" default="${2:-}"
  local ans
  while true; do
    if [[ "${default}" == "y" ]]; then
      read -r -p "${prompt} [Y/n]: " ans
      ans="${ans:-y}"
    elif [[ "${default}" == "n" ]]; then
      read -r -p "${prompt} [y/N]: " ans
      ans="${ans:-n}"
    else
      read -r -p "${prompt} [y/n]: " ans
    fi
    case "${ans,,}" in
      y|yes) return 0 ;;
      n|no) return 1 ;;
      *) echo "Invalid input. Please type y or n." ;;
    esac
  done
}

input_nonempty() {
  local prompt="$1" default="${2:-}"
  local v
  while true; do
    if [[ -n "${default}" ]]; then
      read -r -p "${prompt} [default: ${default}]: " v
      v="${v:-$default}"
    else
      read -r -p "${prompt}: " v
    fi
    v="$(echo -n "${v}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -n "${v}" ]] && { echo "${v}"; return 0; }
    echo "Value cannot be empty."
  done
}

input_int_range() {
  local prompt="$1" min="$2" max="$3" default="${4:-}"
  local v
  while true; do
    if [[ -n "${default}" ]]; then
      read -r -p "${prompt} (${min}-${max}) [default: ${default}]: " v
      v="${v:-$default}"
    else
      read -r -p "${prompt} (${min}-${max}): " v
    fi
    [[ "${v}" =~ ^[0-9]+$ ]] || { echo "Please enter a number."; continue; }
    (( v >= min && v <= max )) || { echo "Out of range."; continue; }
    echo "${v}"
    return 0
  done
}

# Validate: IPv4 / Domain / IPv6 (bracketed for host:port)
is_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
is_domain() { [[ "$1" =~ ^([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$ ]]; }
is_ipv6() { [[ "$1" =~ ^[0-9a-fA-F:]+$ ]]; }

validate_hostport() {
  local v="$1"
  if [[ "${v}" =~ ^\[([0-9a-fA-F:]+)\]:([0-9]{1,5})$ ]]; then
    local h="${BASH_REMATCH[1]}" p="${BASH_REMATCH[2]}"
    is_ipv6 "${h}" || return 1
    (( p>=1 && p<=65535 )) || return 1
    return 0
  fi
  if [[ "${v}" =~ ^([^:]+):([0-9]{1,5})$ ]]; then
    local h="${BASH_REMATCH[1]}" p="${BASH_REMATCH[2]}"
    (( p>=1 && p<=65535 )) || return 1
    is_ipv4 "${h}" && return 0
    is_domain "${h}" && return 0
    return 1
  fi
  return 1
}

input_hostport() {
  local prompt="$1" default="${2:-}"
  local v
  while true; do
    if [[ -n "${default}" ]]; then
      read -r -p "${prompt} [default: ${default}]: " v
      v="${v:-$default}"
    else
      read -r -p "${prompt}: " v
    fi
    v="$(echo -n "${v}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    if validate_hostport "${v}"; then
      echo "${v}"
      return 0
    fi
    echo "Invalid format. Use: ipv4:port, domain:port, or [ipv6]:port"
  done
}

port_in_use() {
  local port="$1"
  ss -lntup 2>/dev/null | awk '{print $4}' | grep -E "[:.]${port}\$" -q
}

# ---------- DB ----------
db_has_tunnel() { grep -E "^${1}\|" "${DB_FILE}" -q; }
db_add_or_update() {
  local name="$1" role="$2" transport="$3" conf="$4" svc="$5"
  if db_has_tunnel "${name}"; then
    sed -i "s#^${name}|.*#${name}|${role}|${transport}|${conf}|${svc}#g" "${DB_FILE}"
  else
    echo "${name}|${role}|${transport}|${conf}|${svc}" >> "${DB_FILE}"
  fi
}
db_remove() { sed -i "/^${1}\|/d" "${DB_FILE}"; }

svc_name_for() { echo "backhaul-${1}.service"; }
conf_path_for() { echo "${TUNNELS_DIR}/${1}.toml"; }

systemd_write_unit() {
  local svc="$1" conf="$2"
  local unit="${SYSTEMD_DIR}/${svc}"
  cat > "${unit}" <<EOF
[Unit]
Description=Backhaul Tunnel (${svc})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${CORE_BIN} -c ${conf}
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

systemd_enable_start() { systemctl enable --now "$1" >/dev/null; }
systemd_stop_disable() { systemctl disable --now "$1" >/dev/null 2>&1 || true; }

systemd_status_line() {
  local svc="$1"
  if systemctl is-enabled "${svc}" >/dev/null 2>&1; then
    local st; st="$(systemctl is-active "${svc}" 2>/dev/null || true)"
    [[ "${st}" == "active" ]] && echo -e "${GREEN}active${NC}" || echo -e "${YELLOW}${st}${NC}"
  else
    echo -e "${GRAY}not-enabled${NC}"
  fi
}

# ---------- core install ----------
arch_to_asset() {
  local arch; arch="$(uname -m)"
  case "${arch}" in
    x86_64|amd64) echo "backhaul_linux_amd64.tar.gz" ;;
    aarch64|arm64) echo "backhaul_linux_arm64.tar.gz" ;;
    *) die "Unsupported architecture: ${arch}. Supported: amd64, arm64." ;;
  esac
}

fetch_latest_tag() {
  local tag
  tag="$(curl -fsSL "${CORE_API_LATEST}" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
  [[ -n "${tag}" ]] || die "Failed to determine latest release tag from GitHub API."
  echo "${tag}"
}

download_core_online() {
  local asset="$1" tag="$2"
  local url="${CORE_RELEASES_URL}/download/${tag}/${asset}"
  local tmp="/tmp/${asset}"
  echo -e "${BLUE}Downloading core:${NC} ${url}"
  curl -fL --retry 3 --retry-delay 2 -o "${tmp}" "${url}" || die "Failed to download core asset."
  echo "${tmp}"
}

install_core_from_tar() {
  local tarfile="$1"
  local tmpdir="/tmp/backhaul-core.$$"
  mkdir -p "${tmpdir}"
  tar -xzf "${tarfile}" -C "${tmpdir}" || die "Failed to extract ${tarfile}"
  [[ -f "${tmpdir}/backhaul" ]] || die "Extracted archive does not contain 'backhaul' binary."
  install -m 0755 "${tmpdir}/backhaul" "${CORE_BIN}"
  rm -rf "${tmpdir}" || true
}

install_core() {
  if [[ -x "${CORE_BIN}" ]]; then
    echo -e "${GREEN}Core already installed.${NC}"
    return 0
  fi

  local asset; asset="$(arch_to_asset)"
  local tarfile=""

  local can_offline="no"
  if [[ -d "${OFFLINE_DIR}" && -f "${OFFLINE_DIR}/${asset}" ]]; then
    can_offline="yes"
  fi

  if [[ "${can_offline}" == "yes" ]] && ask_yes_no "Offline core asset found at ${OFFLINE_DIR}/${asset}. Install core offline?" "y"; then
    tarfile="${OFFLINE_DIR}/${asset}"
    echo -e "${BLUE}Installing core offline from:${NC} ${tarfile}"
    install_core_from_tar "${tarfile}"
    return 0
  fi

  local tag; tag="$(fetch_latest_tag)"
  tarfile="$(download_core_online "${asset}" "${tag}")"
  install_core_from_tar "${tarfile}"
  rm -f "${tarfile}" || true
}

# ---------- self install/update ----------
ensure_manager_on_disk() {
  mkdir -p "${APP_DIR}"

  # If already running from the installed script, do nothing (prevents "same file" error).
  local running; running="$(realpath_soft "${BASH_SOURCE[0]:-$0}")"
  local installed; installed="$(realpath_soft "${APP_SCRIPT}")"

  if [[ -f "${APP_SCRIPT}" && "${running}" == "${installed}" ]]; then
    return 0
  fi

  # If running from a real file on disk (not stdin), copy it unless it's the same.
  local src="${BASH_SOURCE[0]:-$0}"
  local src_real; src_real="$(realpath_soft "${src}")"
  if [[ -f "${src}" && "${src_real}" != "${installed}" ]]; then
    install -m 0755 "${src}" "${APP_SCRIPT}"
    return 0
  fi

  # Otherwise (stdin/pipe or unknown), download from RAW url.
  echo -e "${BLUE}Ensuring manager script on disk (downloading from repo)...${NC}"
  curl -fsSL "${MANAGER_RAW_URL}" -o "${APP_SCRIPT}" || die "Failed to download manager script from ${MANAGER_RAW_URL}"
  chmod +x "${APP_SCRIPT}"
}

install_or_update() {
  os_ok
  is_root || die "Run as root (sudo)."
  need_systemd
  ensure_dirs
  ensure_deps

  ensure_manager_on_disk

  ln -sf "${APP_SCRIPT}" "${APP_SYMLINK}"
  chmod +x "${APP_SYMLINK}" 2>/dev/null || true
  hash -r 2>/dev/null || true

  echo -e "${GREEN}Installed command:${NC} ${APP_SYMLINK}"

  install_core

  echo -e "${GREEN}Installation complete.${NC}"
  echo -e "Run: ${BOLD}${APP_CMD}${NC}"
}

# ---------- tunnel creation helpers ----------
choose_role() {
  echo
  echo -e "${BOLD}Select node role for this tunnel:${NC}"
  echo "  1) Iran (Server)   - runs server config (bind/listen + ports rules)"
  echo "  2) Outside (Client) - runs client config (remote_addr to server)"
  local c; c="$(input_int_range "Enter choice" 1 2 "1")"
  case "${c}" in
    1) echo "server" ;;
    2) echo "client" ;;
  esac
}

choose_transport() {
  echo
  echo -e "${BOLD}Select transport:${NC}"
  echo "  1) tcp"
  echo "  2) tcpmux"
  echo "  3) udp"
  echo "  4) ws"
  echo "  5) wss (TLS required)"
  echo "  6) wsmux"
  echo "  7) wssmux (TLS required)"
  local c; c="$(input_int_range "Enter choice" 1 7 "1")"
  case "${c}" in
    1) echo "tcp" ;;
    2) echo "tcpmux" ;;
    3) echo "udp" ;;
    4) echo "ws" ;;
    5) echo "wss" ;;
    6) echo "wsmux" ;;
    7) echo "wssmux" ;;
  esac
}

choose_bind_addr() {
  local ip
  ip="$(input_nonempty "Bind address (IPv4) for server to listen on" "0.0.0.0")"
  if [[ "${ip}" != "0.0.0.0" ]] && ! is_ipv4 "${ip}"; then
    echo "Invalid IPv4. Using default 0.0.0.0"
    ip="0.0.0.0"
  fi
  echo "${ip}"
}

input_server_listen_port() {
  local p
  p="$(input_int_range "Server listen port" 1 65535 "3080")"
  port_in_use "${p}" && die "Port ${p} is already in use on this system."
  echo "${p}"
}

input_ports_rules_server() {
  echo
  echo -e "${BOLD}Server ports rules:${NC}"
  echo "Examples:"
  echo "  443"
  echo "  443-600"
  echo "  443-600:5201"
  echo "  443-600=1.1.1.1:5201"
  echo
  echo "Enter ONE rule per line. Press Enter on an empty line to finish."
  local rules=()
  while true; do
    local line
    read -r -p "> " line
    line="$(echo -n "${line}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "${line}" ]] && break
    if [[ ! "${line}" =~ ^[0-9]{1,5}(-[0-9]{1,5})?([:=]([0-9]{1,5}|([^=:\ ]+):[0-9]{1,5}))?$ ]]; then
      echo "Invalid rule format. Try again."
      continue
    fi
    rules+=("${line}")
  done
  (( ${#rules[@]} > 0 )) || die "At least one ports rule is required."
  printf "%s\n" "${rules[@]}"
}

input_client_remote_addr() {
  input_hostport "Remote address (server) (ipv4:port, domain:port, or [ipv6]:port)"
}

input_ws_path() {
  local p
  p="$(input_nonempty "WebSocket path (must start with /)" "/")"
  [[ "${p}" =~ ^/ ]] || p="/${p}"
  echo "${p}"
}

input_web_api() {
  if ask_yes_no "Enable web API panel?" "n"; then
    local web_addr web_port secret
    web_addr="$(input_nonempty "Web API bind address" "127.0.0.1")"
    web_port="$(input_int_range "Web API port" 1 65535 "2060")"
    port_in_use "${web_port}" && die "Web API port ${web_port} is in use."
    secret="$(input_nonempty "Web API secret" "$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)")"
    echo "${web_addr}|${web_port}|${secret}"
  else
    echo ""
  fi
}

check_port_80_hint() {
  if port_in_use 80; then
    echo -e "${YELLOW}NOTICE:${NC} Port 80 appears to be in use. Let's Encrypt standalone validation may fail."
    echo "As requested, this tool will not modify services; you can handle it manually if needed."
  else
    echo -e "${GREEN}Port 80 looks free.${NC}"
  fi
}

input_tls_if_needed() {
  local transport="$1"
  if [[ "${transport}" == "wss" || "${transport}" == "wssmux" ]]; then
    echo
    echo -e "${BOLD}TLS configuration required for:${NC} ${transport}"
    check_port_80_hint
    echo "Provide paths to existing TLS certificate and key files."
    local cert key
    while true; do
      cert="$(input_nonempty "TLS certificate path" "/etc/letsencrypt/live/yourdomain/fullchain.pem")"
      [[ -f "${cert}" ]] || { echo "File not found: ${cert}"; continue; }
      break
    done
    while true; do
      key="$(input_nonempty "TLS private key path" "/etc/letsencrypt/live/yourdomain/privkey.pem")"
      [[ -f "${key}" ]] || { echo "File not found: ${key}"; continue; }
      break
    done
    echo "${cert}|${key}"
  else
    echo ""
  fi
}

write_config_server() {
  local name="$1" transport="$2" bind_addr="$3" listen_port="$4" ports_rules="$5" web_info="$6" tls_info="$7"
  local conf; conf="$(conf_path_for "${name}")"

  local web_addr="" web_port="" secret=""
  if [[ -n "${web_info}" ]]; then
    web_addr="${web_info%%|*}"
    web_port="$(echo "${web_info}" | cut -d'|' -f2)"
    secret="$(echo "${web_info}" | cut -d'|' -f3)"
  fi

  local tls_cert="" tls_key=""
  if [[ -n "${tls_info}" ]]; then
    tls_cert="${tls_info%%|*}"
    tls_key="$(echo "${tls_info}" | cut -d'|' -f2)"
  fi

  local ports_toml="ports = ["
  while IFS= read -r r; do
    ports_toml+="\"${r}\","
  done <<< "${ports_rules}"
  ports_toml="${ports_toml%,}]"

  cat > "${conf}" <<EOF
[server]
bind_addr = "${bind_addr}:${listen_port}"
transport = "${transport}"
${ports_toml}
EOF

  if [[ -n "${web_info}" ]]; then
    cat >> "${conf}" <<EOF
web_port = ${web_port}
secret = "${secret}"
web_addr = "${web_addr}"
EOF
  fi

  if [[ -n "${tls_info}" ]]; then
    cat >> "${conf}" <<EOF
tls_cert = "${tls_cert}"
tls_key = "${tls_key}"
EOF
  fi

  chmod 600 "${conf}"
  echo "${conf}"
}

write_config_client() {
  local name="$1" transport="$2" remote_addr="$3" ws_path="$4" web_info="$5" tls_info="$6"
  local conf; conf="$(conf_path_for "${name}")"

  local web_addr="" web_port="" secret=""
  if [[ -n "${web_info}" ]]; then
    web_addr="${web_info%%|*}"
    web_port="$(echo "${web_info}" | cut -d'|' -f2)"
    secret="$(echo "${web_info}" | cut -d'|' -f3)"
  fi

  local tls_cert="" tls_key=""
  if [[ -n "${tls_info}" ]]; then
    tls_cert="${tls_info%%|*}"
    tls_key="$(echo "${tls_info}" | cut -d'|' -f2)"
  fi

  cat > "${conf}" <<EOF
[client]
remote_addr = "${remote_addr}"
transport = "${transport}"
EOF

  if [[ "${transport}" == "ws" || "${transport}" == "wss" || "${transport}" == "wsmux" || "${transport}" == "wssmux" ]]; then
    cat >> "${conf}" <<EOF
path = "${ws_path}"
EOF
  fi

  if [[ -n "${web_info}" ]]; then
    cat >> "${conf}" <<EOF
web_port = ${web_port}
secret = "${secret}"
web_addr = "${web_addr}"
EOF
  fi

  if [[ -n "${tls_info}" ]]; then
    cat >> "${conf}" <<EOF
tls_cert = "${tls_cert}"
tls_key = "${tls_key}"
EOF
  fi

  chmod 600 "${conf}"
  echo "${conf}"
}

create_tunnel() {
  [[ -x "${CORE_BIN}" ]] || die "Core is not installed. Use Install/Update first."
  ensure_dirs
  need_systemd

  print_header
  echo -e "${BOLD}Create New Tunnel${NC}"
  echo

  local name
  while true; do
    name="$(input_nonempty "Tunnel name (letters/numbers/_/-)" "tunnel1")"
    [[ "${name}" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "Invalid name. Use letters/numbers/_/- only."; continue; }
    if db_has_tunnel "${name}"; then
      echo "Tunnel '${name}' already exists."
      ask_yes_no "Overwrite existing tunnel config and service?" "n" || continue
    fi
    break
  done

  local role transport
  role="$(choose_role)"
  echo -e "Selected role: ${BOLD}${role}${NC}"
  transport="$(choose_transport)"
  echo -e "Selected transport: ${BOLD}${transport}${NC}"

  local web_info tls_info
  web_info="$(input_web_api)"
  tls_info="$(input_tls_if_needed "${transport}")"

  local conf=""
  if [[ "${role}" == "server" ]]; then
    local bind_addr listen_port ports_rules
    bind_addr="$(choose_bind_addr)"
    listen_port="$(input_server_listen_port)"
    ports_rules="$(input_ports_rules_server)"
    conf="$(write_config_server "${name}" "${transport}" "${bind_addr}" "${listen_port}" "${ports_rules}" "${web_info}" "${tls_info}")"
  else
    local remote_addr ws_path="/"
    remote_addr="$(input_client_remote_addr)"
    if [[ "${transport}" == "ws" || "${transport}" == "wss" || "${transport}" == "wsmux" || "${transport}" == "wssmux" ]]; then
      ws_path="$(input_ws_path)"
    fi
    conf="$(write_config_client "${name}" "${transport}" "${remote_addr}" "${ws_path}" "${web_info}" "${tls_info}")"
  fi

  local svc; svc="$(svc_name_for "${name}")"
  systemd_write_unit "${svc}" "${conf}"
  systemd_enable_start "${svc}"
  db_add_or_update "${name}" "${role}" "${transport}" "${conf}" "${svc}"

  echo
  echo -e "${GREEN}Tunnel created/updated:${NC} ${name}"
  echo -e "Config: ${conf}"
  echo -e "Service: ${svc} (status: $(systemd_status_line "${svc}"))"
  pause
}

list_tunnels_screen() {
  print_header
  echo -e "${BOLD}Tunnels${NC}"
  echo
  if [[ ! -s "${DB_FILE}" ]]; then
    echo "No tunnels found."
    return 0
  fi
  printf "%-20s %-8s %-8s %-30s %-20s\n" "NAME" "ROLE" "TRANS" "CONFIG" "STATUS"
  echo "------------------------------------------------------------------------------------------------------"
  while IFS='|' read -r name role trans conf svc; do
    [[ -z "${name:-}" ]] && continue
    local st; st="$(systemd_status_line "${svc}")"
    printf "%-20s %-8s %-8s %-30s %-20b\n" "${name}" "${role}" "${trans}" "$(basename "${conf}")" "${st}"
  done < "${DB_FILE}"
}

pick_tunnel() {
  list_tunnels_screen
  echo
  local name
  while true; do
    name="$(input_nonempty "Enter tunnel name" "")"
    db_has_tunnel "${name}" && { echo "${name}"; return 0; }
    echo "Tunnel not found."
  done
}

tunnel_actions() {
  ensure_dirs
  need_systemd
  print_header
  echo -e "${BOLD}Manage Tunnels${NC}"
  echo
  if [[ ! -s "${DB_FILE}" ]]; then
    echo "No tunnels found."
    pause
    return
  fi

  local tname; tname="$(pick_tunnel)"
  local line; line="$(grep -E "^${tname}\|" "${DB_FILE}" || true)"
  [[ -n "${line}" ]] || die "Internal error: tunnel record missing."
  local name role trans conf svc
  IFS='|' read -r name role trans conf svc <<< "${line}"

  while true; do
    print_header
    echo -e "${BOLD}Tunnel:${NC} ${name}"
    echo "Role: ${role}"
    echo "Transport: ${trans}"
    echo "Config: ${conf}"
    echo -e "Service: ${svc} (status: $(systemd_status_line "${svc}"))"
    echo
    echo "1) Show status (systemctl)"
    echo "2) Restart"
    echo "3) Stop"
    echo "4) Start"
    echo "5) Edit config (nano)"
    echo "6) Delete tunnel"
    echo "0) Back"
    echo
    local c; c="$(input_int_range "Choice" 0 6 "0")"
    case "${c}" in
      1) systemctl status "${svc}" --no-pager || true; pause ;;
      2) systemctl restart "${svc}" || die "Failed to restart ${svc}"; echo "Restarted."; pause ;;
      3) systemctl stop "${svc}" || die "Failed to stop ${svc}"; echo "Stopped."; pause ;;
      4) systemctl start "${svc}" || die "Failed to start ${svc}"; echo "Started."; pause ;;
      5)
        have_cmd nano || pkg_install nano || true
        ${EDITOR:-nano} "${conf}" || true
        systemctl restart "${svc}" || true
        echo "Saved. Service restarted."
        pause
        ;;
      6)
        if ask_yes_no "Delete tunnel '${name}' (service + config)?" "n"; then
          systemd_stop_disable "${svc}"
          rm -f "${SYSTEMD_DIR}/${svc}" "${conf}" || true
          systemctl daemon-reload
          db_remove "${name}"
          echo "Deleted."
          pause
          return
        fi
        ;;
      0) return ;;
    esac
  done
}

restart_all() {
  ensure_dirs
  need_systemd
  if [[ ! -s "${DB_FILE}" ]]; then
    return 0
  fi
  while IFS='|' read -r name role trans conf svc; do
    [[ -z "${name:-}" ]] && continue
    systemctl restart "${svc}" >/dev/null 2>&1 || true
  done < "${DB_FILE}"
}

restart_all_ui() {
  print_header
  echo -e "${BOLD}Restart All Tunnels${NC}"
  echo
  if [[ ! -s "${DB_FILE}" ]]; then
    echo "No tunnels found."
    pause
    return
  fi
  restart_all
  echo "Done."
  pause
}

# ---------- scheduling ----------
timer_unit_name() { echo "backhaul-manager-${1}.timer"; }
timer_svc_name() { echo "backhaul-manager-${1}.service"; }

create_schedule() {
  local kind="$1" hours="$2"

  if [[ "${kind}" == "cron" ]]; then
    local cron_line="0 */${hours} * * * root ${APP_CMD} --restart-all >/dev/null 2>&1"
    local cron_file="/etc/cron.d/backhaul-manager"
    if grep -qF "${APP_CMD} --restart-all" "${cron_file}" 2>/dev/null; then
      sed -i "s#.*${APP_CMD} --restart-all.*#${cron_line}#g" "${cron_file}"
    else
      echo "${cron_line}" > "${cron_file}"
    fi
    chmod 644 "${cron_file}"
    echo "Cron configured: restart all every ${hours} hour(s)."
    return 0
  fi

  if [[ "${kind}" == "timer" ]]; then
    local s="${SYSTEMD_DIR}/$(timer_svc_name restart-all)"
    local t="${SYSTEMD_DIR}/$(timer_unit_name restart-all)"

    cat > "${s}" <<EOF
[Unit]
Description=Backhaul Manager - Restart All Tunnels

[Service]
Type=oneshot
ExecStart=${APP_CMD} --restart-all
EOF

    cat > "${t}" <<EOF
[Unit]
Description=Backhaul Manager - Restart All Tunnels (Timer)

[Timer]
OnBootSec=5min
OnUnitActiveSec=${hours}h
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now "$(timer_unit_name restart-all)" >/dev/null
    echo "Systemd timer configured: restart all every ${hours} hour(s)."
    return 0
  fi

  if [[ "${kind}" == "health" ]]; then
    local s="${SYSTEMD_DIR}/$(timer_svc_name health-check)"
    local t="${SYSTEMD_DIR}/$(timer_unit_name health-check)"

    cat > "${s}" <<EOF
[Unit]
Description=Backhaul Manager - Health Check Tunnels

[Service]
Type=oneshot
ExecStart=${APP_CMD} --health-check
EOF

    cat > "${t}" <<EOF
[Unit]
Description=Backhaul Manager - Health Check Tunnels (Timer)

[Timer]
OnBootSec=5min
OnUnitActiveSec=${hours}h
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now "$(timer_unit_name health-check)" >/dev/null
    echo "Health-check timer configured: every ${hours} hour(s)."
    return 0
  fi

  die "Unknown schedule kind: ${kind}"
}

disable_scheduling() {
  rm -f /etc/cron.d/backhaul-manager 2>/dev/null || true
  systemctl disable --now "$(timer_unit_name restart-all)" >/dev/null 2>&1 || true
  systemctl disable --now "$(timer_unit_name health-check)" >/dev/null 2>&1 || true
  rm -f "${SYSTEMD_DIR}/$(timer_svc_name restart-all)" "${SYSTEMD_DIR}/$(timer_unit_name restart-all)" \
        "${SYSTEMD_DIR}/$(timer_svc_name health-check)" "${SYSTEMD_DIR}/$(timer_unit_name health-check)" 2>/dev/null || true
  systemctl daemon-reload
}

schedule_menu() {
  print_header
  echo -e "${BOLD}Scheduling (Restart / Health Check)${NC}"
  echo
  echo "1) Cron job (restart-all periodically)"
  echo "2) Systemd timer (restart-all periodically)  [recommended over cron]"
  echo "3) Health-check timer (restart only if a tunnel is down)  [safest]"
  echo "4) Disable scheduling (remove cron + timers)"
  echo "0) Back"
  echo
  local c; c="$(input_int_range "Choice" 0 4 "3")"
  case "${c}" in
    1) local h; h="$(input_int_range "Every how many hours?" 1 168 "6")"; create_schedule "cron" "${h}"; pause ;;
    2) local h; h="$(input_int_range "Every how many hours?" 1 168 "6")"; create_schedule "timer" "${h}"; pause ;;
    3) local h; h="$(input_int_range "Every how many hours?" 1 168 "1")"; create_schedule "health" "${h}"; pause ;;
    4) disable_scheduling; echo "Scheduling disabled."; pause ;;
    0) ;;
  esac
}

health_check() {
  ensure_dirs
  need_systemd
  [[ -s "${DB_FILE}" ]] || exit 0
  while IFS='|' read -r name role trans conf svc; do
    [[ -z "${name:-}" ]] && continue
    local st; st="$(systemctl is-active "${svc}" 2>/dev/null || true)"
    if [[ "${st}" != "active" ]]; then
      log "Health-check: ${svc} is ${st}, restarting..."
      systemctl restart "${svc}" >/dev/null 2>&1 || log "Health-check: failed to restart ${svc}"
    fi
  done < "${DB_FILE}"
}

# ---------- uninstall ----------
uninstall_all() {
  print_header
  echo -e "${BOLD}Uninstall${NC}"
  echo
  if ! ask_yes_no "This will remove Backhaul Manager, all tunnel configs, services, and scheduling. Continue?" "n"; then
    return
  fi

  if [[ -s "${DB_FILE}" ]]; then
    while IFS='|' read -r name role trans conf svc; do
      [[ -z "${name:-}" ]] && continue
      systemd_stop_disable "${svc}"
      rm -f "${SYSTEMD_DIR}/${svc}" "${conf}" 2>/dev/null || true
    done < "${DB_FILE}"
  fi

  disable_scheduling

  rm -rf "${CONF_DIR}" "${STATE_DIR}" "${LOG_DIR}" "${APP_DIR}" 2>/dev/null || true
  rm -f "${APP_SYMLINK}" 2>/dev/null || true

  if ask_yes_no "Remove core binary (${CORE_BIN}) too?" "n"; then
    rm -f "${CORE_BIN}" 2>/dev/null || true
  fi

  echo -e "${GREEN}Uninstall complete.${NC}"
  pause
}

# ---------- main menu ----------
main_menu() {
  while true; do
    print_header
    echo "1) Install / Update"
    echo "2) Create new tunnel"
    echo "3) Manage tunnels"
    echo "4) Restart all tunnels"
    echo "5) Scheduling (cron/timer/health-check)"
    echo "6) Uninstall"
    echo "0) Exit"
    echo
    local c; c="$(input_int_range "Choice" 0 6 "0")"
    case "${c}" in
      1) install_or_update; pause ;;
      2) create_tunnel ;;
      3) tunnel_actions ;;
      4) restart_all_ui ;;
      5) schedule_menu ;;
      6) uninstall_all ;;
      0) exit 0 ;;
    esac
  done
}

# ---------- CLI flags ----------
if [[ "${1:-}" == "--install" || "${1:-}" == "--update" ]]; then
  install_or_update
  exit 0
fi

if [[ "${1:-}" == "--restart-all" ]]; then
  restart_all
  exit 0
fi

if [[ "${1:-}" == "--health-check" ]]; then
  health_check
  exit 0
fi

main_menu

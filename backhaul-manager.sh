#!/usr/bin/env bash
set -Eeuo pipefail

# ==========================================
# Backhaul Manager (v1.0.0)
# Manager Repo: https://github.com/ach1992/backhaul-manager/
# Core Repo:    https://github.com/Musixal/Backhaul
# ==========================================

MANAGER_VERSION="v1.0.0"
MANAGER_REPO_URL="https://github.com/ach1992/backhaul-manager/"
CORE_REPO_URL="https://github.com/Musixal/Backhaul"
MANAGER_RAW_URL="https://raw.githubusercontent.com/ach1992/backhaul-manager/main/backhaul-manager.sh"

APP_NAME="Backhaul Manager"
APP_CMD="backhaul-manager"
APP_DIR="/opt/backhaul-manager"
APP_SCRIPT="${APP_DIR}/backhaul-manager.sh"
APP_SYMLINK="/usr/local/bin/${APP_CMD}"

CORE_BIN="/usr/local/bin/backhaul"

CONF_DIR="/etc/backhaul-manager"
TUNNELS_DIR="${CONF_DIR}/tunnels"
TLS_BASE_DIR="${TUNNELS_DIR}/.tls"
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
CORE_FALLBACK_TAG="v0.7.2"

# Colors
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[34m"; CYAN="\033[36m"; GRAY="\033[90m"; NC="\033[0m"; BOLD="\033[1m"

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

# ---------- TTY IO helpers  ----------
tty_out() { printf "%b\n" "$*" > /dev/tty; }
tty_print() { printf "%b" "$*" > /dev/tty; }
tty_readline() {
  local __var="$1"; shift
  local __tmp=""
  IFS= read -r -p "$*" __tmp < /dev/tty || true
  __tmp="${__tmp//$'\r'/}"
  printf -v "${__var}" "%s" "${__tmp}"
}

pause() { tty_readline _ "Press Enter to continue..."; }

# ---------- helpers ----------
is_root() { [[ "${EUID}" -eq 0 ]]; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }

need_systemd() { have_cmd systemctl || die "systemctl not found. This tool requires systemd."; }
os_ok() { [[ "$(uname -s)" == "Linux" ]] || die "Unsupported OS: $(uname -s). Linux required."; }

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
    apt) DEBIAN_FRONTEND=noninteractive apt-get -y install "${pkgs[@]}" >/dev/null ;;
    dnf) dnf -y install "${pkgs[@]}" >/dev/null ;;
    yum) yum -y install "${pkgs[@]}" >/dev/null ;;
    pacman) pacman -Sy --noconfirm "${pkgs[@]}" >/dev/null ;;
    *) die "No supported package manager found. Install required tools manually: ${pkgs[*]}" ;;
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
    tty_out "${YELLOW}Installing missing dependencies:${NC} ${missing[*]}"
    pkg_install "${missing[@]}" || die "Failed to install dependencies: ${missing[*]}"
  fi
}

ensure_dirs() {
  mkdir -p "${APP_DIR}" "${CONF_DIR}" "${TUNNELS_DIR}" "${TLS_BASE_DIR}" "${STATE_DIR}" "${LOG_DIR}"
  touch "${DB_FILE}"
  chmod 700 "${APP_DIR}" "${STATE_DIR}" || true
  chmod 755 "${CONF_DIR}" "${TUNNELS_DIR}" || true
  chmod 700 "${TLS_BASE_DIR}" || true
}

realpath_soft() {
  local p="$1"
  if have_cmd readlink; then readlink -f "$p" 2>/dev/null || echo "$p"; else echo "$p"; fi
}

core_version() {
  if [[ -x "${CORE_BIN}" ]]; then "${CORE_BIN}" -v 2>/dev/null || true; else echo ""; fi
}

print_header() {
  clear || true
  tty_out "${BOLD}${CYAN}================================================${NC}"
  tty_out "${BOLD}${CYAN}                 ${APP_NAME}${NC}"
  tty_out "${BOLD}${CYAN}================================================${NC}"
  tty_out "${GRAY}Manager repo:${NC} ${MANAGER_REPO_URL}"
  tty_out "${GRAY}Core repo:   ${NC} ${CORE_REPO_URL}"
  tty_out "${GRAY}Manager ver: ${NC} ${BOLD}${MANAGER_VERSION}${NC}"
  tty_out "${GRAY}Core binary: ${NC} ${CORE_BIN}  $( [[ -x "${CORE_BIN}" ]] && echo -e "${GREEN}[INSTALLED]${NC}" || echo -e "${RED}[NOT INSTALLED]${NC}" )"
  local ver; ver="$(core_version)"
  [[ -n "${ver}" ]] && tty_out "${GRAY}Core ver:    ${NC} ${BOLD}${ver}${NC}"
  tty_out ""
}

ask_yes_no() {
  local prompt="$1" default="${2:-}"
  local ans=""
  while true; do
    if [[ "${default}" == "y" ]]; then
      tty_readline ans "${prompt} [Y/n]: "
      ans="${ans:-y}"
    elif [[ "${default}" == "n" ]]; then
      tty_readline ans "${prompt} [y/N]: "
      ans="${ans:-n}"
    else
      tty_readline ans "${prompt} [y/n]: "
    fi
    case "${ans,,}" in
      y|yes) return 0 ;;
      n|no) return 1 ;;
      *) tty_out "Invalid input. Please type y or n." ;;
    esac
  done
}

input_nonempty() {
  local prompt="$1" default="${2:-}"
  local v=""
  while true; do
    if [[ -n "${default}" ]]; then
      tty_readline v "${prompt} [default: ${default}]: "
      v="${v:-$default}"
    else
      tty_readline v "${prompt}: "
    fi
    v="$(echo -n "${v}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -n "${v}" ]] && { echo "${v}"; return 0; }
    tty_out "Value cannot be empty."
  done
}

input_int_range() {
  local prompt="$1" min="$2" max="$3" default="${4:-}"
  local v=""
  while true; do
    if [[ -n "${default}" ]]; then
      tty_readline v "${prompt} (${min}-${max}) [default: ${default}]: "
      v="${v:-$default}"
    else
      tty_readline v "${prompt} (${min}-${max}): "
    fi
    [[ "${v}" =~ ^[0-9]+$ ]] || { tty_out "Please enter a number."; continue; }
    (( v >= min && v <= max )) || { tty_out "Out of range."; continue; }
    echo "${v}"
    return 0
  done
}

input_int_any() {
  local prompt="$1" default="${2:-}"
  local v=""
  while true; do
    if [[ -n "${default}" ]]; then
      tty_readline v "${prompt} [default: ${default}]: "
      v="${v:-$default}"
    else
      tty_readline v "${prompt}: "
    fi
    v="$(echo -n "${v}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ "${v}" =~ ^-?[0-9]+$ ]] || { tty_out "Please enter an integer."; continue; }
    echo "${v}"
    return 0
  done
}

input_text_allow_empty() {
  local prompt="$1" default="${2:-}"
  local v=""
  if [[ -n "${default}" ]]; then
    tty_readline v "${prompt} [default: ${default}]: "
    v="${v:-$default}"
  else
    tty_readline v "${prompt}: "
  fi
  v="$(echo -n "${v}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  echo "${v}"
}

input_bool() {
  local prompt="$1" default_bool="$2"  # "true" or "false"
  local def_char="n"
  [[ "${default_bool}" == "true" ]] && def_char="y"
  if ask_yes_no "${prompt}" "${def_char}"; then echo "true"; else echo "false"; fi
}

input_choice_log_level() {
  local def="${1:-info}"
  local v=""
  while true; do
    tty_readline v "Log level (panic/fatal/error/warn/info/debug/trace) [default: ${def}]: "
    v="${v:-$def}"
    v="${v,,}"
    case "${v}" in
      panic|fatal|error|warn|info|debug|trace) echo "${v}"; return 0 ;;
      *) tty_out "Invalid log level." ;;
    esac
  done
}

input_optional_int_or_empty() {
  local prompt="$1"
  local default="${2:-}"
  local v=""
  while true; do
    tty_readline v "${prompt} [default: ${default}]: "
    v="${v:-$default}"
    v="$(echo -n "${v}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    if [[ -z "${v}" ]]; then
      echo ""
      return 0
    fi
    [[ "${v}" =~ ^[0-9]+$ ]] || { tty_out "Please enter a number (or leave empty)."; continue; }
    echo "${v}"
    return 0
  done
}

# ---------- network validation ----------
is_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
is_domain() { [[ "$1" =~ ^([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$ ]]; }
is_ipv6() { [[ "$1" =~ ^[0-9a-fA-F:]+$ ]]; }

validate_edge_host() {
  local h="$1"
  is_ipv4 "${h}" && return 0
  is_domain "${h}" && return 0
  is_ipv6 "${h}" && return 0
  return 1
}

input_edge_host() {
  local v=""
  while true; do
    tty_readline v "Edge host (IPv4, domain, or IPv6): "
    v="$(echo -n "${v}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    validate_edge_host "${v}" && { echo "${v}"; return 0; }
    tty_out "Invalid host. Enter a valid IPv4, domain, or IPv6."
  done
}

port_in_use() {
  local port="$1"
  # Check both TCP and UDP listeners for the given port
  ss -lntup 2>/dev/null | awk '{print $4}' | grep -E "[:.]${port}\$" -q && return 0
  ss -lnup  2>/dev/null | awk '{print $4}' | grep -E "[:.]${port}\$" -q && return 0
  return 1
}

tunnel_bind_port_taken() {
  # Returns 0 if a SERVER tunnel already uses bind port $1 (excluding optional tunnel name $2)
  local p="$1"
  local ignore_name="${2:-}"
  [[ -s "$DB_FILE" ]] || return 1

  local db_name db_role db_trans db_conf db_svc
  while IFS='|' read -r db_name db_role db_trans db_conf db_svc; do
    [[ -z "${db_name:-}" ]] && continue
    [[ -n "${ignore_name}" && "${db_name}" == "${ignore_name}" ]] && continue
    [[ "${db_role}" != "server" ]] && continue
    [[ -f "${db_conf}" ]] || continue

    # Config uses bind_addr = "IP:PORT" (not bind_port). Support both for backwards compat.
    local oldp=""
    oldp="$(awk -F'=' '
      /^[[:space:]]*bind_addr[[:space:]]*=/ {
        v=$2;
        gsub(/^[[:space:]]*"/,"",v);
        gsub(/"[[:space:]]*$/,"",v);
        # extract port after last ":" (works for IPv4:port, 0.0.0.0:3080, and [IPv6]:port)
        sub(/.*:/,"",v);
        gsub(/[[:space:]]/,"",v);
        print v;
        exit
      }
      /^[[:space:]]*bind_port[[:space:]]*=/ {
        v=$2;
        gsub(/[[:space:]]/,"",v);
        gsub(/"/,"",v);
        print v;
        exit
      }' "${db_conf}" 2>/dev/null || true)"

    [[ -n "${oldp}" && "${oldp}" == "${p}" ]] && return 0
  done < "$DB_FILE"

  return 1
}


# ---------- DB ----------
db_has_tunnel() { awk -F'|' -v n="$1" '$1==n{found=1} END{exit !found}' "${DB_FILE}"; }
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
  local json tag
  json="$(curl -fsSL "${CORE_API_LATEST}")" || return 1
  tag="$(printf "%s" "${json}" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')" || true
  [[ -n "${tag}" ]] || return 1
  echo "${tag}"
}

download_core_online() {
  local asset="$1" tag="$2"
  local url="${CORE_RELEASES_URL}/download/${tag}/${asset}"
  local tmp="/tmp/${asset}"

  tty_out "${BLUE}Downloading core:${NC} ${url}"
  curl -fL --retry 3 --retry-delay 2 -o "${tmp}" "${url}" || return 1
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
    tty_out "${GREEN}Core already installed.${NC}"
    return 0
  fi

  local asset; asset="$(arch_to_asset)"

  # Offline option
  if [[ -d "${OFFLINE_DIR}" && -f "${OFFLINE_DIR}/${asset}" ]]; then
    if ask_yes_no "Offline core asset found at ${OFFLINE_DIR}/${asset}. Install core offline?" "y"; then
      tty_out "${BLUE}Installing core offline from:${NC} ${OFFLINE_DIR}/${asset}"
      install_core_from_tar "${OFFLINE_DIR}/${asset}"
      return 0
    fi
  fi

  local tag=""
  if tag="$(fetch_latest_tag)"; then
    :
  else
    tty_out "${YELLOW}WARN:${NC} Failed to fetch latest core tag from GitHub API. Falling back to ${CORE_FALLBACK_TAG}."
    tag="${CORE_FALLBACK_TAG}"
  fi

  local tarfile=""
  if tarfile="$(download_core_online "${asset}" "${tag}")"; then
    install_core_from_tar "${tarfile}"
    rm -f "${tarfile}" || true
    return 0
  fi

  if [[ "${tag}" != "${CORE_FALLBACK_TAG}" ]]; then
    tty_out "${YELLOW}WARN:${NC} Failed to download core for ${tag}. Trying fallback ${CORE_FALLBACK_TAG}..."
    if tarfile="$(download_core_online "${asset}" "${CORE_FALLBACK_TAG}")"; then
      install_core_from_tar "${tarfile}"
      rm -f "${tarfile}" || true
      return 0
    fi
  fi

  die "Failed to download/install core. Check connectivity to GitHub releases or use offline mode."
}

# ---------- self install/update ----------
ensure_manager_on_disk() {
  mkdir -p "${APP_DIR}"

  local running; running="$(realpath_soft "${BASH_SOURCE[0]:-$0}")"
  local installed; installed="$(realpath_soft "${APP_SCRIPT}")"
  if [[ -f "${APP_SCRIPT}" && "${running}" == "${installed}" ]]; then
    return 0
  fi

  local src="${BASH_SOURCE[0]:-$0}"
  local src_real; src_real="$(realpath_soft "${src}")"
  if [[ -f "${src}" && "${src_real}" != "${installed}" ]]; then
    install -m 0755 "${src}" "${APP_SCRIPT}"
    return 0
  fi

  tty_out "${BLUE}Ensuring manager script on disk (downloading from repo)...${NC}"
  local tmp="/tmp/backhaul-manager.sh.$$"
  curl -fsSL "${MANAGER_RAW_URL}" -o "${tmp}" || die "Failed to download manager script from ${MANAGER_RAW_URL}"
  install -m 0755 "${tmp}" "${APP_SCRIPT}"
  rm -f "${tmp}" || true
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

  tty_out "${GREEN}Installed command:${NC} ${APP_SYMLINK}"
  install_core
  tty_out "${GREEN}Installation complete.${NC}"
  tty_out "Run: ${BOLD}${APP_CMD}${NC}"
}

# ---------- tunnel creation ----------
choose_role() {
  tty_out ""
  tty_out "${BOLD}Select node role for this tunnel:${NC}"
  tty_out "  1) Iran (Server)   - runs server config (bind/listen + ports rules)"
  tty_out "  2) Outside (Client) - runs client config (remote_addr to server)"
  local c; c="$(input_int_range "Enter choice" 1 2 "1")"
  case "${c}" in
    1) echo "server" ;;
    2) echo "client" ;;
  esac
}

choose_transport() {
  tty_out ""
  tty_out "${BOLD}Select transport:${NC}"
  tty_out "  1) tcp"
  tty_out "  2) tcpmux"
  tty_out "  3) udp"
  tty_out "  4) ws"
  tty_out "  5) wss (TLS required)"
  tty_out "  6) wsmux"
  tty_out "  7) wssmux (TLS required)"
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

input_tunnel_port() {
  local p
  p="$(input_int_range "Tunnel port" 1 65535 "3080")"
  port_in_use "${p}" && die "Port ${p} is already in use on this system."
  echo "${p}"
}

input_ports_rules_server() {
  while true; do
    tty_out ""
    tty_out "${BOLD}Server ports rules:${NC}"
    tty_out "Examples:"
    tty_out "  443"
    tty_out "  443-600"
    tty_out "  443-600:5201"
    tty_out "  443-600=1.1.1.1:5201"
    tty_out ""
    tty_out "Enter ONE rule per line. Press Enter on an empty line to finish."
    local rules=()
    while true; do
      local line=""
      tty_readline line "> "
      line="$(echo -n "${line}" | tr -d '
' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      [[ -z "${line}" ]] && break
      if [[ ! "${line}" =~ ^[0-9]{1,5}(-[0-9]{1,5})?([:=]([0-9]{1,5}|([^=:\ ]+):[0-9]{1,5}))?$ ]]; then
        tty_out "Invalid rule format. Try again."
        continue
      fi
      rules+=("${line}")
    done

    if (( ${#rules[@]} == 0 )); then
      tty_out "${RED}ERROR:${NC} At least one ports rule is required."
      # loop again without exiting the whole script
      continue
    fi

    printf "%s
" "${rules[@]}"
    return 0
  done
}


input_web_api() {
  tty_out ""
  tty_out "${BOLD}Web panel (optional)${NC}"
  tty_out "Set the web panel port. Use 0 to disable."
  local web_port
  web_port="$(input_int_range "Web port" 0 65535 "0")"
  if (( web_port > 0 )); then
    port_in_use "${web_port}" && die "Web port ${web_port} is in use."
  fi
  echo "${web_port}"
}


check_port_80_hint() {
  if port_in_use 80; then
    tty_out "${YELLOW}NOTICE:${NC} Port 80 appears to be in use. Let's Encrypt standalone validation may fail."
    tty_out "As requested, this tool will not modify services; you can handle it manually if needed."
  else
    tty_out "${GREEN}Port 80 looks free.${NC}"
  fi
}


ensure_certbot() {
  have_cmd certbot && return 0
  tty_out "Installing certbot..."
  pkg_install certbot
}

ensure_openssl() {
  have_cmd openssl && return 0
  tty_out "Installing openssl..."
  pkg_install openssl
}

ensure_tls_for_tunnel() {
  # Creates/obtains TLS cert+key for a tunnel and stores them alongside tunnel config.
  # Supports:
  #  - Let's Encrypt (standalone, port 80 must be free)
  #  - Self-signed
  local tname="$1"

  mkdir -p "${TLS_BASE_DIR}/${tname}"
  chmod 700 "${TLS_BASE_DIR}/${tname}" || true

  local cert_out="${TLS_BASE_DIR}/${tname}/fullchain.pem"
  local key_out="${TLS_BASE_DIR}/${tname}/privkey.pem"
  local meta_out="${TLS_BASE_DIR}/${tname}/tls.meta"

  if [[ -f "${cert_out}" && -f "${key_out}" ]]; then
    if ask_yes_no "TLS files already exist for '${tname}'. Reuse them?" "y"; then
      echo "${cert_out}|${key_out}"
      return 0
    fi
    rm -f "${cert_out}" "${key_out}" "${meta_out}" || true
  fi

  while true; do
    tty_out ""
    tty_out "${BOLD}TLS required for this transport.${NC}"
    tty_out "1) Let's Encrypt (standalone, uses port 80)"
    tty_out "2) Self-signed"
    local method
    tty_readline method "Select TLS method (1-2) [default: 1]: "
    method="${method:-1}"

    if [[ "${method}" == "1" ]]; then
      local domain email
      tty_readline domain "Domain (FQDN) for Let's Encrypt: "
      domain="$(printf '%s' "$domain" | tr -d '
' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      if [[ -z "${domain}" ]]; then
        tty_out "${RED}ERROR:${NC} Domain is required for Let's Encrypt."
        continue
      fi
      tty_readline email "Email [default: admin@${domain}]: "
      email="$(printf '%s' "$email" | tr -d '
' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      email="${email:-admin@${domain}}"

      if port_in_use 80; then
        tty_out "${RED}ERROR:${NC} Port 80 is in use. Free port 80 for Let's Encrypt, or choose Self-signed."
        continue
      fi

      ensure_certbot
      if ! certbot certonly --standalone \
        -d "${domain}" \
        --non-interactive --agree-tos -m "${email}" > /dev/tty 2>&1; then
        tty_out "${RED}ERROR:${NC} certbot failed. Check DNS (A/AAAA record) and inbound port 80 reachability."
        continue
      fi

      if [[ ! -f "/etc/letsencrypt/live/${domain}/fullchain.pem" || ! -f "/etc/letsencrypt/live/${domain}/privkey.pem" ]]; then
        tty_out "${RED}ERROR:${NC} Let's Encrypt files not found after certbot run."
        continue
      fi

      cp -f "/etc/letsencrypt/live/${domain}/fullchain.pem" "${cert_out}"
      cp -f "/etc/letsencrypt/live/${domain}/privkey.pem" "${key_out}"
      chmod 600 "${key_out}" || true
      cat > "${meta_out}" <<EOF
method=letsencrypt
domain=${domain}
email=${email}
EOF


      tty_out ""
	  tty_out "${GREEN}SUCCESS:${NC} Let's Encrypt certificate issued for ${domain}"
	  tty_out "Saved TLS files:"
	  tty_out "  cert: ${cert_out}"
	  tty_out "  key : ${key_out}"
	  tty_out ""
	  
	  break

    elif [[ "${method}" == "2" ]]; then
      local cn days
      tty_readline cn "Certificate CN (domain or ip) [default: localhost]: "
      cn="$(printf '%s' "$cn" | tr -d '
' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      cn="${cn:-localhost}"
      tty_readline days "Validity days [default: 3650]: "
      days="${days:-3650}"

      ensure_openssl
      if ! openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${key_out}" \
        -out "${cert_out}" \
        -days "${days}" \
        -subj "/CN=${cn}" > /dev/tty 2>&1; then
        tty_out "${RED}ERROR:${NC} openssl self-signed generation failed."
        continue
      fi

      chmod 600 "${key_out}" || true
      cat > "${meta_out}" <<EOF
method=selfsigned
cn=${cn}
days=${days}
EOF
      break
    else
      tty_out "${RED}ERROR:${NC} Please choose 1 or 2."
      continue
    fi
  done

  if [[ ! -f "${cert_out}" || ! -f "${key_out}" ]]; then
    die "TLS generation failed."
  fi
  echo "${cert_out}|${key_out}"
}



input_tls_if_needed() {
  # Args: transport, role, tunnel_name
  local transport="$1" role="${2:-server}" tname="${3:-}"
  if [[ "${role}" != "server" ]]; then
    echo ""
    return 0
  fi
  if [[ "${transport}" == "wss" || "${transport}" == "wssmux" ]]; then
    [[ -n "${tname}" ]] || die "Internal error: tunnel name missing for TLS."
    check_port_80_hint
    ensure_tls_for_tunnel "${tname}"
  else
    echo ""
  fi
}


input_ws_path() {
  local p
  p="$(input_nonempty "WebSocket path (must start with /)" "/")"
  [[ "${p}" =~ ^/ ]] || p="/${p}"
  echo "${p}"
}

write_config_server() {
  local name="$1" transport="$2" listen_port="$3" bind_ip="$4" ports_rules="$5"
  local token="$6" accept_udp="$7" keepalive_period="$8" nodelay="$9" channel_size="${10}" heartbeat="${11}"
  local mux_con="${12}" mux_version="${13}" mux_framesize="${14}" mux_recievebuffer="${15}" mux_streambuffer="${16}"
  local sniffer="${17}" web_port="${18}" sniffer_log="${19}" log_level="${20}" skip_optz="${21}"
  local mss="${22}" so_rcvbuf="${23}" so_sndbuf="${24}" tls_info="${25}"

  local conf; conf="$(conf_path_for "${name}")"

  local tls_cert="" tls_key=""
  if [[ -n "${tls_info}" ]]; then
    tls_cert="${tls_info%%|*}"
    tls_key="$(echo "${tls_info}" | cut -d'|' -f2)"
  fi

  local ports_toml="ports = ["
  while IFS= read -r r; do ports_toml+="\"${r}\","; done <<< "${ports_rules}"
  ports_toml="${ports_toml%,}]"

  cat > "${conf}" <<EOF
[server]
bind_addr = "${bind_ip}:${listen_port}"
transport = "${transport}"
token = "${token}"
EOF

  # Transport-specific settings
  if [[ "${transport}" == "tcp" ]]; then
    echo "accept_udp = ${accept_udp}" >> "${conf}"
    echo "keepalive_period = ${keepalive_period}" >> "${conf}"
    echo "nodelay = ${nodelay}" >> "${conf}"
    echo "heartbeat = ${heartbeat}" >> "${conf}"
  elif [[ "${transport}" == "tcpmux" || "${transport}" == "wsmux" || "${transport}" == "wssmux" ]]; then
    echo "keepalive_period = ${keepalive_period}" >> "${conf}"
    echo "nodelay = ${nodelay}" >> "${conf}"
    echo "heartbeat = ${heartbeat}" >> "${conf}"
    echo "mux_con = ${mux_con}" >> "${conf}"
    echo "mux_version = ${mux_version}" >> "${conf}"
    echo "mux_framesize = ${mux_framesize}" >> "${conf}"
    echo "mux_recievebuffer = ${mux_recievebuffer}" >> "${conf}"
    echo "mux_streambuffer = ${mux_streambuffer}" >> "${conf}"
  elif [[ "${transport}" == "ws" || "${transport}" == "wss" ]]; then
    echo "keepalive_period = ${keepalive_period}" >> "${conf}"
    echo "nodelay = ${nodelay}" >> "${conf}"
    # README lists heartbeat for ws (not for wss example)
    if [[ "${transport}" == "ws" ]]; then
      echo "heartbeat = ${heartbeat}" >> "${conf}"
    fi
  elif [[ "${transport}" == "udp" ]]; then
    echo "heartbeat = ${heartbeat}" >> "${conf}"
  fi

  # Common settings (across examples)
  echo "channel_size = ${channel_size}" >> "${conf}"
  echo "sniffer = ${sniffer}" >> "${conf}"
  echo "web_port = ${web_port}" >> "${conf}"
  echo "sniffer_log = \"${sniffer_log}\"" >> "${conf}"
  echo "log_level = \"${log_level}\"" >> "${conf}"
  echo "skip_optz = ${skip_optz}" >> "${conf}"

  # TCP/TCPMux tuning (optional; empty => omit to keep system defaults)
  if [[ "${transport}" == "tcp" || "${transport}" == "tcpmux" ]]; then
    [[ -n "${mss}" ]] && echo "mss = ${mss}" >> "${conf}"
    [[ -n "${so_rcvbuf}" ]] && echo "so_rcvbuf = ${so_rcvbuf}" >> "${conf}"
    [[ -n "${so_sndbuf}" ]] && echo "so_sndbuf = ${so_sndbuf}" >> "${conf}"
  fi

  # TLS (server only)
  if [[ -n "${tls_info}" ]]; then
    cat >> "${conf}" <<EOF
tls_cert = "${tls_cert}"
tls_key = "${tls_key}"
EOF
  fi

  echo "${ports_toml}" >> "${conf}"

  chmod 600 "${conf}"
  echo "${conf}"
}



format_remote_addr() {
  local host="$1" port="$2"
  if is_ipv6 "${host}"; then
    echo "[${host}]:${port}"
  else
    echo "${host}:${port}"
  fi
}

write_config_client() {
  local name="$1" transport="$2" remote_addr="$3" edge_ip="$4"
  local token="$5" connection_pool="$6" aggressive_pool="$7" keepalive_period="$8" dial_timeout="$9"
  local nodelay="${10}" retry_interval="${11}"
  local mux_version="${12}" mux_framesize="${13}" mux_recievebuffer="${14}" mux_streambuffer="${15}"
  local sniffer="${16}" web_port="${17}" sniffer_log="${18}" log_level="${19}" skip_optz="${20}"
  local mss="${21}" so_rcvbuf="${22}" so_sndbuf="${23}"

  local conf; conf="$(conf_path_for "${name}")"

  cat > "${conf}" <<EOF
[client]
remote_addr = "${remote_addr}"
transport = "${transport}"
token = "${token}"
EOF

  if [[ "${transport}" == "ws" || "${transport}" == "wss" || "${transport}" == "wsmux" || "${transport}" == "wssmux" ]]; then
    echo "edge_ip = \"${edge_ip}\"" >> "${conf}"
  fi

  # Pools / timers depend on transport
  if [[ "${transport}" != "udp" ]]; then
    echo "connection_pool = ${connection_pool}" >> "${conf}"
    echo "aggressive_pool = ${aggressive_pool}" >> "${conf}"
    echo "keepalive_period = ${keepalive_period}" >> "${conf}"
    echo "dial_timeout = ${dial_timeout}" >> "${conf}"
    echo "retry_interval = ${retry_interval}" >> "${conf}"
    echo "nodelay = ${nodelay}" >> "${conf}"
  else
    echo "connection_pool = ${connection_pool}" >> "${conf}"
    echo "aggressive_pool = ${aggressive_pool}" >> "${conf}"
    echo "retry_interval = ${retry_interval}" >> "${conf}"
  fi

  if [[ "${transport}" == "tcpmux" || "${transport}" == "wsmux" || "${transport}" == "wssmux" ]]; then
    echo "mux_version = ${mux_version}" >> "${conf}"
    echo "mux_framesize = ${mux_framesize}" >> "${conf}"
    echo "mux_recievebuffer = ${mux_recievebuffer}" >> "${conf}"
    echo "mux_streambuffer = ${mux_streambuffer}" >> "${conf}"
  fi

  echo "sniffer = ${sniffer}" >> "${conf}"
  echo "web_port = ${web_port}" >> "${conf}"
  echo "sniffer_log = \"${sniffer_log}\"" >> "${conf}"
  echo "log_level = \"${log_level}\"" >> "${conf}"
  echo "skip_optz = ${skip_optz}" >> "${conf}"

  if [[ "${transport}" == "tcp" || "${transport}" == "tcpmux" ]]; then
    [[ -n "${mss}" ]] && echo "mss = ${mss}" >> "${conf}"
    [[ -n "${so_rcvbuf}" ]] && echo "so_rcvbuf = ${so_rcvbuf}" >> "${conf}"
    [[ -n "${so_sndbuf}" ]] && echo "so_sndbuf = ${so_sndbuf}" >> "${conf}"
  fi

  chmod 600 "${conf}"
  echo "${conf}"
}


create_tunnel() {
  [[ -x "${CORE_BIN}" ]] || die "Core is not installed. Use Install/Update first."
  ensure_dirs
  need_systemd

  print_header
  tty_out "${BOLD}Create New Tunnel${NC}"
  tty_out ""

  local name
  while true; do
    name="$(input_nonempty "Tunnel name (letters/numbers/_/-)" "tunnel1")"
    [[ "${name}" =~ ^[A-Za-z0-9_-]+$ ]] || { tty_out "Invalid name. Use letters/numbers/_/- only."; continue; }
    if db_has_tunnel "${name}"; then
      tty_out "Tunnel '${name}' already exists."
      ask_yes_no "Overwrite existing tunnel config and service?" "n" || continue
    fi
    break
  done

  local role transport
  role="$(choose_role)"
  tty_out "Selected role: ${BOLD}${role}${NC}"
  transport="$(choose_transport)"
  tty_out "Selected transport: ${BOLD}${transport}${NC}"

  local tunnel_port
  while true; do
    tunnel_port="$(input_tunnel_port)"
    if [[ "${role}" == "server" ]] && tunnel_bind_port_taken "${tunnel_port}" "${name}"; then
      tty_out "${RED}ERROR:${NC} Tunnel port ${tunnel_port} is already used by an existing tunnel."
      continue
    fi
    break
  done

  # Common defaults (per Backhaul docs), with your overrides:
  # keepalive_period default => 15 (instead of 75)
  # heartbeat default => 10 (instead of 40/20)
  local def_keepalive="15"
  local def_heartbeat="10"

  local token_default; token_default="$( (set +o pipefail; LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16) 2>/dev/null )"
  [[ -n "${token_default}" ]] || token_default="$(date +%s%N | sha256sum | awk '{print $1}' | cut -c1-16)"

  local web_port tls_info
  web_port="$(input_web_api)"

  if [[ "${role}" == "server" ]]; then
    tls_info="$(input_tls_if_needed "${transport}" "server" "${name}")"
    local bind_ip; bind_ip="$(input_nonempty "Server bind IP" "0.0.0.0")"

	local ports_rules; ports_rules="$(input_ports_rules_server || true)"
	while [[ -z "${ports_rules//$'\n'/}" ]]; do
      tty_out "${RED}ERROR:${NC} At least one ports rule is required."
      ports_rules="$(input_ports_rules_server || true)"
	done

    # --- Ask ALL relevant server options ---
    local token accept_udp keepalive_period nodelay channel_size heartbeat
    local mux_con mux_version mux_framesize mux_recievebuffer mux_streambuffer
    local sniffer sniffer_log log_level skip_optz
    local mss so_rcvbuf so_sndbuf

    token="$(input_nonempty "Token (shared secret)" "${token_default}")"

    accept_udp="false"
    if [[ "${transport}" == "tcp" ]]; then
      accept_udp="$(input_bool "accept_udp (transfer UDP over TCP)?" "false")"
    fi

    keepalive_period="${def_keepalive}"
    if [[ "${transport}" != "udp" ]]; then
      keepalive_period="$(input_int_range "keepalive_period (seconds)" 1 86400 "${def_keepalive}")"
    fi

    nodelay="$(input_bool "nodelay (TCP_NODELAY)?" "true")"
    channel_size="$(input_int_range "channel_size" 1 1048576 "2048")"

    heartbeat="${def_heartbeat}"
    if [[ "${transport}" == "udp" ]]; then
      heartbeat="$(input_int_range "heartbeat (seconds)" 1 86400 "${def_heartbeat}")"
    else
      heartbeat="$(input_int_range "heartbeat (seconds)" 1 86400 "${def_heartbeat}")"
    fi

    mux_con="8"; mux_version="1"; mux_framesize="32768"; mux_recievebuffer="4194304"; mux_streambuffer="65536"
    if [[ "${transport}" == "tcpmux" || "${transport}" == "wsmux" || "${transport}" == "wssmux" ]]; then
      mux_con="$(input_int_range "mux_con" 1 1024 "8")"
      mux_version="$(input_int_range "mux_version (1 or 2)" 1 2 "1")"
      mux_framesize="$(input_int_range "mux_framesize" 1024 1048576 "32768")"
      mux_recievebuffer="$(input_int_range "mux_recievebuffer" 1024 1073741824 "4194304")"
      mux_streambuffer="$(input_int_range "mux_streambuffer" 1024 1073741824 "65536")"
    fi

    sniffer="$(input_bool "sniffer (enable traffic sniffing)?" "false")"
    sniffer_log="$(input_nonempty "sniffer_log path" "/root/backhaul.json")"
    log_level="$(input_choice_log_level "info")"
    skip_optz="$(input_bool "skip_optz (disable optimizations)?" "false")"

    mss=""; so_rcvbuf=""; so_sndbuf=""
    if [[ "${transport}" == "tcp" || "${transport}" == "tcpmux" ]]; then
      tty_out ""
      tty_out "${BOLD}TCP/TCPMux tuning (leave empty to keep system defaults)${NC}"
      mss="$(input_optional_int_or_empty "mss (bytes)" "")"
      so_rcvbuf="$(input_optional_int_or_empty "so_rcvbuf (bytes)" "")"
      so_sndbuf="$(input_optional_int_or_empty "so_sndbuf (bytes)" "")"
    fi

    local conf
    conf="$(write_config_server "${name}" "${transport}" "${tunnel_port}" "${bind_ip}" "${ports_rules}" \
      "${token}" "${accept_udp}" "${keepalive_period}" "${nodelay}" "${channel_size}" "${heartbeat}" \
      "${mux_con}" "${mux_version}" "${mux_framesize}" "${mux_recievebuffer}" "${mux_streambuffer}" \
      "${sniffer}" "${web_port}" "${sniffer_log}" "${log_level}" "${skip_optz}" \
      "${mss}" "${so_rcvbuf}" "${so_sndbuf}" "${tls_info}")"

    local svc; svc="$(svc_name_for "${name}")"
    systemd_write_unit "${svc}" "${conf}"
    systemd_enable_start "${svc}"
    db_add_or_update "${name}" "${role}" "${transport}" "${conf}" "${svc}"

    tty_out ""
    tty_out "${GREEN}Tunnel created/updated:${NC} ${name}"
    tty_out "Config: ${conf}"
    tty_out "Service: ${svc} (status: $(systemd_status_line "${svc}"))"
    pause
    return 0
  fi

  # --- client ---
  tls_info=""  # no client TLS fields in upstream docs
  local edge_host remote_addr
  tty_out ""
  tty_out "${BOLD}Client remote setup:${NC}"
  tty_out "Enter the public Edge host of the server (IPv4/domain/IPv6)."
  edge_host="$(input_edge_host)"
  remote_addr="$(format_remote_addr "${edge_host}" "${tunnel_port}")"

  # --- Ask ALL relevant client options ---
  local edge_ip token connection_pool aggressive_pool keepalive_period dial_timeout retry_interval nodelay
  local mux_version mux_framesize mux_recievebuffer mux_streambuffer
  local sniffer sniffer_log log_level skip_optz
  local mss so_rcvbuf so_sndbuf

  edge_ip=""
  if [[ "${transport}" == "ws" || "${transport}" == "wss" || "${transport}" == "wsmux" || "${transport}" == "wssmux" ]]; then
    edge_ip="$(input_text_allow_empty "edge_ip (CDN edge IP; empty allowed)" "")"
  fi

  token="$(input_nonempty "Token (must match server)" "${token_default}")"
  connection_pool="$(input_int_range "connection_pool" 1 65535 "8")"
  aggressive_pool="$(input_bool "aggressive_pool?" "false")"

  keepalive_period="${def_keepalive}"
  dial_timeout="10"
  retry_interval="3"
  nodelay="true"

  if [[ "${transport}" != "udp" ]]; then
    keepalive_period="$(input_int_range "keepalive_period (seconds)" 1 86400 "${def_keepalive}")"
    dial_timeout="$(input_int_range "dial_timeout (seconds)" 1 86400 "10")"
    retry_interval="$(input_int_range "retry_interval (seconds)" 1 86400 "3")"
    nodelay="$(input_bool "nodelay (TCP_NODELAY)?" "true")"
  else
    retry_interval="$(input_int_range "retry_interval (seconds)" 1 86400 "3")"
  fi

  mux_version="1"; mux_framesize="32768"; mux_recievebuffer="4194304"; mux_streambuffer="65536"
  if [[ "${transport}" == "tcpmux" || "${transport}" == "wsmux" || "${transport}" == "wssmux" ]]; then
    mux_version="$(input_int_range "mux_version (1 or 2)" 1 2 "1")"
    mux_framesize="$(input_int_range "mux_framesize" 1024 1048576 "32768")"
    mux_recievebuffer="$(input_int_range "mux_recievebuffer" 1024 1073741824 "4194304")"
    mux_streambuffer="$(input_int_range "mux_streambuffer" 1024 1073741824 "65536")"
  fi

  sniffer="$(input_bool "sniffer (enable traffic sniffing)?" "false")"
  sniffer_log="$(input_nonempty "sniffer_log path" "/root/backhaul.json")"
  log_level="$(input_choice_log_level "info")"
  skip_optz="$(input_bool "skip_optz (disable optimizations)?" "false")"

  mss=""; so_rcvbuf=""; so_sndbuf=""
  if [[ "${transport}" == "tcp" || "${transport}" == "tcpmux" ]]; then
    tty_out ""
    tty_out "${BOLD}TCP/TCPMux tuning (leave empty to keep system defaults)${NC}"
    mss="$(input_optional_int_or_empty "mss (bytes)" "")"
    so_rcvbuf="$(input_optional_int_or_empty "so_rcvbuf (bytes)" "")"
    so_sndbuf="$(input_optional_int_or_empty "so_sndbuf (bytes)" "")"
  fi

  local conf
  conf="$(write_config_client "${name}" "${transport}" "${remote_addr}" "${edge_ip}" \
    "${token}" "${connection_pool}" "${aggressive_pool}" "${keepalive_period}" "${dial_timeout}" \
    "${nodelay}" "${retry_interval}" \
    "${mux_version}" "${mux_framesize}" "${mux_recievebuffer}" "${mux_streambuffer}" \
    "${sniffer}" "${web_port}" "${sniffer_log}" "${log_level}" "${skip_optz}" \
    "${mss}" "${so_rcvbuf}" "${so_sndbuf}")"

  local svc; svc="$(svc_name_for "${name}")"
  systemd_write_unit "${svc}" "${conf}"
  systemd_enable_start "${svc}"
  db_add_or_update "${name}" "${role}" "${transport}" "${conf}" "${svc}"

  tty_out ""
  tty_out "${GREEN}Tunnel created/updated:${NC} ${name}"
  tty_out "Config: ${conf}"
  tty_out "Service: ${svc} (status: $(systemd_status_line "${svc}"))"
  pause
}


# ---------- management ----------
list_tunnels_screen() {
  tty_out "${BOLD}Tunnels${NC}"
  tty_out ""
  if [[ ! -s "${DB_FILE}" ]]; then
    tty_out "No tunnels found."
    return 0
  fi
  printf "%-4s %-20s %-8s %-8s %-30s %-20s\n" "NO" "NAME" "ROLE" "TRANS" "CONFIG" "STATUS" > /dev/tty
  tty_out "---------------------------------------------------------------------------------------------------------------"
  local i=0
  while IFS='|' read -r name role trans conf svc; do
    [[ -z "${name:-}" ]] && continue
    ((++i))
    local st; st="$(systemd_status_line "${svc}")"
    printf "%-4s %-20s %-8s %-8s %-30s %-20b\n" "${i}" "${name}" "${role}" "${trans}" "$(basename "${conf}")" "${st}" > /dev/tty
  done < "${DB_FILE}"
}


pick_tunnel() {
  list_tunnels_screen
  tty_out ""
  local count; count="$(awk -F'|' 'NF>=1 && $1!="" {c++} END{print c+0}' "${DB_FILE}")"
  (( count > 0 )) || { echo ""; return 0; }

  local n=""
  while true; do
    tty_readline n "Enter tunnel number [default: 0=Back]: "
    n="${n:-0}"
    [[ "${n}" =~ ^[0-9]+$ ]] || { tty_out "Please enter a number."; continue; }
    if (( n == 0 )); then
      echo ""
      return 0
    fi
    if (( n < 1 || n > count )); then
      tty_out "Out of range (1-${count})"
      continue
    fi
    local name
    name="$(awk -F'|' -v idx="${n}" 'NF>=1 && $1!="" {c++; if(c==idx){print $1; exit}}' "${DB_FILE}")"
    [[ -n "${name}" ]] && { echo "${name}"; return 0; }
    tty_out "Tunnel not found."
  done
}


tunnel_actions() {
  ensure_dirs
  need_systemd
  print_header
  tty_out "${BOLD}Manage Tunnels${NC}"
  tty_out ""
  if [[ ! -s "${DB_FILE}" ]]; then
    tty_out "No tunnels found."
    pause
    return 0
  fi

  local tname; tname="$(pick_tunnel)"
  tname="$(printf '%s' "$tname" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [[ -n "${tname}" ]] || return 0
  local line; line="$(awk -F'|' -v n="${tname}" '{ gsub(/\r/,"",$1); if ($1==n) { print; exit } }' "${DB_FILE}")"
  [[ -n "${line}" ]] || die "Internal error: tunnel record missing."
  local name role trans conf svc
  IFS='|' read -r name role trans conf svc <<< "${line}"

  while true; do
    print_header
    tty_out "${BOLD}Tunnel:${NC} ${name}"
    tty_out "Role: ${role}"
    tty_out "Transport: ${trans}"
    tty_out "Config: ${conf}"
    tty_out "Service: ${svc} (status: $(systemd_status_line "${svc}"))"
    tty_out ""
    tty_out "1) Show status (systemctl)"
    tty_out "2) Restart"
    tty_out "3) Stop"
    tty_out "4) Start"
    tty_out "5) Edit config (nano)"
    tty_out "6) Delete tunnel"
    tty_out "0) Back"
    tty_out ""
    local c; c="$(input_int_range "Choice" 0 6 "0")"
    case "${c}" in
      1) systemctl status "${svc}" --no-pager || true; pause ;;
      2) systemctl restart "${svc}" || die "Failed to restart ${svc}"; tty_out "Restarted."; pause ;;
      3) systemctl stop "${svc}" || die "Failed to stop ${svc}"; tty_out "Stopped."; pause ;;
      4) systemctl start "${svc}" || die "Failed to start ${svc}"; tty_out "Started."; pause ;;
      5)
        have_cmd nano || pkg_install nano || true
        ${EDITOR:-nano} "${conf}" || true
        systemctl restart "${svc}" || true
        tty_out "Saved. Service restarted."
        pause
        ;;
      6)
        if ask_yes_no "Delete tunnel '${name}' (service + config)?" "n"; then
          systemd_stop_disable "${svc}"
          rm -f "${SYSTEMD_DIR}/${svc}" "${conf}" || true
          rm -rf "${TLS_BASE_DIR}/${name}" || true
          systemctl daemon-reload
          db_remove "${name}"
          tty_out "Deleted."
          pause
          return 0
        fi
        ;;
      0) return 0 ;;
    esac
  done
}

restart_all() {
  ensure_dirs
  need_systemd
  [[ -s "${DB_FILE}" ]] || return 0

  # Output format (TSV):
  # name<TAB>service<TAB>restart_exit<TAB>active_state
  while IFS='|' read -r name role trans conf svc; do
    [[ -z "${name:-}" ]] && continue

    local rc=0
    systemctl restart "${svc}" >/dev/null 2>&1 || rc=$?
    local st; st="$(systemctl is-active "${svc}" 2>/dev/null || true)"
    echo -e "${name}	${svc}	${rc}	${st}"
  done < "${DB_FILE}"
}

restart_all_ui() {
  print_header
  tty_out "${BOLD}Restart All Tunnels${NC}"
  tty_out ""

  if [[ ! -s "${DB_FILE}" ]]; then
    tty_out "No tunnels found."
    pause
    return
  fi

  tty_out "${BOLD}Results:${NC}"
  tty_out "  ${GRAY}NAME${NC}         ${GRAY}SERVICE${NC}                         ${GRAY}RESTART${NC}    ${GRAY}STATE${NC}"
  tty_out "  ------------------------------------------------------------------------------"

  local any_fail=0
  while IFS=$'	' read -r name svc rc st; do
    local restart_label state_label

    if [[ "${rc}" == "0" ]]; then
      restart_label="${GREEN}OK${NC}"
    else
      restart_label="${RED}FAIL(${rc})${NC}"
      any_fail=1
    fi

    if [[ "${st}" == "active" ]]; then
      state_label="${GREEN}${st}${NC}"
    else
      state_label="${YELLOW}${st}${NC}"
      any_fail=1
    fi

    tty_out "$(printf '  %-12s %-34s %-10b %-10b' "${name}" "${svc}" "${restart_label}" "${state_label}")"
  done < <(restart_all)

  tty_out ""
  if (( any_fail == 0 )); then
    tty_out "${GREEN}All tunnels restarted successfully.${NC}"
  else
    tty_out "${YELLOW}Some tunnels did not restart cleanly.${NC} Use 'Manage tunnels' -> 'Show status' for details.${NC}"
  fi
  pause
}


# ---------- scheduling (global) ----------
timer_unit_name() { echo "backhaul-manager-${1}.timer"; }
timer_svc_name() { echo "backhaul-manager-${1}.service"; }

show_scheduling_status() {
  print_header
  tty_out "${BOLD}Scheduling Status${NC}"
  tty_out ""

  # ---- cron ----
  if [[ -f /etc/cron.d/backhaul-manager ]]; then
    tty_out "${BOLD}Cron:${NC} ${GREEN}enabled${NC}  ${GRAY}(/etc/cron.d/backhaul-manager)${NC}"
    sed 's/^/  /' /etc/cron.d/backhaul-manager > /dev/tty || true
  else
    tty_out "${BOLD}Cron:${NC} ${YELLOW}(none)${NC}"
  fi

  tty_out ""
  tty_out "${BOLD}Systemd timers:${NC}"
																															 
																																		
	  
					  
	

  local timers=()
  timers+=("$(timer_unit_name restart-all)")
  timers+=("$(timer_unit_name health-check)")

  local any=0
  for u in "${timers[@]}"; do
    if systemctl status "${u}" --no-pager >/dev/null 2>&1; then
      any=1
      break
    fi
  done

  if [[ "${any}" -eq 0 ]]; then
    tty_out "  ${YELLOW}(none)${NC}"
  else
    tty_out "  ${BOLD}NAME${NC}                           ${BOLD}ENABLED${NC}    ${BOLD}ACTIVE${NC}     ${BOLD}NEXT${NC}                        ${BOLD}LAST${NC}"
    tty_out "  -------------------------------------------------------------------------------"
    for u in "${timers[@]}"; do
      if ! systemctl status "${u}" --no-pager >/dev/null 2>&1; then
        tty_out "  ${u}  ${YELLOW}not-installed${NC}"
        continue
      fi

      local st act next last stc actc
      st="$(systemctl is-enabled "${u}" 2>/dev/null || true)"
      act="$(systemctl is-active "${u}" 2>/dev/null || true)"
      next="$(systemctl show "${u}" -p NextElapseUSecRealtime --value 2>/dev/null || true)"
      last="$(systemctl show "${u}" -p LastTriggerUSec --value 2>/dev/null || true)"

      [[ -z "${next}" ]] && next="n/a"
      [[ -z "${last}" ]] && last="n/a"

      stc="$(badge_enabled "${st}")"
      actc="$(badge_active "${act}")"

      # Keep columns readable even with ANSI colors (values are short).
      printf "  %-30s  %-10b  %-10b  %-26s  %-26s
"         "${u}" "${stc}" "${actc}" "${next}" "${last}" > /dev/tty
    done
  fi

  tty_out ""
  tty_out "${GRAY}Tip:${NC} if NEXT shows ${BOLD}n/a${NC}, the timer has no upcoming trigger (bad schedule or missing OnCalendar/OnUnit*). Recreate it from the Scheduling menu."
  tty_out ""
  pause
}

create_schedule() {
  local kind="$1" minutes="$2"


  # Normalize minutes (avoid invalid/empty values that make systemd timers show Trigger=n/a)
  if [[ -z "${minutes:-}" || ! "${minutes}" =~ ^[0-9]+$ || "${minutes}" -lt 1 ]]; then
    minutes=5
  fi


  if [[ "${kind}" == "cron" ]]; then
    local cron_file="/etc/cron.d/backhaul-manager"
    local cron_line=""
    if (( minutes <= 59 )); then
      cron_line="*/${minutes} * * * * root ${APP_CMD} --restart-all >/dev/null 2>&1"
    elif (( minutes % 60 == 0 )); then
      local hours=$(( minutes / 60 ))
      cron_line="0 */${hours} * * * root ${APP_CMD} --restart-all >/dev/null 2>&1"
    else
      die "Cron cannot reliably schedule every ${minutes} minutes. Use the systemd timer option instead."
    fi

    if grep -qF "${APP_CMD} --restart-all" "${cron_file}" 2>/dev/null; then
      sed -i "s#.*${APP_CMD} --restart-all.*#${cron_line}#g" "${cron_file}"
    else
      echo "${cron_line}" > "${cron_file}"
    fi
    chmod 644 "${cron_file}"
    tty_out "Cron configured: restart all every ${minutes} minute(s)."
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
Unit=$(timer_svc_name restart-all)
OnBootSec=5min
OnCalendar=*:0/${minutes}
Persistent=true
AccuracySec=1min
RandomizedDelaySec=0

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now "$(timer_unit_name restart-all)" >/dev/null
    tty_out "Systemd timer configured: restart all every ${minutes} minute(s)."
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
Unit=$(timer_svc_name health-check)
OnBootSec=5min
OnCalendar=*:0/${minutes}
Persistent=true
AccuracySec=1min
RandomizedDelaySec=0

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now "$(timer_unit_name health-check)" >/dev/null
    tty_out "Health-check timer configured: every ${minutes} minute(s)."
    return 0
  fi

  die "Unknown schedule kind: ${kind}"
}


disable_scheduling() {
  rm -f /etc/cron.d/backhaul-manager 2>/dev/null || true

  # Stop & disable timers/services (ignore errors if not installed)
  for u in "$(timer_unit_name restart-all)" "$(timer_unit_name health-check)"; do
    systemctl stop "$u" >/dev/null 2>&1 || true
    systemctl disable "$u" >/dev/null 2>&1 || true
    systemctl reset-failed "$u" >/dev/null 2>&1 || true
  done
  for s in "$(timer_svc_name restart-all)" "$(timer_svc_name health-check)"; do
    systemctl stop "$s" >/dev/null 2>&1 || true
    systemctl disable "$s" >/dev/null 2>&1 || true
    systemctl reset-failed "$s" >/dev/null 2>&1 || true
  done

  # Remove unit files
  rm -f "${SYSTEMD_DIR}/$(timer_svc_name restart-all)" "${SYSTEMD_DIR}/$(timer_unit_name restart-all)" \
        "${SYSTEMD_DIR}/$(timer_svc_name health-check)" "${SYSTEMD_DIR}/$(timer_unit_name health-check)" 2>/dev/null || true

  # Remove wants symlinks if they linger
  rm -f "${SYSTEMD_DIR}/timers.target.wants/$(timer_unit_name restart-all)" \
        "${SYSTEMD_DIR}/timers.target.wants/$(timer_unit_name health-check)" 2>/dev/null || true

  systemctl daemon-reload
}

schedule_menu() {
  print_header
  tty_out "${BOLD}Scheduling (Restart / Health Check)${NC}"
  tty_out ""
  tty_out "1) Show scheduling status (cron + timers)"
  tty_out "2) Cron job (restart-all periodically)"
  tty_out "3) Systemd timer (restart-all periodically)  [recommended over cron]"
  tty_out "4) Health-check timer (restart only if a tunnel is down)  [safest]"
  tty_out "5) Disable scheduling (remove cron + timers)"
  tty_out "0) Back"
  tty_out ""
  local c; c="$(input_int_range "Choice" 0 5 "1")"
  case "${c}" in
    1) show_scheduling_status ;;
    2) local m; m="$(input_int_range "Every how many minutes?" 1 10080 "360")"; create_schedule "cron" "${m}"; pause ;;
    3) local m; m="$(input_int_range "Every how many minutes?" 1 10080 "360")"; create_schedule "timer" "${m}"; pause ;;
    4) local m; m="$(input_int_range "Every how many minutes?" 1 10080 "60")"; create_schedule "health" "${m}"; pause ;;
    5) disable_scheduling; tty_out "Scheduling disabled."; pause ;;
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
  tty_out "${BOLD}Uninstall${NC}"
  tty_out ""
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

  tty_out "${GREEN}Uninstall complete.${NC}"
  pause
}

# ---------- main menu ----------
main_menu() {
  while true; do
    print_header
    tty_out "1) Install / Update"
    tty_out "2) Create new tunnel"
    tty_out "3) Manage tunnels"
    tty_out "4) Restart all tunnels"
    tty_out "5) Scheduling (cron/timer/health-check)"
    tty_out "6) Uninstall"
    tty_out "0) Exit"
    tty_out ""
    local c; c="$(input_int_range "Choice" 0 6 "")"
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

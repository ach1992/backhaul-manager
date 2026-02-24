#!/usr/bin/env bash
# Backhaul Manager - single-file installer + management menu
# Core repo: https://github.com/Musixal/Backhaul

set -u
export LC_ALL=C

########################################
# Constants
########################################
MANAGER_NAME="Backhaul Manager"
MANAGER_CMD="backhaul-manager"
MANAGER_INSTALL_PATH="/usr/local/bin/${MANAGER_CMD}"

CORE_REPO="Musixal/Backhaul"
CORE_BIN_NAME="backhaul"
CORE_INSTALL_PATH="/usr/local/bin/${CORE_BIN_NAME}"

BASE_DIR="/etc/backhaul-manager"
TUNNELS_DIR="${BASE_DIR}/tunnels"
SSL_DIR="${BASE_DIR}/ssl"
LOG_DIR="/var/log/backhaul-manager"

SYSTEMD_TEMPLATE="/etc/systemd/system/backhaul@.service"

# Health-check (systemd timer)
HEALTH_SERVICE="/etc/systemd/system/backhaul-manager-health.service"
HEALTH_TIMER="/etc/systemd/system/backhaul-manager-health.timer"

# Optional periodic restart via cron (keep it)
CRON_FILE="/etc/cron.d/backhaul-manager"

# Offline install folder
OFFLINE_DIR="/root/backhaul-manager"

########################################
# UI helpers
########################################
UI_MODE="auto" # whiptail | text
HAS_WHIPTAIL=0

red(){ printf "\033[31m%s\033[0m\n" "$*"; }
grn(){ printf "\033[32m%s\033[0m\n" "$*"; }
ylw(){ printf "\033[33m%s\033[0m\n" "$*"; }

die(){
  red "ERROR: $*"
  exit 1
}

need_root(){
  if [[ "${EUID}" -ne 0 ]]; then
    die "This script must be run as root. Use: sudo"
  fi
}

cmd_exists(){ command -v "$1" >/dev/null 2>&1; }

init_ui(){
  if cmd_exists whiptail; then
    HAS_WHIPTAIL=1
    UI_MODE="whiptail"
  else
    HAS_WHIPTAIL=0
    UI_MODE="text"
  fi
}

ui_msg(){
  local title="${1:-$MANAGER_NAME}"
  local msg="${2:-}"
  if [[ "$UI_MODE" == "whiptail" ]]; then
    whiptail --title "$title" --msgbox "$msg" 12 78
  else
    echo "== $title =="
    echo "$msg"
    echo
    read -r -p "Press Enter to continue..."
  fi
}

ui_yesno(){
  local title="${1:-$MANAGER_NAME}"
  local msg="${2:-}"
  if [[ "$UI_MODE" == "whiptail" ]]; then
    whiptail --title "$title" --yesno "$msg" 12 78
    return $?
  else
    echo "== $title =="
    echo "$msg"
    while true; do
      read -r -p "y/n: " ans
      case "${ans,,}" in
        y|yes) return 0 ;;
        n|no) return 1 ;;
      esac
    done
  fi
}

ui_input(){
  local title="${1:-$MANAGER_NAME}"
  local prompt="${2:-}"
  local default="${3:-}"
  local out=""
  if [[ "$UI_MODE" == "whiptail" ]]; then
    out="$(whiptail --title "$title" --inputbox "$prompt" 12 78 "$default" 3>&1 1>&2 2>&3)" || return 1
    printf "%s" "$out"
  else
    read -r -p "$prompt [$default]: " out
    if [[ -z "$out" ]]; then out="$default"; fi
    printf "%s" "$out"
  fi
}

ui_menu(){
  local title="$1"; shift
  local prompt="$1"; shift
  if [[ "$UI_MODE" == "whiptail" ]]; then
    whiptail --title "$title" --menu "$prompt" 20 86 12 "$@" 3>&1 1>&2 2>&3
  else
    echo "== $title =="
    echo "$prompt"
    while [[ $# -gt 0 ]]; do
      printf "  %s) %s\n" "$1" "$2"
      shift 2
    done
    local sel=""
    read -r -p "Select: " sel
    printf "%s" "$sel"
  fi
}

ui_text(){
  local title="${1:-$MANAGER_NAME}"
  local msg="${2:-}"
  if [[ "$UI_MODE" == "whiptail" ]]; then
    whiptail --title "$title" --msgbox "$msg" 20 86
  else
    echo "== $title =="
    echo "$msg"
    echo
    read -r -p "Press Enter to continue..."
  fi
}

########################################
# Package manager helpers
########################################
detect_arch(){
  local m
  m="$(uname -m)"
  case "$m" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *)
      die "Unsupported architecture: $m (supported: amd64/arm64)"
      ;;
  esac
}

detect_pm(){
  if cmd_exists apt-get; then echo "apt"
  elif cmd_exists dnf; then echo "dnf"
  elif cmd_exists yum; then echo "yum"
  elif cmd_exists apk; then echo "apk"
  elif cmd_exists pacman; then echo "pacman"
  else echo "unknown"
  fi
}

pm_install(){
  local pkg="$1"
  local pm
  pm="$(detect_pm)"
  case "$pm" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get -y install "$pkg" >/dev/null 2>&1 ;;
    dnf) dnf -y install "$pkg" >/dev/null 2>&1 ;;
    yum) yum -y install "$pkg" >/dev/null 2>&1 ;;
    apk) apk add --no-cache "$pkg" >/dev/null 2>&1 ;;
    pacman) pacman -Sy --noconfirm "$pkg" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

ensure_cmd(){
  local c="$1"
  local pkg="${2:-$1}"
  if cmd_exists "$c"; then
    return 0
  fi
  ylw "Installing dependency: $pkg"
  pm_install "$pkg" || die "Failed to install dependency: $pkg. Please install it manually."
}

ensure_prereqs(){
  # No full system upgrade. Only install missing packages.
  ensure_cmd tar tar
  ensure_cmd systemctl systemd
  # Download tool
  if ! cmd_exists curl && ! cmd_exists wget; then
    pm_install curl >/dev/null 2>&1 || pm_install wget >/dev/null 2>&1 || die "Neither curl nor wget is available and installation failed."
  fi
  # UI (optional)
  if ! cmd_exists whiptail; then
    pm_install whiptail >/dev/null 2>&1 || pm_install newt >/dev/null 2>&1 || true
  fi
  # Port check
  pm_install iproute2 >/dev/null 2>&1 || true
  # OpenSSL for cert generation
  pm_install openssl >/dev/null 2>&1 || true
}

########################################
# Download helpers
########################################
download_file(){
  local url="$1"
  local out="$2"
  if cmd_exists curl; then
    curl -fsSL "$url" -o "$out"
  else
    wget -qO "$out" "$url"
  fi
}

github_latest_release_json(){
  local tmp="/tmp/backhaul_latest_release.json"
  download_file "https://api.github.com/repos/${CORE_REPO}/releases/latest" "$tmp" || die "Cannot reach GitHub API (releases/latest)."
  echo "$tmp"
}

extract_latest_tag(){
  local json="$1"
  # "tag_name": "v0.7.2"
  grep -m1 -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"]+"' "$json" | sed -E 's/.*"([^"]+)".*/\1/'
}

extract_download_url(){
  local json="$1"
  local arch="$2"
  grep -oE "https://[^\"]+backhaul_linux_${arch}\.tar\.gz" "$json" | head -n1
}

########################################
# Paths / system
########################################
safe_mkdir(){
  local d="$1"
  [[ -d "$d" ]] || mkdir -p "$d"
}

install_system_layout(){
  safe_mkdir "$BASE_DIR"
  safe_mkdir "$TUNNELS_DIR"
  safe_mkdir "$SSL_DIR"
  safe_mkdir "$LOG_DIR"
  chmod 700 "$BASE_DIR" "$TUNNELS_DIR" "$SSL_DIR" >/dev/null 2>&1 || true
}

systemd_reload(){
  systemctl daemon-reload >/dev/null 2>&1 || true
}

########################################
# Core installed/version/update
########################################
core_installed(){
  [[ -x "$CORE_INSTALL_PATH" ]]
}

core_version_raw(){
  if core_installed; then
    "$CORE_INSTALL_PATH" -v 2>/dev/null | tr -d '\r' || true
  else
    echo ""
  fi
}

core_version_tag_guess(){
  # best-effort extraction of vX.Y.Z from -v output
  local v
  v="$(core_version_raw)"
  echo "$v" | grep -oE 'v?[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1
}

install_core_from_tgz(){
  local tgz="$1"
  [[ -f "$tgz" ]] || die "Archive not found: $tgz"
  local tmpdir="/tmp/backhaul_extract_$$"
  rm -rf "$tmpdir" && mkdir -p "$tmpdir"
  tar -xzf "$tgz" -C "$tmpdir" || die "Failed to extract: $tgz"
  [[ -f "${tmpdir}/backhaul" ]] || die "Binary 'backhaul' not found in archive."
  install -m 0755 "${tmpdir}/backhaul" "$CORE_INSTALL_PATH" || die "Failed to install core binary to $CORE_INSTALL_PATH"
  rm -rf "$tmpdir"
}

install_core_offline_if_possible(){
  local arch="$1"
  local tgz="${OFFLINE_DIR}/backhaul_linux_${arch}.tar.gz"
  if [[ -d "$OFFLINE_DIR" && -f "$tgz" ]]; then
    if ui_yesno "$MANAGER_NAME" "Offline package found at:\n${tgz}\n\nInstall core from offline package?"; then
      install_core_from_tgz "$tgz"
      return 0
    fi
  fi
  return 1
}

install_or_update_core_online(){
  local arch="$1"
  local json tag url
  json="$(github_latest_release_json)"
  tag="$(extract_latest_tag "$json")"
  [[ -n "$tag" ]] || die "Failed to parse latest release tag."
  url="$(extract_download_url "$json" "$arch")"
  [[ -n "$url" ]] || die "Failed to find download URL for linux_${arch} tar.gz."

  local current
  current="$(core_version_tag_guess)"
  if core_installed; then
    # If we can compare tags, skip when equal.
    if [[ -n "$current" && "$current" == "$tag" ]]; then
      ui_msg "$MANAGER_NAME" "Core is already up to date.\n\nInstalled: $current\nLatest:    $tag"
      rm -f "$json" >/dev/null 2>&1 || true
      return 0
    fi
    if ! ui_yesno "$MANAGER_NAME" "A newer core may be available.\n\nInstalled (detected): ${current:-unknown}\nLatest:               $tag\n\nDo you want to download and update core now?"; then
      rm -f "$json" >/dev/null 2>&1 || true
      return 0
    fi
  else
    ui_msg "$MANAGER_NAME" "Core is not installed.\nLatest release: $tag\n\nCore will be installed now."
  fi

  local tgz="/tmp/backhaul_linux_${arch}.tar.gz"
  download_file "$url" "$tgz" || die "Failed to download core archive."
  install_core_from_tgz "$tgz"
  rm -f "$tgz" "$json" >/dev/null 2>&1 || true
  ui_msg "$MANAGER_NAME" "Core installed/updated successfully.\n\nNow installed version output:\n$(core_version_raw)"
}

install_or_update_core(){
  local arch
  arch="$(detect_arch)"

  # Prefer offline if user wants AND file exists
  if install_core_offline_if_possible "$arch"; then
    ui_msg "$MANAGER_NAME" "Core installed from offline package.\n\nVersion output:\n$(core_version_raw)"
    return 0
  fi

  install_or_update_core_online "$arch"
}

########################################
# Install manager command
########################################
manager_installed(){
  [[ -x "$MANAGER_INSTALL_PATH" ]]
}

install_manager_self(){
  local src="$0"
  # Best-effort: install only if not already installed or user wants overwrite
  if manager_installed; then
    return 0
  fi
  if [[ -f "$src" ]]; then
    cp -f "$src" "$MANAGER_INSTALL_PATH" || die "Failed to copy manager to $MANAGER_INSTALL_PATH"
    chmod +x "$MANAGER_INSTALL_PATH" || true
  fi
}

########################################
# systemd template for tunnels
########################################
install_systemd_template(){
  if [[ -f "$SYSTEMD_TEMPLATE" ]]; then
    return 0
  fi

  cat > "$SYSTEMD_TEMPLATE" <<'EOF'
[Unit]
Description=Backhaul tunnel instance (%i)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/backhaul -c /etc/backhaul-manager/tunnels/%i.toml
Restart=always
RestartSec=2
LimitNOFILE=1048576

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

  systemd_reload
}

########################################
# Health-check service & timer
########################################
health_timer_is_enabled(){
  systemctl is-enabled --quiet backhaul-manager-health.timer 2>/dev/null
}

install_health_units(){
  # service: call manager in CLI mode to perform checks
  if [[ ! -f "$HEALTH_SERVICE" ]]; then
    cat > "$HEALTH_SERVICE" <<EOF
[Unit]
Description=Backhaul Manager health check (ensure tunnels are running)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${MANAGER_INSTALL_PATH} --health-check
EOF
  fi

  if [[ ! -f "$HEALTH_TIMER" ]]; then
    # default 5 minutes; can be rewritten by config menu
    cat > "$HEALTH_TIMER" <<'EOF'
[Unit]
Description=Run Backhaul Manager health check every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF
  fi

  systemd_reload
}

configure_health_timer(){
  install_health_units

  if ! ui_yesno "$MANAGER_NAME" "Enable a real health-check using systemd timer?\n\nThis will periodically verify tunnel services and start them if they are not active.\n(You can still use cron periodic restart separately.)"; then
    systemctl disable --now backhaul-manager-health.timer >/dev/null 2>&1 || true
    ui_msg "$MANAGER_NAME" "Health-check timer disabled."
    return 0
  fi

  local minutes
  while true; do
    minutes="$(ui_input "$MANAGER_NAME" "Health-check interval (minutes):" "5")" || return 1
    [[ "$minutes" =~ ^[0-9]+$ ]] || { ui_msg "$MANAGER_NAME" "Invalid number."; continue; }
    (( minutes >= 1 && minutes <= 1440 )) || { ui_msg "$MANAGER_NAME" "Please enter a value between 1 and 1440."; continue; }
    break
  done

  # Rewrite timer file with requested interval
  cat > "$HEALTH_TIMER" <<EOF
[Unit]
Description=Run Backhaul Manager health check every ${minutes} minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=${minutes}min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemd_reload
  systemctl enable --now backhaul-manager-health.timer >/dev/null 2>&1 || die "Failed to enable health-check timer."
  ui_msg "$MANAGER_NAME" "Health-check timer enabled.\n\nInterval: ${minutes} minutes"
}

health_check_run(){
  # Ensure all defined tunnels have active systemd services; if not, try to start.
  local tunnels
  tunnels="$(list_tunnels)"
  [[ -n "$tunnels" ]] || exit 0

  local ok=0 fixed=0 fail=0
  while read -r t; do
    [[ -n "$t" ]] || continue
    local svc
    svc="$(service_name "$t")"
    if systemctl is-active --quiet "$svc"; then
      ((ok++))
      continue
    fi
    # try start
    if systemctl start "$svc" >/dev/null 2>&1; then
      ((fixed++))
    else
      ((fail++))
    fi
  done <<< "$tunnels"

  # Log to journal via logger if available
  if cmd_exists logger; then
    logger -t backhaul-manager "health-check: ok=${ok} fixed=${fixed} fail=${fail}"
  fi
}

########################################
# Cron periodic restart (keep it)
########################################
setup_periodic_restart_cron(){
  if ! ui_yesno "$MANAGER_NAME" "Configure periodic restart using cron?\n\nThis is optional. systemd already uses Restart=always.\n\nEnable cron periodic restart?"; then
    rm -f "$CRON_FILE" >/dev/null 2>&1 || true
    ui_msg "$MANAGER_NAME" "Cron periodic restart disabled (cron file removed)."
    return 0
  fi

  local hours
  while true; do
    hours="$(ui_input "$MANAGER_NAME" "Restart all tunnels every N hours:" "6")" || return 1
    [[ "$hours" =~ ^[0-9]+$ ]] || { ui_msg "$MANAGER_NAME" "Invalid number."; continue; }
    (( hours >= 1 && hours <= 168 )) || { ui_msg "$MANAGER_NAME" "Please enter a value between 1 and 168."; continue; }
    break
  done

  cat > "$CRON_FILE" <<EOF
# Managed by Backhaul Manager
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
0 */${hours} * * * root ${MANAGER_INSTALL_PATH} --restart-all >/dev/null 2>&1
EOF

  ui_msg "$MANAGER_NAME" "Cron periodic restart enabled.\n\nInterval: every ${hours} hour(s)"
}

########################################
# Validation helpers
########################################
valid_name(){
  [[ "$1" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]
}

valid_port(){
  local p="$1"
  [[ "$p" =~ ^[0-9]{1,5}$ ]] || return 1
  (( p >= 1 && p <= 65535 ))
}

valid_hostport(){
  local v="$1"
  # [ipv6]:port
  if [[ "$v" =~ ^\[[0-9a-fA-F:]+\]:[0-9]{1,5}$ ]]; then
    valid_port "${v##*:}"
    return $?
  fi
  # host:port (ipv4 or domain)
  if [[ "$v" =~ ^[^[:space:]]+:[0-9]{1,5}$ ]]; then
    valid_port "${v##*:}"
    return $?
  fi
  return 1
}

port_in_use_running(){
  local p="$1"
  if cmd_exists ss; then
    ss -lntup 2>/dev/null | awk '{print $5}' | grep -qE "[:\.]${p}$"
    return $?
  fi
  return 1
}

collect_existing_listen_ports_from_configs(){
  local f
  for f in "${TUNNELS_DIR}"/*.toml; do
    [[ -f "$f" ]] || continue
    # bind_addr port
    grep -E '^\s*bind_addr\s*=' "$f" | sed -E 's/.*"([^"]+)".*/\1/' | awk -F: '{print $NF}' | grep -E '^[0-9]+$' || true
    # ports rules (best-effort)
    awk '
      BEGIN{inports=0}
      /^\s*ports\s*=\s*\[/{inports=1;next}
      inports==1{
        if ($0 ~ /\]/){inports=0;next}
        gsub(/"|,/, "", $0); gsub(/^[[:space:]]+/, "", $0); gsub(/[[:space:]]+$/, "", $0);
        if (length($0)==0) next;
        split($0,a,"=");
        lhs=a[1];
        n=split(lhs,b,":");
        listen=b[n];
        if (listen ~ /^[0-9]+$/){
          print listen;
        } else if (listen ~ /^[0-9]+-[0-9]+$/){
          split(listen,r,"-");
          print r[1]; print r[2];
        }
      }
    ' "$f" 2>/dev/null || true
  done
}

port_in_use_configs(){
  local p="$1"
  collect_existing_listen_ports_from_configs | grep -qx "$p"
}

ensure_no_port_conflict(){
  local p="$1"
  if port_in_use_configs "$p"; then return 1; fi
  if port_in_use_running "$p"; then return 1; fi
  return 0
}

########################################
# SSL helpers (Self-signed / Import / Let's Encrypt)
########################################
ensure_openssl(){
  ensure_cmd openssl openssl
}

ensure_certbot(){
  if cmd_exists certbot; then
    return 0
  fi
  pm_install certbot >/dev/null 2>&1 || die "certbot is not installed and automatic installation failed. Please install certbot manually."
}

check_port_80_free_or_warn(){
  if cmd_exists ss; then
    if ss -lntp 2>/dev/null | awk '{print $4,$6}' | grep -qE '(:|\.)80[[:space:]]'; then
      ui_text "$MANAGER_NAME" "Port 80 is currently in use.\n\nLet's Encrypt (standalone) requires port 80.\n\nPlease stop the service using port 80 (nginx/apache/etc.) and try again.\n\nExamples:\n- systemctl stop nginx\n- systemctl stop apache2 (or httpd)"
      return 1
    fi
  fi
  return 0
}

ssl_self_signed(){
  local name="$1"
  ensure_openssl
  safe_mkdir "${SSL_DIR}/${name}"
  local crt="${SSL_DIR}/${name}/server.crt"
  local key="${SSL_DIR}/${name}/server.key"
  if [[ -f "$crt" && -f "$key" ]]; then
    echo "$crt|$key"
    return 0
  fi
  openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -keyout "$key" -out "$crt" -subj "/CN=${name}" >/dev/null 2>&1 || die "Failed to generate self-signed certificate."
  chmod 600 "$key" >/dev/null 2>&1 || true
  echo "$crt|$key"
}

ssl_import(){
  local crt key
  while true; do
    crt="$(ui_input "$MANAGER_NAME" "Path to CERT file (e.g. fullchain.pem):" "")" || return 1
    [[ -f "$crt" ]] || { ui_msg "$MANAGER_NAME" "File not found: $crt"; continue; }
    break
  done
  while true; do
    key="$(ui_input "$MANAGER_NAME" "Path to KEY file (e.g. privkey.pem):" "")" || return 1
    [[ -f "$key" ]] || { ui_msg "$MANAGER_NAME" "File not found: $key"; continue; }
    break
  done
  echo "$crt|$key"
}

ssl_letsencrypt(){
  local name="$1"
  ensure_certbot
  check_port_80_free_or_warn || return 1

  local domain email
  while true; do
    domain="$(ui_input "$MANAGER_NAME" "Domain for certificate (e.g. tunnel.example.com):" "")" || return 1
    [[ -n "$domain" ]] || { ui_msg "$MANAGER_NAME" "Domain cannot be empty."; continue; }
    [[ "$domain" =~ ^[A-Za-z0-9.-]+$ ]] || { ui_msg "$MANAGER_NAME" "Invalid domain format."; continue; }
    break
  done
  while true; do
    email="$(ui_input "$MANAGER_NAME" "Email for Let's Encrypt (required):" "")" || return 1
    [[ "$email" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || { ui_msg "$MANAGER_NAME" "Invalid email."; continue; }
    break
  done

  certbot certonly --non-interactive --agree-tos \
    --email "$email" --standalone -d "$domain" \
    || die "Let's Encrypt failed. Check DNS/Firewall and ensure port 80 is reachable."

  local crt="/etc/letsencrypt/live/${domain}/fullchain.pem"
  local key="/etc/letsencrypt/live/${domain}/privkey.pem"
  [[ -f "$crt" && -f "$key" ]] || die "Let's Encrypt files not found after certbot."

  safe_mkdir "${SSL_DIR}/${name}"
  ln -sf "$crt" "${SSL_DIR}/${name}/fullchain.pem" >/dev/null 2>&1 || true
  ln -sf "$key" "${SSL_DIR}/${name}/privkey.pem" >/dev/null 2>&1 || true
  echo "${SSL_DIR}/${name}/fullchain.pem|${SSL_DIR}/${name}/privkey.pem"
}

########################################
# Tunnel helpers
########################################
tunnel_config_path(){
  local name="$1"
  echo "${TUNNELS_DIR}/${name}.toml"
}

tunnel_exists(){
  local name="$1"
  [[ -f "$(tunnel_config_path "$name")" ]]
}

service_name(){
  local name="$1"
  echo "backhaul@${name}.service"
}

list_tunnels(){
  ls -1 "${TUNNELS_DIR}"/*.toml 2>/dev/null | sed -E 's#.*/##; s#\.toml$##' || true
}

tunnel_status(){
  local name="$1"
  local svc
  svc="$(service_name "$name")"
  if systemctl is-active --quiet "$svc"; then
    echo "active"
  else
    echo "inactive"
  fi
}

default_token(){
  if cmd_exists openssl; then
    openssl rand -hex 12 2>/dev/null
  else
    date +%s%N | sha256sum | awk '{print substr($1,1,24)}'
  fi
}

choose_role(){
  ui_menu "$MANAGER_NAME" "Select tunnel role:" \
    "server" "Server" \
    "client" "Client"
}

choose_transport(){
  ui_menu "$MANAGER_NAME" "Select transport:" \
    "tcp"    "TCP" \
    "tcpmux" "TCP Multiplexing" \
    "udp"    "UDP" \
    "ws"     "WebSocket" \
    "wss"    "Secure WebSocket (TLS)" \
    "wsmux"  "WS Multiplexing" \
    "wssmux" "WSS Multiplexing (TLS)"
}

# TOML read helpers (best-effort)
toml_get_string(){
  # toml_get_string <file> <key> => value (without quotes)
  local file="$1" key="$2"
  grep -E "^\s*${key}\s*=" "$file" 2>/dev/null | head -n1 | sed -E 's/.*=\s*"([^"]*)".*/\1/'
}
toml_get_bool_or_num(){
  local file="$1" key="$2"
  grep -E "^\s*${key}\s*=" "$file" 2>/dev/null | head -n1 | sed -E 's/.*=\s*([^#]+).*/\1/' | tr -d '[:space:]'
}
toml_detect_role(){
  local file="$1"
  if grep -q '^\[server\]' "$file" 2>/dev/null; then echo "server"; else echo "client"; fi
}
toml_get_transport(){
  local file="$1"
  toml_get_string "$file" "transport"
}
toml_extract_ports_csv(){
  local file="$1"
  # Extract ports array items into CSV
  awk '
    BEGIN{inports=0; first=1}
    /^\s*ports\s*=\s*\[/{inports=1;next}
    inports==1{
      if ($0 ~ /\]/){inports=0;next}
      line=$0
      gsub(/^[[:space:]]+/, "", line)
      gsub(/[[:space:]]+$/, "", line)
      gsub(/,/, "", line)
      if (match(line, /^"([^"]+)"$/, m)){
        if (first==0) printf(",")
        printf("%s", m[1])
        first=0
      }
    }
  ' "$file" 2>/dev/null
}

parse_rules_csv_to_array(){
  # input: "a,b,c" => prints each trimmed on newline
  local csv="$1"
  # split by comma
  awk -v s="$csv" 'BEGIN{
    n=split(s,a,",");
    for(i=1;i<=n;i++){
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", a[i]);
      if(length(a[i])>0) print a[i];
    }
  }'
}

validate_rule_and_check_ports(){
  local rule="$1"
  # Extract listening part: before '=' then last segment after ':'
  local lhs="${rule%%=*}"
  local listen="${lhs##*:}"
  if [[ "$listen" =~ ^[0-9]+$ ]]; then
    ensure_no_port_conflict "$listen" || return 1
  elif [[ "$listen" =~ ^([0-9]+)-([0-9]+)$ ]]; then
    local s="${BASH_REMATCH[1]}" e="${BASH_REMATCH[2]}"
    valid_port "$s" || return 1
    valid_port "$e" || return 1
    (( s <= e )) || return 1
    # Check endpoints only (fast). You can tighten later if you want full scan.
    ensure_no_port_conflict "$s" || return 1
    ensure_no_port_conflict "$e" || return 1
  else
    # Unknown, accept (cannot reliably check). Return success.
    return 0
  fi
  return 0
}

collect_ports_rules_csv(){
  # Allow single port / range, multiple entries comma-separated.
  # Return CSV string
  local default_csv="${1:-}"
  while true; do
    local csv
    csv="$(ui_input "$MANAGER_NAME" "Enter port rules (comma-separated). Empty = no rules.\nExamples:\n  443\n  4000=5000\n  127.0.0.2:443=1.1.1.1:5201\n  443-600\n\nRules:" "$default_csv")" || return 1
    # empty allowed
    if [[ -z "$csv" ]]; then
      echo ""
      return 0
    fi

    local ok=1
    while read -r r; do
      [[ -n "$r" ]] || continue
      if ! validate_rule_and_check_ports "$r"; then
        ok=0
        ui_msg "$MANAGER_NAME" "Port conflict or invalid port range detected for rule:\n$r\n\nPlease change it."
        break
      fi
    done < <(parse_rules_csv_to_array "$csv")

    if (( ok == 1 )); then
      echo "$csv"
      return 0
    fi
  done
}

write_tunnel_config(){
  # write_tunnel_config <name> <role> <transport> [existing_cfg_for_defaults]
  local name="$1"
  local role="$2"
  local transport="$3"
  local existing="${4:-}"
  local cfg
  cfg="$(tunnel_config_path "$name")"

  local token keepalive heartbeat channel_size nodelay web_port log_level
  local bind_addr remote_addr edge_ip
  local connection_pool aggressive_pool dial_timeout retry_interval

  # Defaults (Iran-friendly)
  local def_token def_keepalive def_heartbeat def_channel def_nodelay def_web_port def_log
  def_token="$(default_token)"
  def_keepalive="75"
  def_heartbeat="40"
  def_channel="2048"
  def_nodelay="true"
  def_web_port="0"
  def_log="info"

  if [[ -n "$existing" && -f "$existing" ]]; then
    def_token="$(toml_get_string "$existing" "token")"; [[ -z "$def_token" ]] && def_token="$(default_token)"
    def_keepalive="$(toml_get_bool_or_num "$existing" "keepalive_period")"; [[ -z "$def_keepalive" ]] && def_keepalive="75"
    def_heartbeat="$(toml_get_bool_or_num "$existing" "heartbeat")"; [[ -z "$def_heartbeat" ]] && def_heartbeat="40"
    def_channel="$(toml_get_bool_or_num "$existing" "channel_size")"; [[ -z "$def_channel" ]] && def_channel="2048"
    def_nodelay="$(toml_get_bool_or_num "$existing" "nodelay")"; [[ -z "$def_nodelay" ]] && def_nodelay="true"
    def_web_port="$(toml_get_bool_or_num "$existing" "web_port")"; [[ -z "$def_web_port" ]] && def_web_port="0"
    def_log="$(toml_get_string "$existing" "log_level")"; [[ -z "$def_log" ]] && def_log="info"
  fi

  token="$(ui_input "$MANAGER_NAME" "Token:" "$def_token")" || return 1
  keepalive="$(ui_input "$MANAGER_NAME" "keepalive_period (seconds):" "$def_keepalive")" || return 1
  heartbeat="$(ui_input "$MANAGER_NAME" "heartbeat (seconds):" "$def_heartbeat")" || return 1
  channel_size="$(ui_input "$MANAGER_NAME" "channel_size:" "$def_channel")" || return 1
  nodelay="$(ui_input "$MANAGER_NAME" "nodelay (true/false):" "$def_nodelay")" || return 1
  web_port="$(ui_input "$MANAGER_NAME" "web_port (0 disables):" "$def_web_port")" || return 1
  log_level="$(ui_input "$MANAGER_NAME" "log_level (debug/info/warn/error):" "$def_log")" || return 1

  local tls_cert="" tls_key=""

  if [[ "$transport" == "wss" || "$transport" == "wssmux" ]]; then
    if [[ "$role" == "server" ]]; then
      local sslsel
      sslsel="$(ui_menu "$MANAGER_NAME" "TLS mode:" \
        "self"   "Self-signed" \
        "le"     "Let's Encrypt (requires free port 80 + domain)" \
        "import" "Import cert/key paths")" || return 1
      local pair
      case "$sslsel" in
        self) pair="$(ssl_self_signed "$name")" ;;
        le) pair="$(ssl_letsencrypt "$name")" ;;
        import) pair="$(ssl_import)" ;;
        *) die "Invalid TLS selection." ;;
      esac
      tls_cert="${pair%%|*}"
      tls_key="${pair##*|}"
    fi
  fi

  if [[ "$role" == "server" ]]; then
    local def_bind def_ports_csv
    def_bind="0.0.0.0:3080"
    def_ports_csv=""
    if [[ -n "$existing" && -f "$existing" ]]; then
      local x
      x="$(toml_get_string "$existing" "bind_addr")"
      [[ -n "$x" ]] && def_bind="$x"
      def_ports_csv="$(toml_extract_ports_csv "$existing")"
    fi

    while true; do
      bind_addr="$(ui_input "$MANAGER_NAME" "bind_addr (e.g. 0.0.0.0:3080 or [::]:3080):" "$def_bind")" || return 1
      if [[ "$bind_addr" =~ ^\[[0-9a-fA-F:]+\]:[0-9]{1,5}$ ]] || [[ "$bind_addr" =~ ^[^[:space:]]+:[0-9]{1,5}$ ]]; then
        local p="${bind_addr##*:}"
        valid_port "$p" || { ui_msg "$MANAGER_NAME" "Invalid port in bind_addr."; continue; }
        if ! ensure_no_port_conflict "$p"; then
          ui_msg "$MANAGER_NAME" "Port conflict detected for bind_addr port: $p"
          continue
        fi
        break
      fi
      ui_msg "$MANAGER_NAME" "Invalid bind_addr format."
    done

    local ports_csv
    ports_csv="$(collect_ports_rules_csv "$def_ports_csv")" || return 1

    # Write server config
    cat > "$cfg" <<EOF
[server]
bind_addr = "${bind_addr}"
transport = "${transport}"
accept_udp = false
token = "${token}"
keepalive_period = ${keepalive}
nodelay = ${nodelay}
heartbeat = ${heartbeat}
channel_size = ${channel_size}
mux_con = 8
mux_version = 1
mux_framesize = 32768
mux_recievebuffer = 4194304
mux_streambuffer = 65536
sniffer = false
web_port = ${web_port}
sniffer_log = "${LOG_DIR}/${name}.json"
log_level = "${log_level}"
EOF

    if [[ -n "$tls_cert" && -n "$tls_key" ]]; then
      cat >> "$cfg" <<EOF
tls_cert = "${tls_cert}"
tls_key = "${tls_key}"
EOF
    fi

    echo "ports = [" >> "$cfg"
    if [[ -n "$ports_csv" ]]; then
      while read -r r; do
        [[ -n "$r" ]] || continue
        echo "  \"${r}\"," >> "$cfg"
      done < <(parse_rules_csv_to_array "$ports_csv")
    fi
    echo "]" >> "$cfg"

  else
    # client
    local def_remote def_edge def_pool def_aggr def_dial def_retry
    def_remote="0.0.0.0:3080"
    def_edge=""
    def_pool="8"
    def_aggr="false"
    def_dial="10"
    def_retry="3"

    if [[ -n "$existing" && -f "$existing" ]]; then
      local x
      x="$(toml_get_string "$existing" "remote_addr")"; [[ -n "$x" ]] && def_remote="$x"
      x="$(toml_get_string "$existing" "edge_ip")"; [[ -n "$x" ]] && def_edge="$x"
      x="$(toml_get_bool_or_num "$existing" "connection_pool")"; [[ -n "$x" ]] && def_pool="$x"
      x="$(toml_get_bool_or_num "$existing" "aggressive_pool")"; [[ -n "$x" ]] && def_aggr="$x"
      x="$(toml_get_bool_or_num "$existing" "dial_timeout")"; [[ -n "$x" ]] && def_dial="$x"
      x="$(toml_get_bool_or_num "$existing" "retry_interval")"; [[ -n "$x" ]] && def_retry="$x"
    fi

    while true; do
      remote_addr="$(ui_input "$MANAGER_NAME" "remote_addr (IPv4/IPv6/Domain) e.g. 1.2.3.4:3080 or example.com:443 or [2001:db8::1]:3080:" "$def_remote")" || return 1
      valid_hostport "$remote_addr" && break
      ui_msg "$MANAGER_NAME" "Invalid remote_addr format."
    done

    if [[ "$transport" == "ws" || "$transport" == "wss" || "$transport" == "wsmux" || "$transport" == "wssmux" ]]; then
      edge_ip="$(ui_input "$MANAGER_NAME" "edge_ip (optional):" "$def_edge")" || return 1
    else
      edge_ip=""
    fi

    connection_pool="$(ui_input "$MANAGER_NAME" "connection_pool:" "$def_pool")" || return 1
    aggressive_pool="$(ui_input "$MANAGER_NAME" "aggressive_pool (true/false):" "$def_aggr")" || return 1
    dial_timeout="$(ui_input "$MANAGER_NAME" "dial_timeout (seconds):" "$def_dial")" || return 1
    retry_interval="$(ui_input "$MANAGER_NAME" "retry_interval (seconds):" "$def_retry")" || return 1

    cat > "$cfg" <<EOF
[client]
remote_addr = "${remote_addr}"
transport = "${transport}"
token = "${token}"
connection_pool = ${connection_pool}
aggressive_pool = ${aggressive_pool}
keepalive_period = ${keepalive}
dial_timeout = ${dial_timeout}
retry_interval = ${retry_interval}
nodelay = ${nodelay}
sniffer = false
web_port = ${web_port}
sniffer_log = "${LOG_DIR}/${name}.json"
log_level = "${log_level}"
EOF

    if [[ -n "$edge_ip" ]]; then
      echo "edge_ip = \"${edge_ip}\"" >> "$cfg"
    fi

    if [[ "$transport" == "tcpmux" || "$transport" == "wsmux" || "$transport" == "wssmux" ]]; then
      cat >> "$cfg" <<EOF
mux_version = 1
mux_framesize = 32768
mux_recievebuffer = 4194304
mux_streambuffer = 65536
EOF
    fi
  fi

  chmod 600 "$cfg" >/dev/null 2>&1 || true
}

create_tunnel(){
  core_installed || { ui_msg "$MANAGER_NAME" "Core is not installed. Please install/update core first."; return 1; }

  local name
  while true; do
    name="$(ui_input "$MANAGER_NAME" "Tunnel name (a-zA-Z0-9_- up to 32 chars):" "")" || return 1
    valid_name "$name" || { ui_msg "$MANAGER_NAME" "Invalid tunnel name."; continue; }
    if tunnel_exists "$name"; then
      ui_msg "$MANAGER_NAME" "This tunnel name already exists."
      continue
    fi
    break
  done

  local role transport
  role="$(choose_role)" || return 1
  transport="$(choose_transport)" || return 1

  write_tunnel_config "$name" "$role" "$transport" "" || return 1

  systemd_reload
  systemctl enable "$(service_name "$name")" >/dev/null 2>&1 || true
  systemctl restart "$(service_name "$name")" >/dev/null 2>&1 || true

  ui_msg "$MANAGER_NAME" "Tunnel created:\n\nName: $name\nRole: $role\nTransport: $transport\nService: $(service_name "$name")"
}

edit_tunnel(){
  local name="$1"
  local cfg
  cfg="$(tunnel_config_path "$name")"
  [[ -f "$cfg" ]] || { ui_msg "$MANAGER_NAME" "Config not found."; return 1; }

  local role transport
  role="$(toml_detect_role "$cfg")"
  transport="$(toml_get_transport "$cfg")"
  [[ -z "$transport" ]] && transport="tcp"

  if ui_yesno "$MANAGER_NAME" "Edit using interactive wizard?\n\nYes: Wizard (supports add/remove ports via comma-separated rules)\nNo: Open editor (nano/vi)"; then
    write_tunnel_config "$name" "$role" "$transport" "$cfg" || return 1
  else
    if cmd_exists nano; then
      nano "$cfg"
    else
      vi "$cfg"
    fi
  fi

  systemd_reload
  systemctl restart "$(service_name "$name")" >/dev/null 2>&1 || true
  ui_msg "$MANAGER_NAME" "Tunnel updated and service restarted."
}

delete_tunnel(){
  local name="$1"
  if ! ui_yesno "$MANAGER_NAME" "Delete tunnel '$name'?\n\nThis removes config, service instance and related SSL files."; then
    return 0
  fi
  systemctl disable --now "$(service_name "$name")" >/dev/null 2>&1 || true
  rm -f "$(tunnel_config_path "$name")" >/dev/null 2>&1 || true
  rm -rf "${SSL_DIR}/${name}" >/dev/null 2>&1 || true
  systemd_reload
  ui_msg "$MANAGER_NAME" "Tunnel deleted."
}

show_logs(){
  local name="$1"
  local svc
  svc="$(service_name "$name")"
  if cmd_exists journalctl; then
    journalctl -u "$svc" -n 120 --no-pager | sed 's/\x1b\[[0-9;]*m//g' > "/tmp/${svc}.log" || true
    ui_text "$MANAGER_NAME" "$(cat "/tmp/${svc}.log" 2>/dev/null || echo "No logs available.")"
  else
    ui_msg "$MANAGER_NAME" "journalctl not available."
  fi
}

manage_tunnel_actions(){
  local name="$1"
  while true; do
    local status sel
    status="$(tunnel_status "$name")"
    sel="$(ui_menu "$MANAGER_NAME" "Manage: $name (status: $status)" \
      "1" "Start" \
      "2" "Stop" \
      "3" "Restart" \
      "4" "Status (systemctl)" \
      "5" "Edit" \
      "6" "Logs (last 120 lines)" \
      "7" "Delete" \
      "0" "Back")" || return 1

    case "$sel" in
      1) systemctl start "$(service_name "$name")" >/dev/null 2>&1 || ui_msg "$MANAGER_NAME" "Start failed." ;;
      2) systemctl stop "$(service_name "$name")" >/dev/null 2>&1 || ui_msg "$MANAGER_NAME" "Stop failed." ;;
      3) systemctl restart "$(service_name "$name")" >/dev/null 2>&1 || ui_msg "$MANAGER_NAME" "Restart failed." ;;
      4)
        systemctl status "$(service_name "$name")" --no-pager | sed 's/\x1b\[[0-9;]*m//g' > "/tmp/bhm_status_${name}.txt" || true
        ui_text "$MANAGER_NAME" "$(cat "/tmp/bhm_status_${name}.txt" 2>/dev/null)"
        ;;
      5) edit_tunnel "$name" ;;
      6) show_logs "$name" ;;
      7) delete_tunnel "$name"; return 0 ;;
      0) return 0 ;;
      *) ;;
    esac
  done
}

manage_tunnels_menu(){
  local tunnels
  tunnels="$(list_tunnels)"
  [[ -n "$tunnels" ]] || { ui_msg "$MANAGER_NAME" "No tunnels found."; return 0; }

  local args=() t
  while read -r t; do
    [[ -n "$t" ]] || continue
    args+=("$t" "status: $(tunnel_status "$t")")
  done <<< "$tunnels"

  local sel
  sel="$(ui_menu "$MANAGER_NAME" "Select a tunnel:" "${args[@]}")" || return 1
  manage_tunnel_actions "$sel"
}

restart_all_tunnels(){
  local tunnels
  tunnels="$(list_tunnels)"
  [[ -n "$tunnels" ]] || { ui_msg "$MANAGER_NAME" "No tunnels found."; return 0; }

  local ok=0 fail=0 t
  while read -r t; do
    [[ -n "$t" ]] || continue
    if systemctl restart "$(service_name "$t")" >/dev/null 2>&1; then
      ((ok++))
    else
      ((fail++))
    fi
  done <<< "$tunnels"

  ui_msg "$MANAGER_NAME" "Restart all completed.\n\nOK: $ok\nFailed: $fail"
}

########################################
# Uninstall
########################################
uninstall_all(){
  if ! ui_yesno "$MANAGER_NAME" "Uninstall Backhaul Manager completely?\n\nThis removes tunnels, configs, services, SSL files, health timer, cron, and manager command."; then
    return 0
  fi

  local tunnels
  tunnels="$(list_tunnels)"
  if [[ -n "$tunnels" ]]; then
    while read -r t; do
      [[ -n "$t" ]] || continue
      systemctl disable --now "$(service_name "$t")" >/dev/null 2>&1 || true
    done <<< "$tunnels"
  fi

  # Remove health timer/service
  systemctl disable --now backhaul-manager-health.timer >/dev/null 2>&1 || true
  rm -f "$HEALTH_TIMER" "$HEALTH_SERVICE" >/dev/null 2>&1 || true

  rm -f "$CRON_FILE" >/dev/null 2>&1 || true
  rm -f "$SYSTEMD_TEMPLATE" >/dev/null 2>&1 || true
  rm -rf "$BASE_DIR" >/dev/null 2>&1 || true
  rm -rf "$LOG_DIR" >/dev/null 2>&1 || true
  rm -f "$MANAGER_INSTALL_PATH" >/dev/null 2>&1 || true

  systemd_reload

  if ui_yesno "$MANAGER_NAME" "Also remove core binary (${CORE_BIN_NAME})?"; then
    rm -f "$CORE_INSTALL_PATH" >/dev/null 2>&1 || true
  fi

  ui_msg "$MANAGER_NAME" "Uninstall completed."
}

########################################
# Setup / Install everything
########################################
setup_all(){
  ensure_prereqs
  init_ui
  install_system_layout
  install_systemd_template
  install_manager_self
  install_or_update_core
  install_health_units
  ui_msg "$MANAGER_NAME" "Setup completed.\n\nCommand: ${MANAGER_CMD}\nCore version output:\n$(core_version_raw)"
}

########################################
# Header / status
########################################
tunnels_count(){
  ls -1 "${TUNNELS_DIR}"/*.toml 2>/dev/null | wc -l | tr -d ' '
}

core_status_line(){
  if core_installed; then
    echo "Core: installed (detected: ${cv:-unknown})"
  else
    echo "Core: NOT installed"
  fi
}

########################################
# CLI flags (cron/health)
########################################
handle_cli(){
  case "${1:-}" in
    --restart-all)
      restart_all_tunnels
      exit 0
      ;;
    --health-check)
      health_check_run
      exit 0
      ;;
  esac
}

########################################
# Main menu
########################################
main_menu(){
  while true; do
    local cv hdr sel
    cv="$(core_version_tag_guess)"
    hdr="Core: $([[ -n "$cv" ]] && echo "$cv" || echo "not-installed") | Tunnels: $(tunnels_count)\n\nSelect an option:"
    sel="$(ui_menu "$MANAGER_NAME" "$hdr" \
      "1" "Setup (install manager + install/update core)" \
      "2" "Install/Update Core (check latest release)" \
      "3" "Create new tunnel" \
      "4" "Manage tunnels" \
      "5" "Restart ALL tunnels" \
      "6" "Health-check (systemd timer) settings" \
      "7" "Cron periodic restart settings" \
      "8" "Uninstall (remove everything)" \
      "0" "Exit")" || exit 0

    case "$sel" in
      1) setup_all ;;
      2) install_or_update_core ;;
      3) create_tunnel ;;
      4) manage_tunnels_menu ;;
      5) restart_all_tunnels ;;
      6) configure_health_timer ;;
      7) setup_periodic_restart_cron ;;
      8) uninstall_all ;;
      0) exit 0 ;;
      *) ;;
    esac
  done
}

########################################
# Entry
########################################
need_root
ensure_prereqs
init_ui
install_system_layout
install_systemd_template
handle_cli "$@"

# If command not installed yet, offer setup
if ! manager_installed; then
  if ui_yesno "$MANAGER_NAME" "Manager command is not installed.\n\nRun initial setup now?"; then
    setup_all
  fi
fi

main_menu

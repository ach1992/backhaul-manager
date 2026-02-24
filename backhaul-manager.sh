#!/usr/bin/env bash
# Backhaul Manager - single-file installer + menu (TEXT ONLY - no whiptail)
# Manager Repo: https://github.com/ach1992/backhaul-manager/
# Core Repo:    https://github.com/Musixal/Backhaul

set -u
export LC_ALL=C

########################################
# Constants
########################################
MANAGER_NAME="Backhaul Manager"
MANAGER_CMD="backhaul-manager"
MANAGER_REPO_URL="https://github.com/ach1992/backhaul-manager/"

CORE_REPO="Musixal/Backhaul"
CORE_BIN_NAME="backhaul"
CORE_INSTALL_PATH="/usr/local/bin/${CORE_BIN_NAME}"

MANAGER_INSTALL_PATH="/usr/local/bin/${MANAGER_CMD}"

BASE_DIR="/etc/backhaul-manager"
TUNNELS_DIR="${BASE_DIR}/tunnels"
SSL_DIR="${BASE_DIR}/ssl"
LOG_DIR="/var/log/backhaul-manager"

CORE_VERSION_FILE="${BASE_DIR}/core.version"

SYSTEMD_TEMPLATE="/etc/systemd/system/backhaul@.service"

CRON_FILE="/etc/cron.d/backhaul-manager"

HEALTH_SERVICE="/etc/systemd/system/backhaul-manager-health.service"
HEALTH_TIMER="/etc/systemd/system/backhaul-manager-health.timer"

OFFLINE_DIR="/root/backhaul-manager"

########################################
# UI helpers (TEXT ONLY)
########################################
UI_MODE="text"

red(){ printf "\033[31m%s\033[0m\n" "$*"; }
grn(){ printf "\033[32m%s\033[0m\n" "$*"; }
ylw(){ printf "\033[33m%s\033[0m\n" "$*"; }

die(){
  red "ERROR: $*"
  exit 1
}

pause(){
  echo
  read -r -p "Press Enter to continue..." _
}

clear_screen(){
  command -v clear >/dev/null 2>&1 && clear || true
}

need_root(){
  if [[ "${EUID}" -ne 0 ]]; then
    die "This script must be run as root (use sudo)."
  fi
}

cmd_exists(){ command -v "$1" >/dev/null 2>&1; }

init_ui(){
  UI_MODE="text"
}

ui_msg(){
  local title="${1:-$MANAGER_NAME}"
  local msg="${2:-}"
  echo "== $title =="
  echo -e "$msg"
  pause
}

ui_textarea(){
  local title="${1:-$MANAGER_NAME}"
  local msg="${2:-}"
  echo "== $title =="
  echo -e "$msg"
  pause
}

ui_yesno(){
  local title="${1:-$MANAGER_NAME}"
  local msg="${2:-}"
  echo "== $title =="
  echo -e "$msg"
  while true; do
    read -r -p "y/n: " ans
    case "${ans,,}" in
      y|yes) return 0 ;;
      n|no)  return 1 ;;
    esac
  done
}

ui_input(){
  local title="${1:-$MANAGER_NAME}"
  local prompt="${2:-}"
  local default="${3:-}"
  local out=""

  # title فقط برای یکدست بودن نگه داشته شده
  if [[ -n "$default" ]]; then
    read -r -p "$prompt [$default]: " out
    [[ -z "$out" ]] && out="$default"
  else
    read -r -p "$prompt: " out
  fi

  printf "%s" "$out"
}

# ui_menu(key label key label ...)
# خروجی: همان key انتخاب شده
ui_menu(){
  local title="$1"; shift
  local prompt="$1"; shift

  echo "== $title =="
  echo -e "$prompt"
  echo

  local keys=()
  local labels=()
  while [[ $# -gt 0 ]]; do
    keys+=("$1")
    labels+=("$2")
    printf "  %s) %s\n" "$1" "$2"
    shift 2
  done

  echo
  while true; do
    local sel=""
    read -r -p "Choose: " sel

    local i
    for i in "${!keys[@]}"; do
      if [[ "$sel" == "${keys[$i]}" ]]; then
        printf "%s" "$sel"
        return 0
      fi
    done

    echo "Invalid choice. Try again."
  done
}

########################################
# System helpers
########################################
detect_arch(){
  local m
  m="$(uname -m)"
  case "$m" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *)
      die "Unsupported architecture: $m (supported: amd64, arm64)"
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
    apt)
      DEBIAN_FRONTEND=noninteractive apt-get -y install "$pkg" >/dev/null 2>&1 || return 1
      ;;
    dnf)
      dnf -y install "$pkg" >/dev/null 2>&1 || return 1
      ;;
    yum)
      yum -y install "$pkg" >/dev/null 2>&1 || return 1
      ;;
    apk)
      apk add --no-cache "$pkg" >/dev/null 2>&1 || return 1
      ;;
    pacman)
      pacman -Sy --noconfirm "$pkg" >/dev/null 2>&1 || return 1
      ;;
    *)
      return 1
      ;;
  esac
}

ensure_cmd(){
  local c="$1"
  local pkg="${2:-$1}"
  if cmd_exists "$c"; then
    return 0
  fi
  ylw "Installing dependency: $pkg"
  pm_install "$pkg" || die "Failed to install $pkg. Please install it manually and re-run."
}

ensure_prereqs(){
  # No full upgrade; only install missing.
  ensure_cmd tar tar
  ensure_cmd systemctl systemd

  if ! cmd_exists curl && ! cmd_exists wget; then
    pm_install curl >/dev/null 2>&1 || pm_install wget >/dev/null 2>&1 || die "Neither curl nor wget is available and install failed."
  fi

  # Best-effort for port check
  pm_install iproute2 >/dev/null 2>&1 || true
}

download_file(){
  local url="$1"
  local out="$2"
  if cmd_exists curl; then
    curl -fsSL "$url" -o "$out"
  else
    wget -qO "$out" "$url"
  fi
}

safe_mkdir(){
  local d="$1"
  [[ -d "$d" ]] || mkdir -p "$d"
}

systemd_reload(){
  systemctl daemon-reload >/dev/null 2>&1 || true
}

########################################
# GitHub release helpers (no jq)
########################################
github_latest_release_json(){
  local tmp="/tmp/backhaul_latest_release.json"
  download_file "https://api.github.com/repos/${CORE_REPO}/releases/latest" "$tmp" || die "Failed to reach GitHub API for latest release."
  echo "$tmp"
}

extract_latest_tag(){
  local json="$1"
  # "tag_name": "v0.7.2"
  grep -oE '"tag_name"\s*:\s*"[^"]+"' "$json" | head -n1 | sed -E 's/.*"([^"]+)".*/\1/'
}

extract_download_url(){
  local json="$1"
  local arch="$2"
  grep -oE "https://[^\"]+backhaul_linux_${arch}\.tar\.gz" "$json" | head -n1
}

########################################
# Core helpers
########################################
core_installed(){
  [[ -x "$CORE_INSTALL_PATH" ]]
}

core_version_local(){
  if [[ -f "$CORE_VERSION_FILE" ]]; then
    tr -d '\r\n' < "$CORE_VERSION_FILE"
  else
    echo "unknown"
  fi
}

set_core_version_local(){
  local v="$1"
  echo "$v" > "$CORE_VERSION_FILE"
}

core_version_runtime(){
  if core_installed; then
    "$CORE_INSTALL_PATH" -v 2>/dev/null | tr -d '\r' || true
  else
    echo "not-installed"
  fi
}

manager_installed(){
  [[ -x "$MANAGER_INSTALL_PATH" ]]
}

install_manager_self(){
  local src="$0"
  if manager_installed; then
    return 0
  fi
  if [[ -f "$src" ]]; then
    cp -f "$src" "$MANAGER_INSTALL_PATH" || die "Failed to copy manager to ${MANAGER_INSTALL_PATH}"
    chmod +x "$MANAGER_INSTALL_PATH" || true
  fi
}

install_system_layout(){
  safe_mkdir "$BASE_DIR"
  safe_mkdir "$TUNNELS_DIR"
  safe_mkdir "$SSL_DIR"
  safe_mkdir "$LOG_DIR"
  chmod 700 "$BASE_DIR" "$TUNNELS_DIR" "$SSL_DIR" || true
}

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
# Offline / online core install/update
########################################
install_core_from_tgz(){
  local tgz="$1"
  local tag="$2"

  local tmpdir="/tmp/backhaul_extract_$$"
  rm -rf "$tmpdir" && mkdir -p "$tmpdir"
  tar -xzf "$tgz" -C "$tmpdir" || die "Failed to extract: $tgz"
  [[ -f "${tmpdir}/backhaul" ]] || die "The archive does not contain 'backhaul' binary."
  install -m 0755 "${tmpdir}/backhaul" "$CORE_INSTALL_PATH" || die "Failed to install core binary to ${CORE_INSTALL_PATH}"
  rm -rf "$tmpdir"
  set_core_version_local "$tag"
}

install_or_update_core(){
  local arch
  arch="$(detect_arch)"

  local json tag url
  json="$(github_latest_release_json)"
  tag="$(extract_latest_tag "$json")"
  [[ -n "$tag" ]] || die "Failed to parse latest release tag."
  url="$(extract_download_url "$json" "$arch")"
  [[ -n "$url" ]] || die "No matching asset found for linux_${arch}.tar.gz"

  local current_tag
  current_tag="$(core_version_local)"

  if core_installed && [[ "$current_tag" == "$tag" ]]; then
    ui_msg "$MANAGER_NAME" "Core is already up to date.\n\nInstalled: $current_tag\nLatest:    $tag"
    rm -f "$json" >/dev/null 2>&1 || true
    return 0
  fi

  if core_installed; then
    if ! ui_yesno "$MANAGER_NAME" "A core update is available.\n\nInstalled: $current_tag\nLatest:    $tag\n\nUpdate now?"; then
      rm -f "$json" >/dev/null 2>&1 || true
      return 0
    fi
  fi

  # Offline option if present
  local offline_tgz="${OFFLINE_DIR}/backhaul_linux_${arch}.tar.gz"
  if [[ -d "$OFFLINE_DIR" && -f "$offline_tgz" ]]; then
    if ui_yesno "$MANAGER_NAME" "Offline package found:\n$offline_tgz\n\nInstall/update using offline package?"; then
      install_core_from_tgz "$offline_tgz" "$tag"
      rm -f "$json" >/dev/null 2>&1 || true
      ui_msg "$MANAGER_NAME" "Core installed/updated successfully (offline).\n\nNow: $tag"
      return 0
    fi
  fi

  local tgz="/tmp/backhaul_linux_${arch}.tar.gz"
  download_file "$url" "$tgz" || die "Failed to download core release asset."
  install_core_from_tgz "$tgz" "$tag"
  rm -f "$tgz" "$json" >/dev/null 2>&1 || true

  ui_msg "$MANAGER_NAME" "Core installed/updated successfully.\n\nNow: $tag"
}

########################################
# Health-check (systemd timer/service)
########################################
install_health_units(){
  # service
  if [[ ! -f "$HEALTH_SERVICE" ]]; then
    cat > "$HEALTH_SERVICE" <<EOF
[Unit]
Description=Backhaul Manager Health Check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${MANAGER_INSTALL_PATH} --health-check
EOF
  fi

  # timer
  if [[ ! -f "$HEALTH_TIMER" ]]; then
    cat > "$HEALTH_TIMER" <<'EOF'
[Unit]
Description=Run Backhaul Manager Health Check periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF
  fi

  systemd_reload
}

enable_health_timer(){
  install_health_units
  systemctl enable --now backhaul-manager-health.timer >/dev/null 2>&1 || die "Failed to enable health timer."
  ui_msg "$MANAGER_NAME" "Health-check timer enabled.\n\nTimer: backhaul-manager-health.timer"
}

disable_health_timer(){
  systemctl disable --now backhaul-manager-health.timer >/dev/null 2>&1 || true
  ui_msg "$MANAGER_NAME" "Health-check timer disabled."
}

health_check_run(){
  # Checks each backhaul@<tunnel> service. If inactive/failed -> restart.
  local tunnels
  tunnels="$(list_tunnels)"
  [[ -n "$tunnels" ]] || exit 0

  local t ok=0 fixed=0 fail=0
  while read -r t; do
    [[ -n "$t" ]] || continue
    local svc
    svc="$(service_name "$t")"
    if systemctl is-active --quiet "$svc"; then
      ((ok++))
    else
      # attempt restart
      if systemctl restart "$svc" >/dev/null 2>&1; then
        ((fixed++))
      else
        ((fail++))
      fi
    fi
  done <<< "$tunnels"

  logger -t backhaul-manager "health-check: ok=${ok} fixed=${fixed} fail=${fail}"
  exit 0
}

########################################
# Cron periodic restart (kept)
########################################
setup_periodic_restart_cron(){
  if ! ui_yesno "$MANAGER_NAME" "Enable periodic restart using cron?\n(kept alongside systemd Restart=always)\n\nIf you choose No, cron will be removed."; then
    rm -f "$CRON_FILE" >/dev/null 2>&1 || true
    ui_msg "$MANAGER_NAME" "Cron periodic restart disabled (cron removed if existed)."
    return 0
  fi

  local hours
  while true; do
    hours="$(ui_input "$MANAGER_NAME" "Restart all tunnels every N hours (1-168):" "6")" || return 1
    [[ "$hours" =~ ^[0-9]+$ ]] || { ui_msg "$MANAGER_NAME" "Invalid number."; continue; }
    (( hours >= 1 && hours <= 168 )) || { ui_msg "$MANAGER_NAME" "Please enter a number between 1 and 168."; continue; }
    break
  done

  cat > "$CRON_FILE" <<EOF
# Managed by Backhaul Manager
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
0 */${hours} * * * root ${MANAGER_INSTALL_PATH} --restart-all >/dev/null 2>&1
EOF

  ui_msg "$MANAGER_NAME" "Cron periodic restart configured.\n\nEvery ${hours} hours."
}

########################################
# Validation / port checks
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
  if [[ "$v" =~ ^\[[0-9a-fA-F:]+\]:[0-9]{1,5}$ ]]; then
    local p="${v##*:}"
    valid_port "$p"
    return $?
  fi
  if [[ "$v" =~ ^[^[:space:]]+:[0-9]{1,5}$ ]]; then
    local p="${v##*:}"
    valid_port "$p"
    return $?
  fi
  return 1
}

port_conflict_in_running(){
  local p="$1"
  if cmd_exists ss; then
    ss -lntup 2>/dev/null | awk '{print $5}' | grep -qE "[:\.]${p}$"
    return $?
  fi
  return 1
}

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

collect_existing_ports_from_configs(){
  local f
  for f in "${TUNNELS_DIR}"/*.toml; do
    [[ -f "$f" ]] || continue
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
        if (listen ~ /^[0-9]+-[0-9]+$/){
          split(listen,r,"-");
          print r[1]; print r[2];
        } else if (listen ~ /^[0-9]+$/){
          print listen;
        }
      }
    ' "$f" 2>/dev/null || true
  done
}

port_conflict_in_configs(){
  local p="$1"
  collect_existing_ports_from_configs | grep -qx "$p"
}

ensure_no_port_conflict(){
  local p="$1"
  if port_conflict_in_configs "$p"; then
    return 1
  fi
  if port_conflict_in_running "$p"; then
    return 1
  fi
  return 0
}

# Parse comma-separated port list like: "443, 80-90,8443"
# Outputs normalized tokens (one per line) or returns non-zero on invalid.
parse_port_list(){
  local s="$1"
  s="${s// /}"
  [[ -n "$s" ]] || return 1
  IFS=',' read -r -a parts <<< "$s"
  local p
  for p in "${parts[@]}"; do
    [[ -n "$p" ]] || continue
    if [[ "$p" =~ ^[0-9]+$ ]]; then
      valid_port "$p" || return 1
      echo "$p"
    elif [[ "$p" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      local a="${BASH_REMATCH[1]}"
      local b="${BASH_REMATCH[2]}"
      valid_port "$a" || return 1
      valid_port "$b" || return 1
      (( a <= b )) || return 1
      echo "$a-$b"
    else
      return 1
    fi
  done
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
  pm_install certbot >/dev/null 2>&1 || die "Failed to install certbot. Please install it manually."
}

check_port_80_free_or_die(){
  if cmd_exists ss; then
    if ss -lntp 2>/dev/null | awk '{print $4,$6}' | grep -qE '(:|\.)80[[:space:]]'; then
      ui_textarea "$MANAGER_NAME" \
"Port 80 is currently in use.

Let's Encrypt (standalone) requires port 80 to be free.

Please free port 80 and try again. Examples:
- systemctl stop nginx
- systemctl stop apache2
- systemctl stop httpd"
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
    -keyout "$key" -out "$crt" -subj "/CN=${name}" >/dev/null 2>&1 || die "Failed to create self-signed certificate."
  chmod 600 "$key" || true
  echo "$crt|$key"
}

ssl_import(){
  local crt key
  while true; do
    crt="$(ui_input "$MANAGER_NAME" "CERT file path (e.g. /etc/letsencrypt/live/.../fullchain.pem):" "")" || return 1
    [[ -f "$crt" ]] || { ui_msg "$MANAGER_NAME" "File not found: $crt"; continue; }
    break
  done
  while true; do
    key="$(ui_input "$MANAGER_NAME" "KEY file path (e.g. /etc/letsencrypt/live/.../privkey.pem):" "")" || return 1
    [[ -f "$key" ]] || { ui_msg "$MANAGER_NAME" "File not found: $key"; continue; }
    break
  done
  echo "$crt|$key"
}

ssl_letsencrypt(){
  local name="$1"
  ensure_certbot
  check_port_80_free_or_die || return 1

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
    || die "Let's Encrypt failed. Check DNS, firewall, and ensure port 80 is reachable."

  local crt="/etc/letsencrypt/live/${domain}/fullchain.pem"
  local key="/etc/letsencrypt/live/${domain}/privkey.pem"
  [[ -f "$crt" && -f "$key" ]] || die "Certificate files not found after certbot run."

  safe_mkdir "${SSL_DIR}/${name}"
  ln -sf "$crt" "${SSL_DIR}/${name}/fullchain.pem" || true
  ln -sf "$key" "${SSL_DIR}/${name}/privkey.pem" || true
  echo "${SSL_DIR}/${name}/fullchain.pem|${SSL_DIR}/${name}/privkey.pem"
}

########################################
# Tunnel config generation / ports rules
########################################
default_token(){
  if cmd_exists openssl; then
    openssl rand -hex 12 2>/dev/null
  else
    date +%s%N | sha256sum | awk '{print substr($1,1,24)}'
  fi
}

choose_role(){
  local sel
  sel="$(ui_menu "$MANAGER_NAME" "Select tunnel role:" \
    "server" "Server" \
    "client" "Client" \
  )" || return 1
  echo "$sel"
}

choose_transport(){
  local sel
  sel="$(ui_menu "$MANAGER_NAME" "Select transport:" \
    "tcp" "TCP" \
    "tcpmux" "TCP Multiplexing" \
    "udp" "UDP" \
    "ws" "WebSocket" \
    "wss" "Secure WebSocket (TLS)" \
    "wsmux" "WS Multiplexing" \
    "wssmux" "WSS Multiplexing (TLS)" \
  )" || return 1
  echo "$sel"
}

# Outputs TOML lines: "rule",
build_ports_rules_from_portlist(){
  local portlist="$1"
  local mode="$2"      # none|local|remote
  local target="$3"    # empty|5201|1.2.3.4:5201|domain:5201|[v6]:5201
  local rules=()

  local token
  while read -r token; do
    [[ -n "$token" ]] || continue

    # Conflict checks
    if [[ "$token" =~ ^[0-9]+$ ]]; then
      if ! ensure_no_port_conflict "$token"; then
        ui_msg "$MANAGER_NAME" "Port conflict detected for listen port: $token\nRule not added."
        continue
      fi
    else
      local a="${token%-*}"
      local b="${token#*-}"
      if ! ensure_no_port_conflict "$a" || ! ensure_no_port_conflict "$b"; then
        ui_msg "$MANAGER_NAME" "Port conflict detected in listen range: $token\n(At least start/end conflicts)\nRule not added."
        continue
      fi
    fi

    case "$mode" in
      none)   rules+=("$token") ;;
      local)  rules+=("${token}=${target}") ;;
      remote) rules+=("${token}=${target}") ;;
      *) die "Invalid port rule mode." ;;
    esac
  done < <(parse_port_list "$portlist" || true)

  local out=""
  local r
  for r in "${rules[@]}"; do
    out+="\"$r\",\n"
  done
  printf "%b" "$out"
}

collect_ports_rules_wizard(){
  ui_textarea "$MANAGER_NAME" \
"Ports rules wizard (Server only)

You can add multiple listen ports in one line:
  - Single ports: 443,8443
  - Ranges: 80-90
  - Mix: 443,80-90,8443

Then choose how to map them (optional):
  - No mapping: \"443\" or \"80-90\"
  - Map to local port: \"443=5201\"
  - Map to remote host:port: \"443=1.1.1.1:5201\" or \"443=example.com:5201\" or \"443=[2001:db8::1]:5201\"

You can repeat and add more groups. Choose Done to finish."

  local rules_lines=""
  while true; do
    local action
    action="$(ui_menu "$MANAGER_NAME" "Ports rules wizard:" \
      "1" "Add ports (comma-separated list)" \
      "2" "Done" \
    )" || return 1

    case "$action" in
      1)
        local portlist
        while true; do
          portlist="$(ui_input "$MANAGER_NAME" "Listen ports (e.g. 443,80-90,8443):" "")" || return 1
          if parse_port_list "$portlist" >/dev/null 2>&1; then
            break
          fi
          ui_msg "$MANAGER_NAME" "Invalid format. Examples:\n443\n443,8443\n80-90\n443,80-90,8443"
        done

        local mode
        mode="$(ui_menu "$MANAGER_NAME" "Mapping type for this ports group:" \
          "none"  "No mapping (just listen)" \
          "local" "Map to a local port (e.g. 5201)" \
          "remote" "Map to a remote host:port (IP/domain/IPv6)" \
        )" || return 1

        local target=""
        if [[ "$mode" == "local" ]]; then
          while true; do
            target="$(ui_input "$MANAGER_NAME" "Target local port (e.g. 5201):" "5201")" || return 1
            valid_port "$target" && break
            ui_msg "$MANAGER_NAME" "Invalid port."
          done
        elif [[ "$mode" == "remote" ]]; then
          while true; do
            target="$(ui_input "$MANAGER_NAME" "Target host:port (e.g. 1.1.1.1:5201 or example.com:5201 or [v6]:5201):" "")" || return 1
            valid_hostport "$target" && break
            ui_msg "$MANAGER_NAME" "Invalid host:port format."
          done
        fi

        local new_lines
        new_lines="$(build_ports_rules_from_portlist "$portlist" "$mode" "$target")"
        if [[ -z "$new_lines" ]]; then
          ui_msg "$MANAGER_NAME" "No rules were added (possible conflicts)."
        else
          rules_lines+="$new_lines"
          ui_msg "$MANAGER_NAME" "Rules added."
        fi
        ;;
      2) break ;;
      *) ;;
    esac
  done

  printf "%b" "$rules_lines"
}

extract_ports_rules_from_config(){
  local cfg="$1"
  awk '
    BEGIN{inports=0}
    /^\s*ports\s*=\s*\[/{inports=1;next}
    inports==1{
      if ($0 ~ /\]/){inports=0;next}
      gsub(/"|,/, "", $0); gsub(/^[[:space:]]+/, "", $0); gsub(/[[:space:]]+$/, "", $0);
      if (length($0)>0) print $0;
    }
  ' "$cfg" 2>/dev/null || true
}

rewrite_ports_block_in_config(){
  local cfg="$1"
  local new_lines="$2"

  local tmp="/tmp/bhm_cfg_$$.toml"
  awk '
    BEGIN{inports=0}
    /^\s*ports\s*=\s*\[/{inports=1;next}
    inports==1{
      if ($0 ~ /\]/){inports=0}
      next
    }
    {print}
  ' "$cfg" > "$tmp"

  cat >> "$tmp" <<EOF

ports = [
$(printf "%b" "$new_lines")
]
EOF

  mv "$tmp" "$cfg"
  chmod 600 "$cfg" || true
}

ports_manage_interactive(){
  local name="$1"
  local cfg
  cfg="$(tunnel_config_path "$name")"
  [[ -f "$cfg" ]] || { ui_msg "$MANAGER_NAME" "Config not found."; return 1; }

  if ! grep -q '^\[server\]' "$cfg"; then
    ui_msg "$MANAGER_NAME" "This tunnel is not a server tunnel. Ports rules apply to server config."
    return 0
  fi

  local rules=()
  local line
  while read -r line; do
    [[ -n "$line" ]] || continue
    rules+=("$line")
  done < <(extract_ports_rules_from_config "$cfg")

  while true; do
    local preview="Current rules:\n"
    if (( ${#rules[@]} == 0 )); then
      preview+="(none)\n"
    else
      local i=1
      local r
      for r in "${rules[@]}"; do
        preview+="$i) $r\n"
        ((i++))
      done
    fi

    local sel
    sel="$(ui_menu "$MANAGER_NAME" "$(printf "%b" "$preview")\nChoose action:" \
      "1" "Add rules (comma-separated ports list wizard)" \
      "2" "Remove a rule (by number)" \
      "3" "Save and exit" \
      "0" "Cancel" \
    )" || return 1

    case "$sel" in
      1)
        local new_lines
        new_lines="$(collect_ports_rules_wizard)"
        if [[ -n "$new_lines" ]]; then
          while read -r l; do
            l="${l//\"/}"
            l="${l//,/}"
            l="$(echo "$l" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
            [[ -n "$l" ]] && rules+=("$l")
          done < <(printf "%b" "$new_lines")
        fi
        ;;
      2)
        if (( ${#rules[@]} == 0 )); then
          ui_msg "$MANAGER_NAME" "No rules to remove."
          continue
        fi
        local idx
        while true; do
          idx="$(ui_input "$MANAGER_NAME" "Enter rule number to remove:" "1")" || return 1
          [[ "$idx" =~ ^[0-9]+$ ]] || { ui_msg "$MANAGER_NAME" "Invalid number."; continue; }
          (( idx >= 1 && idx <= ${#rules[@]} )) || { ui_msg "$MANAGER_NAME" "Out of range."; continue; }
          break
        done
        unset 'rules[idx-1]'
        local tmp=()
        local r
        for r in "${rules[@]}"; do tmp+=("$r"); done
        rules=("${tmp[@]}")
        ui_msg "$MANAGER_NAME" "Rule removed."
        ;;
      3)
        local out=""
        local r
        for r in "${rules[@]}"; do
          out+="\"$r\",\n"
        done
        rewrite_ports_block_in_config "$cfg" "$out"
        systemd_reload
        systemctl restart "$(service_name "$name")" >/dev/null 2>&1 || true
        ui_msg "$MANAGER_NAME" "Ports rules saved and service restarted."
        return 0
        ;;
      0) return 0 ;;
      *) ;;
    esac
  done
}

write_tunnel_config(){
  local name="$1"
  local role="$2"
  local transport="$3"
  local cfg
  cfg="$(tunnel_config_path "$name")"

  local token bind_addr remote_addr edge_ip
  local keepalive heartbeat channel_size nodelay web_port log_level
  local connection_pool aggressive_pool dial_timeout retry_interval
  local mux_con mux_version mux_framesize mux_recievebuffer mux_streambuffer
  local tls_cert="" tls_key=""

  token="$(ui_input "$MANAGER_NAME" "Token (Enter for random default):" "$(default_token)")" || return 1

  keepalive="$(ui_input "$MANAGER_NAME" "keepalive_period (seconds):" "75")" || return 1
  channel_size="$(ui_input "$MANAGER_NAME" "channel_size:" "2048")" || return 1
  nodelay="$(ui_input "$MANAGER_NAME" "nodelay (true/false):" "true")" || return 1
  web_port="$(ui_input "$MANAGER_NAME" "web_port (0=disabled):" "0")" || return 1
  log_level="$(ui_input "$MANAGER_NAME" "log_level (debug/info/warn/error):" "info")" || return 1

  heartbeat="$(ui_input "$MANAGER_NAME" "heartbeat (seconds):" "40")" || return 1

  mux_con="8"
  mux_version="1"
  mux_framesize="32768"
  mux_recievebuffer="4194304"
  mux_streambuffer="65536"

  # TLS if needed
  if [[ "$transport" == "wss" || "$transport" == "wssmux" ]]; then
    if [[ "$role" == "server" ]]; then
      local sslsel
      sslsel="$(ui_menu "$MANAGER_NAME" "TLS option (Server):" \
        "self" "Self-signed (quick)" \
        "le" "Let's Encrypt (requires free port 80 + domain)" \
        "import" "Import existing cert/key paths" \
      )" || return 1

      local pair
      case "$sslsel" in
        self) pair="$(ssl_self_signed "$name")" ;;
        le) pair="$(ssl_letsencrypt "$name")" ;;
        import) pair="$(ssl_import)" ;;
        *) die "Invalid TLS option." ;;
      esac
      tls_cert="${pair%%|*}"
      tls_key="${pair##*|}"
    fi
  fi

  if [[ "$role" == "server" ]]; then
    while true; do
      bind_addr="$(ui_input "$MANAGER_NAME" "bind_addr (e.g. 0.0.0.0:3080 or [::]:3080):" "0.0.0.0:3080")" || return 1
      if [[ "$bind_addr" =~ ^\[[0-9a-fA-F:]+\]:[0-9]{1,5}$ ]] || [[ "$bind_addr" =~ ^[^[:space:]]+:[0-9]{1,5}$ ]]; then
        local p="${bind_addr##*:}"
        valid_port "$p" || { ui_msg "$MANAGER_NAME" "Invalid bind port."; continue; }
        if ! ensure_no_port_conflict "$p"; then
          ui_msg "$MANAGER_NAME" "Port conflict detected for bind_addr port: $p"
          continue
        fi
        break
      fi
      ui_msg "$MANAGER_NAME" "Invalid bind_addr format."
    done

    local ports_lines
    ports_lines="$(collect_ports_rules_wizard)"

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
mux_con = ${mux_con}
mux_version = ${mux_version}
mux_framesize = ${mux_framesize}
mux_recievebuffer = ${mux_recievebuffer}
mux_streambuffer = ${mux_streambuffer}
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

    cat >> "$cfg" <<EOF
ports = [
$(printf "%b" "$ports_lines")
]
EOF

  else
    while true; do
      remote_addr="$(ui_input "$MANAGER_NAME" "remote_addr (IPv4/IPv6/Domain) e.g. 1.2.3.4:3080 or example.com:443 or [v6]:3080:" "0.0.0.0:3080")" || return 1
      valid_hostport "$remote_addr" && break
      ui_msg "$MANAGER_NAME" "Invalid remote_addr format."
    done

    if [[ "$transport" == "ws" || "$transport" == "wss" || "$transport" == "wsmux" || "$transport" == "wssmux" ]]; then
      edge_ip="$(ui_input "$MANAGER_NAME" "edge_ip (optional, Enter to skip):" "")" || return 1
    else
      edge_ip=""
    fi

    connection_pool="$(ui_input "$MANAGER_NAME" "connection_pool:" "8")" || return 1
    aggressive_pool="$(ui_input "$MANAGER_NAME" "aggressive_pool (true/false):" "false")" || return 1
    dial_timeout="$(ui_input "$MANAGER_NAME" "dial_timeout (seconds):" "10")" || return 1
    retry_interval="$(ui_input "$MANAGER_NAME" "retry_interval (seconds):" "3")" || return 1

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
mux_version = ${mux_version}
mux_framesize = ${mux_framesize}
mux_recievebuffer = ${mux_recievebuffer}
mux_streambuffer = ${mux_streambuffer}
EOF
    fi
  fi

  chmod 600 "$cfg" || true
}

########################################
# Tunnels listing / status
########################################
list_tunnels(){
  ls -1 "${TUNNELS_DIR}"/*.toml 2>/dev/null | sed -E 's#.*/##; s#\.toml$##' || true
}

tunnel_status_text(){
  local name="$1"
  local svc
  svc="$(service_name "$name")"
  if systemctl is-active --quiet "$svc"; then
    echo "active"
  else
    echo "inactive"
  fi
}

########################################
# Main actions
########################################
install_everything(){
  ensure_prereqs
  init_ui
  install_system_layout
  install_systemd_template
  install_manager_self

  install_or_update_core
  install_health_units

  ui_msg "$MANAGER_NAME" \
"Setup completed.

Manager command: ${MANAGER_CMD}
Manager repo:    ${MANAGER_REPO_URL}

Core runtime version output:
$(core_version_runtime)

Core tag tracking:
$(core_version_local)"
}

create_tunnel(){
  core_installed || { ui_msg "$MANAGER_NAME" "Core is not installed. Choose 'Core install/update' first."; return 1; }

  local name
  while true; do
    name="$(ui_input "$MANAGER_NAME" "Tunnel name (a-zA-Z0-9_- , max 32):" "")" || return 1
    valid_name "$name" || { ui_msg "$MANAGER_NAME" "Invalid tunnel name."; continue; }
    if tunnel_exists "$name"; then
      ui_msg "$MANAGER_NAME" "Tunnel name already exists."
      continue
    fi
    break
  done

  local role transport
  role="$(choose_role)" || return 1
  transport="$(choose_transport)" || return 1

  write_tunnel_config "$name" "$role" "$transport" || return 1

  systemd_reload
  systemctl enable "$(service_name "$name")" >/dev/null 2>&1 || true
  systemctl restart "$(service_name "$name")" >/dev/null 2>&1 || true

  ui_msg "$MANAGER_NAME" \
"Tunnel created.

Name:      $name
Role:      $role
Transport: $transport

Service:
$(service_name "$name")"
}

edit_tunnel(){
  local name="$1"
  local cfg
  cfg="$(tunnel_config_path "$name")"
  [[ -f "$cfg" ]] || { ui_msg "$MANAGER_NAME" "Config not found."; return 1; }

  local role transport
  if grep -q '^\[server\]' "$cfg"; then role="server"; else role="client"; fi
  transport="$(grep -E '^\s*transport\s*=' "$cfg" | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')" || true
  [[ -n "$transport" ]] || transport="tcp"

  local sel
  sel="$(ui_menu "$MANAGER_NAME" "Edit tunnel: $name" \
    "1" "Interactive rewrite (keeps role/transport, asks all fields again)" \
    "2" "Edit ports rules (server only: add/remove)" \
    "3" "Open config file in editor (nano/vi)" \
    "0" "Back" \
  )" || return 1

  case "$sel" in
    1)
      write_tunnel_config "$name" "$role" "$transport" || return 1
      systemd_reload
      systemctl restart "$(service_name "$name")" >/dev/null 2>&1 || true
      ui_msg "$MANAGER_NAME" "Config updated and service restarted."
      ;;
    2)
      ports_manage_interactive "$name"
      ;;
    3)
      if cmd_exists nano; then nano "$cfg"; else vi "$cfg"; fi
      systemd_reload
      systemctl restart "$(service_name "$name")" >/dev/null 2>&1 || true
      ui_msg "$MANAGER_NAME" "Editor closed. Service restarted."
      ;;
    0) ;;
  esac
}

delete_tunnel(){
  local name="$1"
  if ! ui_yesno "$MANAGER_NAME" "Delete tunnel '$name'?\nThis removes config, service, and SSL files for this tunnel."; then
    return 0
  fi
  systemctl disable --now "$(service_name "$name")" >/dev/null 2>&1 || true
  rm -f "$(tunnel_config_path "$name")" || true
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
    ui_textarea "$MANAGER_NAME" "$(cat "/tmp/${svc}.log" 2>/dev/null || echo "No logs available.")"
  else
    ui_msg "$MANAGER_NAME" "journalctl not available."
  fi
}

manage_tunnel_actions(){
  local name="$1"
  while true; do
    local status
    status="$(tunnel_status_text "$name")"
    local sel
    sel="$(ui_menu "$MANAGER_NAME" "Tunnel: $name (status: $status)" \
      "1" "Start" \
      "2" "Stop" \
      "3" "Restart" \
      "4" "Status details" \
      "5" "Edit" \
      "6" "Logs (last 120 lines)" \
      "7" "Delete" \
      "0" "Back" \
    )" || return 1

    case "$sel" in
      1) systemctl start "$(service_name "$name")" >/dev/null 2>&1 || ui_msg "$MANAGER_NAME" "Start failed." ;;
      2) systemctl stop "$(service_name "$name")" >/dev/null 2>&1 || ui_msg "$MANAGER_NAME" "Stop failed." ;;
      3) systemctl restart "$(service_name "$name")" >/dev/null 2>&1 || ui_msg "$MANAGER_NAME" "Restart failed." ;;
      4)
        systemctl status "$(service_name "$name")" --no-pager | sed 's/\x1b\[[0-9;]*m//g' > "/tmp/bhm_status_${name}.txt" || true
        ui_textarea "$MANAGER_NAME" "$(cat "/tmp/bhm_status_${name}.txt" 2>/dev/null || echo "No status output.")"
        ;;
      5) edit_tunnel "$name" ;;
      6) show_logs "$name" ;;
      7) delete_tunnel "$name"; return 0 ;;
      0) return 0 ;;
      *) ;;
    esac
  done
}

manage_tunnel_menu(){
  local tunnels
  tunnels="$(list_tunnels)"
  [[ -n "$tunnels" ]] || { ui_msg "$MANAGER_NAME" "No tunnels found."; return 0; }

  local args=()
  local t
  while read -r t; do
    [[ -n "$t" ]] || continue
    args+=("$t" "status: $(tunnel_status_text "$t")")
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
  ui_msg "$MANAGER_NAME" "Restart all completed.\nSuccess: $ok\nFailed:  $fail"
}

uninstall_all(){
  if ! ui_yesno "$MANAGER_NAME" "Full uninstall?\nThis removes ALL tunnels, configs, services, SSL files, cron, and health timer."; then
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

  disable_health_timer || true
  rm -f "$HEALTH_TIMER" "$HEALTH_SERVICE" >/dev/null 2>&1 || true

  rm -f "$SYSTEMD_TEMPLATE" >/dev/null 2>&1 || true
  systemd_reload

  rm -f "$CRON_FILE" >/dev/null 2>&1 || true

  rm -rf "$BASE_DIR" >/dev/null 2>&1 || true
  rm -rf "$LOG_DIR" >/dev/null 2>&1 || true

  rm -f "$MANAGER_INSTALL_PATH" >/dev/null 2>&1 || true

  if ui_yesno "$MANAGER_NAME" "Remove core binary (${CORE_INSTALL_PATH}) too?"; then
    rm -f "$CORE_INSTALL_PATH" >/dev/null 2>&1 || true
  fi

  ui_msg "$MANAGER_NAME" "Uninstall completed."
}

########################################
# Header / About
########################################
tunnels_count(){
  local n
  n="$(ls -1 "${TUNNELS_DIR}"/*.toml 2>/dev/null | wc -l | tr -d ' ')"
  echo "$n"
}

health_timer_status(){
  if systemctl is-enabled --quiet backhaul-manager-health.timer 2>/dev/null; then
    echo "enabled"
  else
    echo "disabled"
  fi
}

about_screen(){
  ui_textarea "$MANAGER_NAME" \
"Backhaul Manager

Repo: ${MANAGER_REPO_URL}

Core repo: https://github.com/${CORE_REPO}

Core runtime version output:
$(core_version_runtime)

Core tag tracking (local):
$(core_version_local)

Tunnels directory:
${TUNNELS_DIR}

Health-check timer:
$(health_timer_status)

Cron file:
${CRON_FILE}"
}

########################################
# CLI flags (cron / timer)
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
# Menu
########################################
main_menu(){
  while true; do
    local core_tag core_run
    core_tag="$(core_version_local)"
    core_run="$(core_version_runtime)"

    local hdr
    hdr="Repo: ${MANAGER_REPO_URL}\nCore tag: ${core_tag}\nTunnels: $(tunnels_count)\nHealth timer: $(health_timer_status)\n\nChoose an option:"

    local sel
    sel="$(ui_menu "$MANAGER_NAME" "$hdr" \
      "1" "Install/Setup Manager + Install/Update Core" \
      "2" "Core install/update (check latest and update if needed)" \
      "3" "Create new tunnel" \
      "4" "Manage tunnels" \
      "5" "Restart ALL tunnels" \
      "6" "Health-check timer (systemd) settings" \
      "7" "Cron periodic restart settings" \
      "8" "About" \
      "9" "Uninstall (remove everything)" \
      "0" "Exit" \
    )" || exit 0

    case "$sel" in
      1) install_everything ;;
      2) install_or_update_core ;;
      3) create_tunnel ;;
      4) manage_tunnel_menu ;;
      5) restart_all_tunnels ;;
      6)
        local hsel
        hsel="$(ui_menu "$MANAGER_NAME" "Health-check timer settings:" \
          "1" "Enable health-check timer (every ~2 minutes)" \
          "2" "Disable health-check timer" \
          "3" "Show timer status" \
          "0" "Back" \
        )" || true
        case "$hsel" in
          1) enable_health_timer ;;
          2) disable_health_timer ;;
          3)
            systemctl status backhaul-manager-health.timer --no-pager | sed 's/\x1b\[[0-9;]*m//g' > /tmp/bhm_timer_status.txt || true
            ui_textarea "$MANAGER_NAME" "$(cat /tmp/bhm_timer_status.txt 2>/dev/null || echo "No output.")"
            ;;
          0) ;;
        esac
        ;;
      7) setup_periodic_restart_cron ;;
      8) about_screen ;;
      9) uninstall_all ;;
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
install_manager_self
install_health_units
handle_cli "$@"

# First-run suggestion
if ! core_installed; then
  if ui_yesno "$MANAGER_NAME" "Core is not installed.\nRun setup now (install/update core + manager)?"; then
    install_everything
  fi
fi

main_menu

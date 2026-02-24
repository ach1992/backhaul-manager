# Backhaul Manager

**Backhaul Manager** is an interactive (menu-driven) Bash tool that installs the Backhaul core binary, creates/manages Backhaul tunnels, and optionally sets up automated restarts and health-checks using **systemd timers** or **cron**.

> Manager repo: https://github.com/ach1992/backhaul-manager/  
> Backhaul core repo: https://github.com/Musixal/Backhaul

---

## Features

- One-command install/update (installs a `backhaul-manager` command).
- Create new tunnels (server/client) with guided prompts.
- Supports transports: `tcp`, `tcpmux`, `udp`, `ws`, `wss`, `wsmux`, `wssmux`.
- TLS automation for `wss` / `wssmux` server tunnels:
  - Let's Encrypt (certbot standalone)
  - Self-signed (openssl)
- Systemd service per tunnel (`backhaul-<name>.service`).
- Manage tunnels: start/stop/restart/status/edit config/delete.
- Restart all tunnels (manual or scheduled).
- Health-check mode: restarts a tunnel service if it is not **active** in systemd.
- Offline install support for the Backhaul core tarball.

---

## Requirements

- Linux host with **systemd**
- Root access (or `sudo`)
- Packages (auto-installed if missing): `curl`, `tar`, `gawk`, `sed`, `grep`, `iproute2` (for `ss`)
- Optional (only if you use TLS features):
  - `certbot` (Let's Encrypt)
  - `openssl` (self-signed)

Supported architectures for core auto-install:
- `amd64/x86_64`
- `arm64/aarch64`

---

## Quick Install (Online)

Run:

```bash
curl -fsSL https://raw.githubusercontent.com/ach1992/backhaul-manager/main/backhaul-manager.sh | sudo bash -s -- --install
```

Then start the menu:

```bash
sudo backhaul-manager
```

---

## Install / Update (Already downloaded script)

If you have the script locally:

```bash
sudo bash backhaul-manager.sh --install
```

(You can also use `--update` which is equivalent.)

---

## Offline Install (Core Binary)

The manager can install the Backhaul core binary **offline** if you provide the correct release tarball in:

```bash
/root/backhaul-manager/
```

1) On a machine with internet, download the correct core asset for your architecture:
- `amd64/x86_64`  → `backhaul_linux_amd64.tar.gz`
- `arm64/aarch64` → `backhaul_linux_arm64.tar.gz`

2) Copy the file to the target server:

```bash
sudo mkdir -p /root/backhaul-manager
sudo cp backhaul_linux_amd64.tar.gz /root/backhaul-manager/
```

3) Run install:

```bash
sudo bash backhaul-manager.sh --install
```

During installation, the script will detect the offline tarball and ask whether to use it.

---

## What Gets Installed / Created

### Commands & binaries
- Manager script: `/opt/backhaul-manager/backhaul-manager.sh`
- Command symlink: `/usr/local/bin/backhaul-manager`
- Backhaul core binary: `/usr/local/bin/backhaul`

### Config & state
- Tunnel configs (TOML): `/etc/backhaul-manager/tunnels/<name>.toml`
- TLS files (per tunnel): `/etc/backhaul-manager/tunnels/.tls/<name>/`
- Tunnel database: `/var/lib/backhaul-manager/tunnels.db`
- Logs: `/var/log/backhaul-manager/manager.log`

### Systemd units
- Tunnel service: `/etc/systemd/system/backhaul-<name>.service`
- Optional scheduling:
  - `backhaul-manager-restart-all.timer/.service`
  - `backhaul-manager-health-check.timer/.service`

---

## Usage (Menu)

Run:

```bash
sudo backhaul-manager
```

Main menu:
- Install / Update
- Create new tunnel
- Manage tunnels
- Restart all tunnels
- Scheduling (cron/timer/health-check)
- Uninstall

---

## TLS (WSS / WSSMUX)

When creating a **server** tunnel with `wss` or `wssmux`, the manager will require TLS and offers:

### 1) Let's Encrypt (certbot standalone)
- Requires an FQDN (domain) pointing to your server.
- Requires inbound **port 80** reachable (HTTP-01 challenge).
- The tool runs `certbot certonly --standalone ...` and copies:
  - `fullchain.pem`
  - `privkey.pem`
  into the tunnel's TLS directory.

### 2) Self-signed (openssl)
- Generates a self-signed certificate locally.

The TOML config stores file paths (not inline PEM content), e.g.:

```toml
tls_cert = "/etc/backhaul-manager/tunnels/.tls/<name>/fullchain.pem"
tls_key  = "/etc/backhaul-manager/tunnels/.tls/<name>/privkey.pem"
```

---

## Scheduling

Open: **Scheduling (cron/timer/health-check)** from the menu.

Options:
- **Cron restart-all**: restarts every *N* minutes (simple, less precise).
- **Systemd timer restart-all**: recommended over cron.
- **Health-check timer**: safest option.

### Health-check behavior
Health-check loops over all tunnels in the internal DB and checks each tunnel service with:

```bash
systemctl is-active backhaul-<name>.service
```

If the service is **not** `active`, it restarts it:

```bash
systemctl restart backhaul-<name>.service
```

Health-check writes actions to:

```bash
/var/log/backhaul-manager/manager.log
```

Example log line:
```
[YYYY-MM-DD HH:MM:SS] Health-check: backhaul-tunnel1.service is inactive, restarting...
```

---

## CLI (Non-interactive) Commands

The script supports a few command-line flags, useful for systemd/cron:

```bash
sudo backhaul-manager --install
sudo backhaul-manager --update
sudo backhaul-manager --restart-all
sudo backhaul-manager --health-check
```

---

## Troubleshooting

### Check a tunnel service
```bash
systemctl status backhaul-<name>.service --no-pager -l
journalctl -u backhaul-<name>.service -n 200 --no-pager
```

### Check manager logs
```bash
tail -n 200 /var/log/backhaul-manager/manager.log
```

### Check timers
```bash
systemctl list-timers --all | grep backhaul-manager
systemctl status backhaul-manager-health-check.timer --no-pager
systemctl status backhaul-manager-restart-all.timer --no-pager
```

### Common TLS issues
- **Let's Encrypt fails**: make sure port **80** is free and reachable, and DNS A/AAAA points to the server IP.
- **TOML parse errors about newlines**: `tls_cert`/`tls_key` must be file paths, not embedded PEM text.

---

## Uninstall

From the main menu choose **Uninstall**.

This removes:
- Tunnel configs/services (and TLS files)
- Scheduling (cron + timers)
- Manager directories and logs

It can optionally remove the core binary (`/usr/local/bin/backhaul`) as well.

---

## Security Notes

- Tunnel configs contain tokens/secrets; keep `/etc/backhaul-manager` protected.
- TLS private keys are stored with `600` permissions in the tunnel TLS directory.

---

## License

Add your license here (e.g., MIT) if you plan to publish publicly.

#!/bin/bash
#
# install.sh — Portable Network Vulnerability Scanner installer
#
# Detects its own install location and the current user automatically
# (thanks to config.py, nothing in the Python codebase assumes a
# specific username or path anymore), then sets up everything needed
# to run: system dependencies, a Python venv, sudoers permissions, a
# systemd service for the dashboard, and an Ollama preload service.
#
# SAFE TO RE-RUN: every generated file (sudoers entry, systemd units)
# is written fresh from a template each time, not appended to. So if
# a future update needs a new permission or dependency, just update
# this script and run it again — it won't duplicate or break the
# existing install.
#
# Usage:
#   cd network-scanner/        (wherever you cloned/copied the project)
#   chmod +x install.sh
#   ./install.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_USER="$(whoami)"
VENV_PYTHON="$SCRIPT_DIR/venv/bin/python3"

log()  { echo "[*] $1"; }
ok()   { echo "[+] $1"; }
warn() { echo "[!] $1"; }

echo "============================================================"
echo "  PORTABLE NETWORK VULNERABILITY SCANNER — INSTALLER"
echo "============================================================"
log "Install directory: $SCRIPT_DIR"
log "Install user:      $INSTALL_USER"
echo ""

# ── 1. System dependencies ──────────────────────────────────
log "Checking for nmap..."
if command -v nmap &> /dev/null; then
    ok "nmap already installed."
elif command -v apt-get &> /dev/null; then
    log "Installing nmap via apt..."
    sudo apt-get update -qq
    sudo apt-get install -y nmap
    ok "nmap installed."
else
    warn "apt-get not found — please install nmap manually for your distro, then re-run this script."
fi

log "Checking for Ollama..."
if command -v ollama &> /dev/null; then
    ok "Ollama already installed."
else
    log "Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
    ok "Ollama installed."
fi

log "Pulling phi3:mini model (this may take a few minutes)..."
ollama pull phi3:mini
ok "phi3:mini ready."
echo ""

# ── 2. Python virtual environment ───────────────────────────
log "Setting up Python virtual environment..."
python3 -m venv "$SCRIPT_DIR/venv"
"$SCRIPT_DIR/venv/bin/pip" install --quiet --upgrade pip
"$SCRIPT_DIR/venv/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements.txt"
ok "Python dependencies installed."
echo ""

# ── 3. Sudoers entry ─────────────────────────────────────────
# scanner.py and main.py need root for nmap's OS detection; stop-scan
# needs root to kill a running scan. Generated fresh each run so this
# stays correct even if the install path or user changes.
log "Configuring sudoers (passwordless nmap/kill access for this install only)..."
SUDOERS_FILE="/etc/sudoers.d/scanner"
SUDOERS_TMP="$(mktemp)"

cat > "$SUDOERS_TMP" <<EOF
$INSTALL_USER ALL=(ALL) NOPASSWD: $VENV_PYTHON $SCRIPT_DIR/scanner.py
$INSTALL_USER ALL=(ALL) NOPASSWD: $VENV_PYTHON $SCRIPT_DIR/main.py
$INSTALL_USER ALL=(ALL) NOPASSWD: /bin/kill
EOF

if sudo visudo -cf "$SUDOERS_TMP"; then
    sudo cp "$SUDOERS_TMP" "$SUDOERS_FILE"
    sudo chmod 0440 "$SUDOERS_FILE"
    ok "Sudoers entry installed."
else
    warn "Generated sudoers file failed validation — skipping. Scans requiring sudo will prompt for a password until this is fixed manually."
fi
rm -f "$SUDOERS_TMP"
echo ""

# ── 4. Dashboard credentials ────────────────────────────────
log "Set credentials for the dashboard (protects it with HTTP Basic Auth)."
read -p "    Username: " DASH_USER
while true; do
    read -s -p "    Password: " DASH_PASS; echo ""
    read -s -p "    Confirm password: " DASH_PASS_CONFIRM; echo ""
    if [ "$DASH_PASS" = "$DASH_PASS_CONFIRM" ] && [ -n "$DASH_PASS" ]; then
        break
    fi
    warn "Passwords didn't match or were empty — try again."
done
echo ""

# ── 5. systemd service — dashboard ──────────────────────────
log "Setting up the dashboard systemd service..."
sudo tee /etc/systemd/system/scanner.service > /dev/null <<EOF
[Unit]
Description=Network Vulnerability Scanner Dashboard
After=network.target

[Service]
Type=simple
User=$INSTALL_USER
WorkingDirectory=$SCRIPT_DIR
Environment=SCANNER_USERNAME=$DASH_USER
Environment=SCANNER_PASSWORD=$DASH_PASS
ExecStart=$VENV_PYTHON $SCRIPT_DIR/app.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable scanner --quiet
sudo systemctl restart scanner
ok "Dashboard service installed and running."
echo ""

# ── 6. systemd service — Ollama preload ─────────────────────
log "Setting up the Ollama preload service (keeps phi3:mini resident in RAM)..."
chmod +x "$SCRIPT_DIR/preload_ollama.sh"

sudo tee /etc/systemd/system/ollama-preload.service > /dev/null <<EOF
[Unit]
Description=Preload Phi-3 Mini into Ollama RAM at boot
After=ollama.service network-online.target
Wants=ollama.service network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=$INSTALL_USER
ExecStart=$SCRIPT_DIR/preload_ollama.sh

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable ollama-preload.service --quiet
sudo systemctl start ollama-preload.service
ok "Ollama preload service installed and running."
echo ""

# ── 7. History directory ────────────────────────────────────
mkdir -p "$SCRIPT_DIR/history"

# ── 8. Optional: offline CVE cache ──────────────────────────
read -p "Build the offline CVE cache now? Needs internet, takes a few minutes. [y/N]: " BUILD_CACHE
if [[ "$BUILD_CACHE" =~ ^[Yy]$ ]]; then
    log "Building CVE cache..."
    "$VENV_PYTHON" "$SCRIPT_DIR/build_cve_cache.py"
    ok "CVE cache built."
else
    log "Skipped — you can build it later with: $VENV_PYTHON build_cve_cache.py"
fi
echo ""

# ── 9. Summary ───────────────────────────────────────────────
IP_ADDR="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo "============================================================"
ok "Install complete."
echo "    Dashboard: http://${IP_ADDR:-<this-machine-ip>}:5000"
echo "    Username:  $DASH_USER"
echo "============================================================"

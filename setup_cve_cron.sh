#!/bin/bash
#
# setup_cve_cron.sh
#
# Interactively schedules automatic refreshing of the offline CVE
# cache (cve_cache.json) via cron — entirely through plain-English
# questions (which day, what time). No cron syntax knowledge needed;
# the script builds the correct schedule internally.
#
# Safe to re-run at any time to change the schedule — it overwrites
# the existing cron entry rather than adding a duplicate.
#
# Note: cron only fires if the machine is actually powered on and
# connected to the internet at the scheduled time. On a portable
# device that isn't guaranteed to be always-on, this is a convenience
# layer on top of manually running build_cve_cache.py, not a
# guarantee the cache is always fresh.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_USER="$(whoami)"
VENV_PYTHON="$SCRIPT_DIR/venv/bin/python3"
CRON_FILE="/etc/cron.d/scanner-cve-cache"

DAY_NAMES=(Sunday Monday Tuesday Wednesday Thursday Friday Saturday)

log()  { echo "[*] $1"; }
ok()   { echo "[+] $1"; }
warn() { echo "[!] $1"; }

# Make sure cron itself is installed and running (not guaranteed on
# minimal server images).
if ! command -v crontab &> /dev/null; then
    log "Installing cron..."
    sudo apt-get update -qq
    sudo apt-get install -y cron
fi
sudo systemctl enable --now cron > /dev/null 2>&1 || true

read_time() {
    # Prompts until a valid 24-hour HH:MM time is entered.
    # Accepts both "9:00" and "09:00" style input.
    while true; do
        read -p "    What time? (24-hour, e.g. 9:00 or 03:00): " TIME_INPUT
        if [[ "$TIME_INPUT" =~ ^(0?[0-9]|1[0-9]|2[0-3]):([0-5][0-9])$ ]]; then
            HOUR="${BASH_REMATCH[1]}"
            MINUTE="${BASH_REMATCH[2]}"
            break
        else
            warn "That doesn't look like a valid time — try something like 3:00 or 14:30."
        fi
    done
}

echo ""
echo "How often should the offline CVE cache refresh automatically?"
echo "  1) Daily at 3:00 AM (recommended)"
echo "  2) Daily, at a time I choose"
echo "  3) Weekly, on a day and time I choose"
echo "  4) Monthly, on the 1st at 3:00 AM"
echo "  5) Don't schedule anything — I'll refresh manually"
read -p "Choice [1-5]: " CHOICE

DESCRIPTION=""
CRON_SCHEDULE=""

case "$CHOICE" in
    1)
        CRON_SCHEDULE="0 3 * * *"
        DESCRIPTION="every day at 3:00"
        ;;
    2)
        read_time
        CRON_SCHEDULE="$MINUTE $HOUR * * *"
        DESCRIPTION="every day at $HOUR:$MINUTE"
        ;;
    3)
        echo "    Which day?"
        for i in "${!DAY_NAMES[@]}"; do
            echo "      $i) ${DAY_NAMES[$i]}"
        done
        read -p "    Choice [0-6]: " DOW
        if ! [[ "$DOW" =~ ^[0-6]$ ]]; then
            warn "That's not a valid day — defaulting to Sunday."
            DOW=0
        fi
        read_time
        CRON_SCHEDULE="$MINUTE $HOUR * * $DOW"
        DESCRIPTION="every ${DAY_NAMES[$DOW]} at $HOUR:$MINUTE"
        ;;
    4)
        CRON_SCHEDULE="0 3 1 * *"
        DESCRIPTION="on the 1st of every month at 3:00"
        ;;
    *)
        CRON_SCHEDULE=""
        ;;
esac

if [ -n "$CRON_SCHEDULE" ]; then
    sudo tee "$CRON_FILE" > /dev/null <<EOF
# Automatic offline CVE cache refresh for the Network Vulnerability Scanner
# Schedule: $DESCRIPTION (set via setup_cve_cron.sh)
# Runs as $INSTALL_USER (not root) so cve_cache.json's ownership stays
# consistent with the rest of the project's files.
$CRON_SCHEDULE $INSTALL_USER $VENV_PYTHON $SCRIPT_DIR/build_cve_cache.py >> $SCRIPT_DIR/cve_cache_update.log 2>&1
EOF
    sudo chmod 0644 "$CRON_FILE"
    ok "CVE cache auto-refresh scheduled: $DESCRIPTION"
    log "Logs will be written to $SCRIPT_DIR/cve_cache_update.log"
else
    if [ -f "$CRON_FILE" ]; then
        sudo rm -f "$CRON_FILE"
        log "Removed any existing auto-refresh schedule."
    fi
    log "No schedule set — run '$VENV_PYTHON build_cve_cache.py' manually anytime to refresh."
fi

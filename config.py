"""
config.py

Central place for filesystem paths used across the scanner project.

Every path is derived from this file's own location (BASE_DIR) rather
than hardcoded per-script. This is what lets the whole project run
correctly regardless of which user account or directory it's
installed under — previously everything assumed the specific path
/home/admin/scanner and the specific user 'admin', which only worked
because that happens to be this Pi's setup. A different install
(different username, different path, a future non-Pi machine) would
have silently broken without this.

Nothing here needs editing by hand — it's computed automatically from
wherever this file happens to live.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Core data files ──────────────────────────────────────────
SCAN_STATUS_PATH      = os.path.join(BASE_DIR, 'scan_status.json')
SCAN_RESULTS_PATH     = os.path.join(BASE_DIR, 'scan_results.json')
ANALYSIS_RESULTS_PATH = os.path.join(BASE_DIR, 'analysis_results.json')
LLM_REPORT_PATH       = os.path.join(BASE_DIR, 'llm_report.txt')
CVE_CACHE_PATH         = os.path.join(BASE_DIR, 'cve_cache.json')
HISTORY_DIR            = os.path.join(BASE_DIR, 'history')

# ── Interpreter / entrypoints ────────────────────────────────
# Used when one script needs to launch another (e.g. app.py spawning
# main.py, main.py spawning scanner.py) via the venv's own Python.
VENV_PYTHON    = os.path.join(BASE_DIR, 'venv', 'bin', 'python3')
MAIN_SCRIPT    = os.path.join(BASE_DIR, 'main.py')
SCANNER_SCRIPT = os.path.join(BASE_DIR, 'scanner.py')

# ── Dashboard port ───────────────────────────────────────────
# Single source of truth for which port the Flask dashboard binds
# to. app.py uses this to start the server, and cve_lookup.py uses
# it to automatically exclude the dashboard's own port from CVE
# lookups — so scanning the Pi itself never mismatches Flask against
# an unrelated CVE (this happened twice: port 5000 -> "Apache"
# SpamAssassin/Airflow, then again on port 5001 after the dashboard
# was moved to make room for a Wireguard/Pi-hole setup). Change the
# port by setting SCANNER_PORT in the systemd unit's environment,
# not by editing this file.
DASHBOARD_PORT = os.environ.get('SCANNER_PORT', '5000')

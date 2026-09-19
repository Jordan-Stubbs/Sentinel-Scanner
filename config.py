import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SCAN_STATUS_PATH      = os.path.join(BASE_DIR, 'scan_status.json')
SCAN_RESULTS_PATH     = os.path.join(BASE_DIR, 'scan_results.json')
ANALYSIS_RESULTS_PATH = os.path.join(BASE_DIR, 'analysis_results.json')
LLM_REPORT_PATH       = os.path.join(BASE_DIR, 'llm_report.txt')
CVE_CACHE_PATH         = os.path.join(BASE_DIR, 'cve_cache.json')
HISTORY_DIR            = os.path.join(BASE_DIR, 'history')

VENV_PYTHON    = os.path.join(BASE_DIR, 'venv', 'bin', 'python3')
MAIN_SCRIPT    = os.path.join(BASE_DIR, 'main.py')
SCANNER_SCRIPT = os.path.join(BASE_DIR, 'scanner.py')

# Traffic monitor - separate lock file from SCAN_STATUS_PATH, since
# this is a genuinely different kind of on-demand check, not part of
# the vulnerability-scan pipeline. Both trigger_scan() and the
# traffic-monitor route check EACH OTHER's lock before starting, so
# they can never run concurrently in either direction.
TRAFFIC_MONITOR_SCRIPT = os.path.join(BASE_DIR, 'traffic_monitor.py')
TRAFFIC_STATUS_PATH    = os.path.join(BASE_DIR, 'traffic_status.json')
TRAFFIC_RESULTS_PATH   = os.path.join(BASE_DIR, 'traffic_results.json')

DASHBOARD_PORT = os.environ.get('SCANNER_PORT', '5000')

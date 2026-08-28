from flask import Flask, render_template, jsonify, send_file, request, Response
import json
import subprocess
import os
import shutil
import socket
import csv
import io
from datetime import datetime
import urllib.request
import urllib.error
import config
from diff import compare_scans

app = Flask(__name__)

# ── Basic auth ───────────────────────────────────────────────
# Credentials come from environment variables (set them in the
# scanner.service systemd unit — see deployment notes) so nothing
# sensitive is hardcoded in this file. Falls back to a default
# admin/changeme pair if unset — CHANGE THIS before relying on it.
DASHBOARD_USERNAME = os.environ.get('SCANNER_USERNAME', 'admin')
DASHBOARD_PASSWORD = os.environ.get('SCANNER_PASSWORD', 'changeme')

def check_auth(username, password):
    return username == DASHBOARD_USERNAME and password == DASHBOARD_PASSWORD

def authenticate():
    return Response(
        'Authentication required to access the Network Vulnerability Scanner.',
        401,
        {'WWW-Authenticate': 'Basic realm="Scanner Dashboard"'}
    )

@app.before_request
def require_auth():
    auth = request.authorization
    if not auth or not check_auth(auth.username, auth.password):
        return authenticate()

def load_json(filepath):
    if not os.path.exists(filepath):
        return None
    with open(filepath) as f:
        return json.load(f)

def get_hostname():
    """Actual machine hostname — used in the dashboard header instead
    of a hardcoded 'Raspberry Pi 4' label, since this now also runs
    on other hardware (verified on an Ubuntu VM, 2026-08-25)."""
    try:
        return socket.gethostname()
    except Exception:
        return 'This Device'

def get_history():
    if not os.path.exists(config.HISTORY_DIR):
        return []
    entries = []
    for name in sorted(os.listdir(config.HISTORY_DIR), reverse=True):
        path = os.path.join(config.HISTORY_DIR, name)
        if not os.path.isdir(path):
            continue
        analysis = load_json(os.path.join(path, 'analysis_results.json'))
        if analysis:
            entries.append({
                'id':              name,
                'timestamp':       analysis.get('timestamp', name),
                'score':           analysis.get('score'),
                'rating':          analysis.get('rating'),
                'findings':        len(analysis.get('findings', [])),
                'duration':        analysis.get('duration', '—'),
                'severity_counts': analysis.get('severity_counts', {}),
            })
    return entries

# ── System resource monitoring ──────────────────────────────
# Keeps the previous /proc/stat reading between requests so CPU
# usage can be computed as a delta rather than a cumulative total.
_cpu_last = {'total': None, 'idle': None}

def read_cpu_percent():
    """Compute CPU usage % since the previous call using /proc/stat deltas."""
    global _cpu_last
    try:
        with open('/proc/stat') as f:
            parts = f.readline().split()
        # Fields: cpu user nice system idle iowait irq softirq steal guest guest_nice
        values = list(map(int, parts[1:]))
        idle  = values[3] + values[4]  # idle + iowait
        total = sum(values)

        if _cpu_last['total'] is None:
            _cpu_last = {'total': total, 'idle': idle}
            return None  # first call — no delta available yet

        total_delta = total - _cpu_last['total']
        idle_delta  = idle - _cpu_last['idle']
        _cpu_last = {'total': total, 'idle': idle}

        if total_delta <= 0:
            return None

        usage = 100 * (1 - (idle_delta / total_delta))
        return round(max(0.0, min(100.0, usage)), 1)
    except Exception:
        return None

# read_memory, read_cpu_temp, and read_ollama_status are shared with
# main.py (which uses them for point-in-time snapshots saved into
# scan history) — defined once in resource_monitor.py rather than
# duplicated here.
from resource_monitor import read_memory, read_cpu_temp, read_ollama_status

@app.route('/api/system')
def api_system():
    return jsonify({
        'cpu_percent': read_cpu_percent(),
        'memory':      read_memory(),
        'cpu_temp':    read_cpu_temp(),
        'ollama':      read_ollama_status(),
    })

@app.route('/')
def index():
    analysis    = load_json(config.ANALYSIS_RESULTS_PATH)
    report_text = None
    scan_meta   = None

    if os.path.exists(config.LLM_REPORT_PATH):
        with open(config.LLM_REPORT_PATH) as f:
            report_text = f.read()

    scan_data = load_json(config.SCAN_RESULTS_PATH)
    if scan_data and isinstance(scan_data, dict):
        scan_meta = scan_data.get('meta')

    history = get_history()

    return render_template('dashboard.html',
                           analysis=analysis,
                           report=report_text,
                           scan_meta=scan_meta,
                           history=history,
                           hostname=get_hostname())

@app.route('/history/<scan_id>')
def view_history(scan_id):
    base        = os.path.join(config.HISTORY_DIR, scan_id)
    analysis    = load_json(os.path.join(base, 'analysis_results.json'))
    report_text = None
    scan_meta   = None

    report_path = os.path.join(base, 'llm_report.txt')
    if os.path.exists(report_path):
        with open(report_path) as f:
            report_text = f.read()

    scan_data = load_json(os.path.join(base, 'scan_results.json'))
    if scan_data and isinstance(scan_data, dict):
        scan_meta = scan_data.get('meta')

    history = get_history()

    return render_template('dashboard.html',
                           analysis=analysis,
                           report=report_text,
                           scan_meta=scan_meta,
                           history=history,
                           viewing_history=scan_id,
                           hostname=get_hostname())

@app.route('/diff/<id_a>/<id_b>')
def view_diff(id_a, id_b):
    dir_a = os.path.join(config.HISTORY_DIR, id_a)
    dir_b = os.path.join(config.HISTORY_DIR, id_b)

    if not os.path.isdir(dir_a) or not os.path.isdir(dir_b):
        return "One or both selected scans could not be found in history.", 404

    try:
        result = compare_scans(dir_a, dir_b)
    except Exception as e:
        return f"Could not compare these scans: {e}", 500

    return render_template('diff.html',
                           diff=result,
                           id_a=id_a,
                           id_b=id_b,
                           hostname=get_hostname())

@app.route('/api/history-trend')
def api_history_trend():
    # get_history() returns newest-first (for the browsing list) —
    # charting wants chronological order, oldest to newest.
    entries = list(reversed(get_history()))
    return jsonify([
        {
            'timestamp': e['timestamp'],
            'score': e['score'],
            'findings': e['findings'],
            'severity_counts': e['severity_counts'],
        }
        for e in entries
    ])

@app.route('/api/results')
def api_results():
    return jsonify({
        'analysis': load_json(config.ANALYSIS_RESULTS_PATH),
        'scan':     load_json(config.SCAN_RESULTS_PATH)
    })

@app.route('/api/history')
def api_history():
    return jsonify(get_history())

@app.route('/api/status')
def scan_status():
    status = load_json(config.SCAN_STATUS_PATH)
    if not status:
        return jsonify({
            'stage':   'idle',
            'message': 'Ready',
            'percent': 0,
            'running': False
        })
    return jsonify(status)

@app.route('/stop-scan', methods=['POST'])
def stop_scan():
    try:
        result = subprocess.run(
            ['pgrep', '-f', 'main.py'],
            capture_output=True, text=True
        )
        pids = result.stdout.strip().split('\n')
        for pid in pids:
            if pid:
                subprocess.run(['sudo', 'kill', pid])

        with open(config.SCAN_STATUS_PATH, 'w') as f:
            json.dump({
                'stage':   'idle',
                'message': 'Scan stopped by user.',
                'percent': 0,
                'running': False
            }, f)
        try:
            os.chmod(config.SCAN_STATUS_PATH, 0o666)
        except Exception:
            pass

        return jsonify({'status': 'stopped'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/clear-history', methods=['POST'])
def clear_history():
    try:
        if os.path.exists(config.HISTORY_DIR):
            shutil.rmtree(config.HISTORY_DIR)
            os.makedirs(config.HISTORY_DIR)
        return jsonify({'status': 'cleared'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/scan', methods=['POST'])
def trigger_scan():
    try:
        status = load_json(config.SCAN_STATUS_PATH)
        if status and status.get('running'):
            return jsonify({
                'status':  'already_running',
                'message': 'A scan is already in progress. Please wait for it to finish or stop it first.'
            })

        subprocess.Popen(
            ['sudo', config.VENV_PYTHON, config.MAIN_SCRIPT],
            cwd=config.BASE_DIR
        )
        return jsonify({'status': 'started'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

def build_findings_csv(analysis):
    """Flatten a scan's findings into CSV rows for spreadsheet use."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Host', 'Hostname', 'Vendor', 'Port', 'ID', 'Name',
        'Severity', 'CVSS Score', 'Description', 'Remediation', 'Source'
    ])
    for f in analysis.get('findings', []):
        is_cve = bool(f.get('cve_id'))
        writer.writerow([
            f.get('host', ''),
            f.get('hostname', ''),
            f.get('vendor', ''),
            f.get('port', ''),
            f.get('cve_id') or f.get('rule_id', ''),
            f.get('name', ''),
            f.get('severity', ''),
            f.get('cvss_score', '') if is_cve else '',
            f.get('description', ''),
            f.get('remediation', ''),
            'CVE' if is_cve else 'Rule',
        ])
    return output.getvalue()

@app.route('/export/csv')
def export_csv():
    analysis = load_json(config.ANALYSIS_RESULTS_PATH)
    if not analysis:
        return "No scan data available.", 404
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    return Response(
        build_findings_csv(analysis),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=findings_{timestamp}.csv'}
    )

@app.route('/export/csv/history/<scan_id>')
def export_csv_history(scan_id):
    base = os.path.join(config.HISTORY_DIR, scan_id)
    analysis = load_json(os.path.join(base, 'analysis_results.json'))
    if not analysis:
        return "Scan not found.", 404
    return Response(
        build_findings_csv(analysis),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=findings_{scan_id}.csv'}
    )

@app.route('/export/json')
def export_json():
    analysis = load_json(config.ANALYSIS_RESULTS_PATH)
    if not analysis:
        return "No scan data available.", 404
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    return Response(
        json.dumps(analysis, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename=scan_{timestamp}.json'}
    )

@app.route('/export/json/history/<scan_id>')
def export_json_history(scan_id):
    base = os.path.join(config.HISTORY_DIR, scan_id)
    analysis = load_json(os.path.join(base, 'analysis_results.json'))
    if not analysis:
        return "Scan not found.", 404
    return Response(
        json.dumps(analysis, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename=scan_{scan_id}.json'}
    )

@app.route('/download-pdf')
def download_pdf():
    from pdf_reporter import generate_pdf
    path = generate_pdf()
    return send_file(path, as_attachment=True,
                     download_name=os.path.basename(path))

@app.route('/download-pdf/history/<scan_id>')
def download_pdf_history(scan_id):
    from pdf_reporter import generate_pdf
    base = os.path.join(config.HISTORY_DIR, scan_id)
    path = generate_pdf(base_dir=base)
    return send_file(path, as_attachment=True,
                     download_name=os.path.basename(path))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(config.DASHBOARD_PORT), debug=False)

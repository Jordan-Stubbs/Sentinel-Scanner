from flask import Flask, render_template, jsonify, send_file, request, Response
import json
import subprocess
import os
import shutil
import socket
import urllib.request
import urllib.error
import config

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
                'id':        name,
                'timestamp': analysis.get('timestamp', name),
                'score':     analysis.get('score'),
                'rating':    analysis.get('rating'),
                'findings':  len(analysis.get('findings', [])),
                'duration':  analysis.get('duration', '—')
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

def read_memory():
    """Parse /proc/meminfo for RAM and swap stats, returned in GB."""
    try:
        meminfo = {}
        with open('/proc/meminfo') as f:
            for line in f:
                key, value = line.split(':', 1)
                meminfo[key.strip()] = int(value.strip().split()[0])  # kB

        total_gb      = meminfo.get('MemTotal', 0) / (1024 * 1024)
        available_gb  = meminfo.get('MemAvailable', 0) / (1024 * 1024)
        used_gb       = total_gb - available_gb
        swap_total_gb = meminfo.get('SwapTotal', 0) / (1024 * 1024)
        swap_free_gb  = meminfo.get('SwapFree', 0) / (1024 * 1024)
        swap_used_gb  = swap_total_gb - swap_free_gb

        return {
            'total_gb':      round(total_gb, 1),
            'used_gb':       round(used_gb, 1),
            'available_gb':  round(available_gb, 1),
            'percent_used':  round((used_gb / total_gb) * 100, 1) if total_gb else 0,
            'swap_total_gb': round(swap_total_gb, 1),
            'swap_used_gb':  round(swap_used_gb, 1),
        }
    except Exception:
        return None

def read_cpu_temp():
    """Read CPU temperature. Tries multiple methods since this can run
    on Raspberry Pi hardware, generic Linux hardware, or inside a VM
    (where no real sensor may be exposed at all — in that case this
    correctly returns None rather than fabricating a number)."""

    # Method 1: Raspberry Pi firmware tool
    try:
        result = subprocess.run(
            ['vcgencmd', 'measure_temp'],
            capture_output=True, text=True, timeout=2
        )
        output = result.stdout.strip()  # looks like: temp=48.7'C
        if output.startswith('temp='):
            temp_str = output.replace('temp=', '').replace("'C", '')
            return round(float(temp_str), 1)
    except Exception:
        pass

    # Method 2: standard Linux thermal zone interface (works on most
    # real laptops/desktops; usually absent or non-functional in VMs
    # since it depends on the hypervisor exposing real sensor data).
    try:
        base = '/sys/class/thermal'
        if os.path.isdir(base):
            zones = sorted(d for d in os.listdir(base) if d.startswith('thermal_zone'))
            preferred_keywords = ('cpu', 'pkg', 'soc', 'core')

            candidates = []
            for zone in zones:
                temp_path = os.path.join(base, zone, 'temp')
                type_path = os.path.join(base, zone, 'type')
                if not os.path.exists(temp_path):
                    continue
                zone_type = ''
                if os.path.exists(type_path):
                    with open(type_path) as f:
                        zone_type = f.read().strip().lower()
                candidates.append((zone_type, temp_path))

            # Try zones whose type looks CPU-related first, then any zone
            candidates.sort(key=lambda c: not any(k in c[0] for k in preferred_keywords))

            for _, temp_path in candidates:
                with open(temp_path) as f:
                    millidegrees = int(f.read().strip())
                celsius = millidegrees / 1000.0
                # Sanity check — some VMs/sensors report bogus 0 or negative values
                if 0 < celsius < 150:
                    return round(celsius, 1)
    except Exception:
        pass

    return None

def read_ollama_status():
    """Check whether Phi-3 Mini is currently resident in Ollama's RAM."""
    try:
        req = urllib.request.Request('http://localhost:11434/api/ps')
        with urllib.request.urlopen(req, timeout=2) as response:
            data   = json.loads(response.read().decode('utf-8'))
            models = data.get('models', [])
            if models:
                m = models[0]
                size_gb = m.get('size', 0) / (1024 ** 3)
                return {
                    'loaded':  True,
                    'name':    m.get('name', 'unknown'),
                    'size_gb': round(size_gb, 1)
                }
            return {'loaded': False}
    except Exception:
        return {'loaded': False}

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
                'status':  'error',
                'message': 'A scan is already in progress. Please wait for it to finish or stop it first.'
            })

        subprocess.Popen(
            ['sudo', config.VENV_PYTHON, config.MAIN_SCRIPT],
            cwd=config.BASE_DIR
        )
        return jsonify({'status': 'started'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

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
    app.run(host='0.0.0.0', port=5000, debug=False)

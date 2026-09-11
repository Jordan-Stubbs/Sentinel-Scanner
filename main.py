import json
import subprocess
import sys
import os
import shutil
import time
from datetime import datetime

try:
    import config
    import resource_monitor
    from analyser import analyse, calculate_score, get_rating, get_severity_counts
    from llm_reporter import load_analysis, build_report_data, build_prompt, query_ollama, build_final_report, save_report
    from cve_lookup import run_cve_lookup
except Exception as import_error:
    # A failure here happens BEFORE `if __name__ == "__main__":` ever
    # runs, so the try/except further down in this file never gets a
    # chance to catch it — a missing or broken module (e.g. a renamed
    # or deleted .py file) would otherwise crash silently, leaving
    # scan_status.json stuck on whatever it last said and the
    # dashboard endlessly showing stale/looping status.
    #
    # Can't safely rely on config.SCAN_STATUS_PATH here since config
    # itself might be what failed to import — so this computes the
    # same default path config.py would, independently.
    import traceback
    traceback.print_exc()

    fallback_status_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'scan_status.json'
    )
    try:
        with open(fallback_status_path, 'w') as f:
            json.dump({
                'stage':   'error',
                'message': f'Scan failed to start: {import_error}',
                'percent': 0,
                'running': False
            }, f)
        os.chmod(fallback_status_path, 0o666)
    except Exception:
        pass

    sys.exit(1)

def write_status(stage, message, percent, running=True):
    with open(config.SCAN_STATUS_PATH, 'w') as f:
        json.dump({
            'stage':   stage,
            'message': message,
            'percent': percent,
            'running': running,
            # Read by the dashboard so the AI Report stage label and
            # indicator reflect what THIS scan was actually started
            # with — a ground-truth server value, not just whatever
            # the browser's checkbox happens to show right now.
            'ai_report_enabled': not SKIP_AI_REPORT,
        }, f)
    # Ensure both root (this script, run via sudo) and admin (the Flask
    # service) can read/write this file regardless of who wrote it last —
    # prevents the root-owned-file-blocks-admin permission bug (bug 3/19).
    try:
        os.chmod(config.SCAN_STATUS_PATH, 0o666)
    except Exception:
        pass

# Set via the dashboard's "Generate AI Report" checkbox — app.py's
# trigger_scan() appends this flag to the command it spawns when the
# user unchecks it. Skipping the LLM step removes the single biggest
# CPU spike in the whole pipeline (99.9% CPU observed live during
# generation), useful for quick/frequent scans or when freeing up
# headroom for something else running concurrently.
SKIP_AI_REPORT = '--skip-ai-report' in sys.argv

def run_scanner():
    write_status('scanning', 'Scanning network — this takes 2-3 minutes...', 10)
    print("\n[*] Starting network scan...")
    result = subprocess.run(
        ['sudo', config.VENV_PYTHON, config.SCANNER_SCRIPT],
        capture_output=False,
        cwd=config.BASE_DIR
    )
    if result.returncode != 0:
        write_status('error', 'Scanner failed.', 0, running=False)
        print("[!] Scanner failed. Exiting.")
        sys.exit(1)
    print("[+] Scan complete.\n")

def run_analyser():
    write_status('analysing', 'Analysing findings and calculating score...', 35)
    print("[*] Analysing scan results...")

    with open(config.SCAN_RESULTS_PATH) as f:
        data = json.load(f)
    scan_results = data['hosts'] if isinstance(data, dict) else data

    findings = analyse(scan_results)
    score    = calculate_score(findings)
    rating   = get_rating(score)
    counts   = get_severity_counts(findings)
    meta     = data.get('meta', {}) if isinstance(data, dict) else {}

    print(f"\n{'='*50}")
    print(f"  SECURITY SCORE: {score}/100  |  RATING: {rating}")
    print(f"{'='*50}\n")

    if not findings:
        print("[+] No vulnerabilities detected.")
    else:
        print(f"[!] {len(findings)} finding(s):\n")
        for f in findings:
            print(f"  [{f['severity'].upper()}] {f['name']}")
            print(f"  Host: {f['host']} ({f['hostname']}) — Port {f['port']}")
            print(f"  {f['description']}")
            print(f"  Fix: {f['remediation']}\n")

    return findings, score, rating, counts, meta, scan_results

def run_cve(scan_results):
    write_status('cve', 'Looking up CVEs for detected services...', 55)
    print("[*] Running CVE lookup against NVD database...")

    cve_findings, online_mode = run_cve_lookup(scan_results)
    mode_str = "online" if online_mode else "offline cache"
    print(f"[+] CVE lookup complete ({mode_str}) — {len(cve_findings)} CVE(s) found\n")
    return cve_findings, online_mode

def run_llm_reporter():
    write_status('reporting', 'Generating AI report — please wait...', 75)
    print("[*] Sending findings to Phi-3 Mini via Ollama...")

    report_path = config.LLM_REPORT_PATH
    if os.path.exists(report_path):
        os.remove(report_path)

    analysis    = load_analysis(config.ANALYSIS_RESULTS_PATH)
    report_data = build_report_data(analysis)
    prompt      = build_prompt(report_data)
    ai_text     = query_ollama(prompt)
    report      = build_final_report(ai_text, report_data)

    print("\n" + "="*60)
    print("  AI GENERATED SECURITY REPORT")
    print("="*60 + "\n")
    print(report)

    save_report(report, report_path)

def save_to_history(duration_str):
    write_status('saving', 'Saving to history...', 95)
    timestamp   = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    history_dir = os.path.join(config.HISTORY_DIR, timestamp)
    os.makedirs(history_dir, exist_ok=True)

    for filename in ['scan_results.json', 'analysis_results.json', 'llm_report.txt']:
        src = os.path.join(config.BASE_DIR, filename)
        if os.path.exists(src):
            shutil.copy(src, os.path.join(history_dir, filename))

    with open(os.path.join(history_dir, 'meta.json'), 'w') as f:
        json.dump({'duration': duration_str}, f)

    # This whole script runs under sudo (root), so every file/directory
    # created above is root-owned. Without this, the dashboard's own
    # "Clear History" button — which runs as the admin user, not root —
    # fails with a PermissionError trying to delete them later. That
    # failure gets silently swallowed by app.py's clear_history() route
    # (which still returns HTTP 200) and the button just appears to do
    # nothing. This is the exact same failure shape as bugs 3/13/19.
    try:
        os.chmod(history_dir, 0o777)
        for filename in os.listdir(history_dir):
            os.chmod(os.path.join(history_dir, filename), 0o666)
    except Exception:
        pass

    print(f"[+] Scan saved to history/{timestamp}")
    return timestamp

def run_pipeline():
    print("="*60)
    print("  PORTABLE NETWORK VULNERABILITY SCANNER")
    print("="*60)

    scan_start = time.time()
    write_status('starting', 'Initialising scanner...', 5)

    # Automatically log resource usage at key pipeline stages, so this
    # data is available later for review instead of only being visible
    # live in the dashboard at the moment it happens.
    resource_snapshots = {}
    resource_snapshots['start'] = resource_monitor.take_snapshot()

    # Stage 1 — Scan
    run_scanner()
    write_status('scanning', 'Network scan complete.', 30)

    # Stage 2 — Analyse
    findings, score, rating, counts, meta, scan_results = run_analyser()
    write_status('analysing', 'Analysis complete.', 50)

    # Stage 3 — CVE lookup
    cve_findings, online_mode = run_cve(scan_results)
    write_status('cve', 'CVE lookup complete.', 65)

    # Merge CVE findings into analysis
    all_findings = findings + cve_findings
    total        = len(all_findings)

    # Recalculate score including CVE findings
    final_score  = calculate_score(all_findings)
    final_rating = get_rating(final_score)
    final_counts = get_severity_counts(all_findings)

    print(f"\n{'='*50}")
    print(f"  FINAL SCORE (with CVEs): {final_score}/100  |  RATING: {final_rating}")
    print(f"{'='*50}\n")

    # Distinguishes *why* there's no AI report — the dashboard shows a
    # different message for each: no vulnerabilities to report on at
    # all, vs. the user explicitly disabled it for this scan, vs. an
    # actual report being generated normally.
    if total == 0:
        ai_report_status = 'no_findings'
    elif SKIP_AI_REPORT:
        ai_report_status = 'opted_out'
    else:
        ai_report_status = 'generated'

    # Save combined analysis
    analysis_data = {
        'score':             final_score,
        'rating':            final_rating,
        'findings':          all_findings,
        'severity_counts':   final_counts,
        'meta':              meta,
        'cve_count':         len(cve_findings),
        'cve_mode':          'online' if online_mode else 'offline',
        'ai_report_status':  ai_report_status,
        'timestamp':         datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    with open(config.ANALYSIS_RESULTS_PATH, 'w') as f:
        json.dump(analysis_data, f, indent=2)

    print("[+] Analysis saved to analysis_results.json\n")

    # Stage 4 — AI report
    if total == 0:
        print("[+] No vulnerabilities found. Skipping AI report.")
        write_status('reporting', 'No vulnerabilities found.', 90)
        # Clear any stale report from a previous scan so it doesn't
        # get copied into THIS scan's history as if it were current.
        if os.path.exists(config.LLM_REPORT_PATH):
            os.remove(config.LLM_REPORT_PATH)
    elif SKIP_AI_REPORT:
        print("[+] AI report generation skipped (disabled for this scan).")
        write_status('reporting', 'AI report skipped by user.', 90)
        if os.path.exists(config.LLM_REPORT_PATH):
            os.remove(config.LLM_REPORT_PATH)
    else:
        resource_snapshots['before_llm'] = resource_monitor.take_snapshot()
        run_llm_reporter()
        resource_snapshots['after_llm'] = resource_monitor.take_snapshot()
        write_status('reporting', 'AI report complete.', 90)

    # Calculate duration
    elapsed      = time.time() - scan_start
    minutes      = int(elapsed // 60)
    seconds      = int(elapsed % 60)
    duration_str = f"{minutes}m {seconds}s"

    # Save duration into analysis_results.json
    with open(config.ANALYSIS_RESULTS_PATH) as f:
        analysis_data = json.load(f)
    analysis_data['duration'] = duration_str

    resource_snapshots['end'] = resource_monitor.take_snapshot()
    analysis_data['resource_snapshots'] = resource_snapshots

    with open(config.ANALYSIS_RESULTS_PATH, 'w') as f:
        json.dump(analysis_data, f, indent=2)

    history_id = save_to_history(duration_str)

    print("\n[+] All done. Files saved:")
    print("    - scan_results.json")
    print("    - analysis_results.json")
    print("    - llm_report.txt")
    print(f"    - history/{history_id}/")
    print(f"[+] Scan duration: {duration_str}")
    print(f"[+] CVE findings: {len(cve_findings)} ({analysis_data['cve_mode']} mode)")
    print("="*60 + "\n")

    write_status('complete', f'Scan complete in {duration_str}.', 100, running=False)

if __name__ == "__main__":
    try:
        run_pipeline()
    except SystemExit:
        # run_scanner() already calls write_status('error', ...) and
        # sys.exit(1) itself on a scanner failure — nothing more to
        # do here, just don't let this fall through to the generic
        # handler below and overwrite that more specific message.
        raise
    except Exception as e:
        # Guarantees scan_status.json always ends up with running:
        # False, no matter what goes wrong or where. Without this,
        # any unhandled error leaves the status file stuck showing
        # running: true forever — and since trigger_scan() in app.py
        # refuses to start a new scan while running is true, a single
        # crash would permanently lock out every future scan until
        # someone manually resets the file by hand.
        print(f"\n[!] Scan failed with an unexpected error: {e}")
        write_status('error', f'Scan failed: {e}', 0, running=False)
        sys.exit(1)

import json
import subprocess
import sys
import os
import shutil
import time
from datetime import datetime
from analyser import analyse, calculate_score, get_rating, get_severity_counts
from llm_reporter import load_analysis, build_report_data, build_prompt, query_ollama, build_final_report, save_report
from cve_lookup import run_cve_lookup
import config

def write_status(stage, message, percent, running=True):
    with open(config.SCAN_STATUS_PATH, 'w') as f:
        json.dump({
            'stage':   stage,
            'message': message,
            'percent': percent,
            'running': running
        }, f)
    # Ensure both root (this script, run via sudo) and admin (the Flask
    # service) can read/write this file regardless of who wrote it last —
    # prevents the root-owned-file-blocks-admin permission bug (bug 3/19).
    try:
        os.chmod(config.SCAN_STATUS_PATH, 0o666)
    except Exception:
        pass

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

    print(f"[+] Scan saved to history/{timestamp}")
    return timestamp

if __name__ == "__main__":
    print("="*60)
    print("  PORTABLE NETWORK VULNERABILITY SCANNER")
    print("="*60)

    scan_start = time.time()
    write_status('starting', 'Initialising scanner...', 5)

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

    # Save combined analysis
    analysis_data = {
        'score':           final_score,
        'rating':          final_rating,
        'findings':        all_findings,
        'severity_counts': final_counts,
        'meta':            meta,
        'cve_count':       len(cve_findings),
        'cve_mode':        'online' if online_mode else 'offline',
        'timestamp':       datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    with open(config.ANALYSIS_RESULTS_PATH, 'w') as f:
        json.dump(analysis_data, f, indent=2)

    print("[+] Analysis saved to analysis_results.json\n")

    # Stage 4 — AI report
    if total == 0:
        print("[+] No vulnerabilities found. Skipping AI report.")
        write_status('reporting', 'No vulnerabilities found.', 90)
    else:
        run_llm_reporter()
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

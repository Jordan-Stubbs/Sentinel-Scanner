"""
diff.py

Compares two past scans (from history/) and reports what changed:
hosts that appeared or disappeared, findings that are new or
resolved, and the score/rating delta.

Uses data already saved in each history/<timestamp>/ folder — no new
scanning logic needed.
"""

import json
import os


def _load_history_entry(history_dir):
    """Load a single history entry's analysis + scan data."""
    analysis_path = os.path.join(history_dir, 'analysis_results.json')
    scan_path = os.path.join(history_dir, 'scan_results.json')

    with open(analysis_path) as f:
        analysis = json.load(f)

    scan_data = {}
    if os.path.exists(scan_path):
        with open(scan_path) as f:
            scan_data = json.load(f)

    return analysis, scan_data


def _finding_key(finding):
    """
    Stable identity for a finding, used to match the same finding
    across two scans even if it appears in a different position in
    the list. Rule-based findings are identified by (host, rule_id,
    port); CVE findings by (host, cve_id, port) since cve_id is more
    specific than the generic 'CVE: <id>' rule_id they share.
    """
    identifier = finding.get('cve_id') or finding.get('rule_id')
    return (finding.get('host'), identifier, finding.get('port'))


def _host_set(scan_data):
    """Set of (ip, hostname) tuples from a scan_results.json's hosts."""
    hosts = scan_data.get('hosts', []) if isinstance(scan_data, dict) else scan_data
    return {(h.get('ip'), h.get('hostname')) for h in hosts}


def compare_scans(history_dir_a, history_dir_b):
    """
    Compare two history entries. 'a' is treated as the earlier scan,
    'b' as the later one — the diff describes what changed going from
    a to b.

    Returns a dict with hosts_added, hosts_removed, findings_new,
    findings_resolved, score_delta, rating_a, rating_b, and the raw
    scores/timestamps for display.
    """
    analysis_a, scan_a = _load_history_entry(history_dir_a)
    analysis_b, scan_b = _load_history_entry(history_dir_b)

    # ── Hosts ────────────────────────────────────────────────
    hosts_a = _host_set(scan_a)
    hosts_b = _host_set(scan_b)

    hosts_added = sorted(hosts_b - hosts_a)
    hosts_removed = sorted(hosts_a - hosts_b)

    # ── Findings ─────────────────────────────────────────────
    findings_a = analysis_a.get('findings', [])
    findings_b = analysis_b.get('findings', [])

    keys_a = {_finding_key(f): f for f in findings_a}
    keys_b = {_finding_key(f): f for f in findings_b}

    findings_new = [keys_b[k] for k in keys_b if k not in keys_a]
    findings_resolved = [keys_a[k] for k in keys_a if k not in keys_b]

    # ── Score / rating ───────────────────────────────────────
    score_a = analysis_a.get('score', 0)
    score_b = analysis_b.get('score', 0)

    return {
        'timestamp_a': analysis_a.get('timestamp', ''),
        'timestamp_b': analysis_b.get('timestamp', ''),
        'score_a': score_a,
        'score_b': score_b,
        'score_delta': score_b - score_a,
        'rating_a': analysis_a.get('rating', 'Unknown'),
        'rating_b': analysis_b.get('rating', 'Unknown'),
        'hosts_added': [{'ip': ip, 'hostname': hostname} for ip, hostname in hosts_added],
        'hosts_removed': [{'ip': ip, 'hostname': hostname} for ip, hostname in hosts_removed],
        'findings_new': findings_new,
        'findings_resolved': findings_resolved,
    }

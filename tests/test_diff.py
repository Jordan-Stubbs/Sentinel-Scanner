"""
test_diff.py

Unit tests for diff.py's compare_scans() - uses temporary fake
history directories built in setUp(), never touches real scan data.

Run from the scanner directory:

    cd ~/scanner
    source venv/bin/activate
    python3 -m unittest tests.test_diff -v
"""

import sys
import os
import json
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from diff import compare_scans


def _write_history_entry(base_dir, name, score, rating, findings, hosts):
    entry_dir = os.path.join(base_dir, name)
    os.makedirs(entry_dir)

    with open(os.path.join(entry_dir, 'analysis_results.json'), 'w') as f:
        json.dump({
            'score': score,
            'rating': rating,
            'findings': findings,
            'timestamp': name,
        }, f)

    with open(os.path.join(entry_dir, 'scan_results.json'), 'w') as f:
        json.dump({'hosts': hosts}, f)

    return entry_dir


class TestCompareScans(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir)

    def test_detects_new_host(self):
        dir_a = _write_history_entry(
            self.tmp_dir, 'a', 80, 'GOOD', [],
            hosts=[{'ip': '1.1.1.1', 'hostname': 'host-a'}]
        )
        dir_b = _write_history_entry(
            self.tmp_dir, 'b', 80, 'GOOD', [],
            hosts=[
                {'ip': '1.1.1.1', 'hostname': 'host-a'},
                {'ip': '2.2.2.2', 'hostname': 'host-b'},
            ]
        )
        result = compare_scans(dir_a, dir_b)
        self.assertEqual(len(result['hosts_added']), 1)
        self.assertEqual(result['hosts_added'][0]['ip'], '2.2.2.2')
        self.assertEqual(result['hosts_removed'], [])

    def test_detects_removed_host(self):
        dir_a = _write_history_entry(
            self.tmp_dir, 'a', 80, 'GOOD', [],
            hosts=[
                {'ip': '1.1.1.1', 'hostname': 'host-a'},
                {'ip': '2.2.2.2', 'hostname': 'host-b'},
            ]
        )
        dir_b = _write_history_entry(
            self.tmp_dir, 'b', 80, 'GOOD', [],
            hosts=[{'ip': '1.1.1.1', 'hostname': 'host-a'}]
        )
        result = compare_scans(dir_a, dir_b)
        self.assertEqual(len(result['hosts_removed']), 1)
        self.assertEqual(result['hosts_removed'][0]['ip'], '2.2.2.2')
        self.assertEqual(result['hosts_added'], [])

    def test_detects_new_finding(self):
        dir_a = _write_history_entry(self.tmp_dir, 'a', 90, 'GOOD', [], hosts=[])
        dir_b = _write_history_entry(
            self.tmp_dir, 'b', 70, 'MODERATE',
            findings=[{'host': '1.1.1.1', 'rule_id': 'VULN-001', 'port': 23,
                       'name': 'Telnet Open', 'severity': 'critical'}],
            hosts=[]
        )
        result = compare_scans(dir_a, dir_b)
        self.assertEqual(len(result['findings_new']), 1)
        self.assertEqual(result['findings_new'][0]['rule_id'], 'VULN-001')
        self.assertEqual(result['findings_resolved'], [])

    def test_detects_resolved_finding(self):
        dir_a = _write_history_entry(
            self.tmp_dir, 'a', 70, 'MODERATE',
            findings=[{'host': '1.1.1.1', 'rule_id': 'VULN-001', 'port': 23,
                       'name': 'Telnet Open', 'severity': 'critical'}],
            hosts=[]
        )
        dir_b = _write_history_entry(self.tmp_dir, 'b', 90, 'GOOD', [], hosts=[])
        result = compare_scans(dir_a, dir_b)
        self.assertEqual(len(result['findings_resolved']), 1)
        self.assertEqual(result['findings_new'], [])

    def test_unchanged_finding_is_not_new_or_resolved(self):
        finding = {'host': '1.1.1.1', 'rule_id': 'VULN-001', 'port': 23,
                   'name': 'Telnet Open', 'severity': 'critical'}
        dir_a = _write_history_entry(self.tmp_dir, 'a', 70, 'MODERATE', [finding], hosts=[])
        dir_b = _write_history_entry(self.tmp_dir, 'b', 70, 'MODERATE', [finding], hosts=[])
        result = compare_scans(dir_a, dir_b)
        self.assertEqual(result['findings_new'], [])
        self.assertEqual(result['findings_resolved'], [])

    def test_cve_findings_matched_by_cve_id_not_generic_rule_id(self):
        # Two different CVEs on the same host/port share the generic
        # rule_id pattern "CVE: <id>" - matching must use cve_id
        # specifically, or these would be wrongly treated as the same finding.
        finding_a = {'host': '1.1.1.1', 'port': 22, 'cve_id': 'CVE-2020-0001',
                     'rule_id': 'CVE-2020-0001', 'severity': 'high'}
        finding_b = {'host': '1.1.1.1', 'port': 22, 'cve_id': 'CVE-2023-9999',
                     'rule_id': 'CVE-2023-9999', 'severity': 'critical'}
        dir_a = _write_history_entry(self.tmp_dir, 'a', 70, 'MODERATE', [finding_a], hosts=[])
        dir_b = _write_history_entry(self.tmp_dir, 'b', 60, 'POOR', [finding_b], hosts=[])
        result = compare_scans(dir_a, dir_b)
        self.assertEqual(len(result['findings_new']), 1)
        self.assertEqual(result['findings_new'][0]['cve_id'], 'CVE-2023-9999')
        self.assertEqual(len(result['findings_resolved']), 1)
        self.assertEqual(result['findings_resolved'][0]['cve_id'], 'CVE-2020-0001')

    def test_score_delta_calculated_correctly(self):
        dir_a = _write_history_entry(self.tmp_dir, 'a', 60, 'POOR', [], hosts=[])
        dir_b = _write_history_entry(self.tmp_dir, 'b', 85, 'GOOD', [], hosts=[])
        result = compare_scans(dir_a, dir_b)
        self.assertEqual(result['score_delta'], 25)
        self.assertEqual(result['rating_a'], 'POOR')
        self.assertEqual(result['rating_b'], 'GOOD')

    def test_negative_score_delta_when_score_worsens(self):
        dir_a = _write_history_entry(self.tmp_dir, 'a', 90, 'GOOD', [], hosts=[])
        dir_b = _write_history_entry(self.tmp_dir, 'b', 40, 'POOR', [], hosts=[])
        result = compare_scans(dir_a, dir_b)
        self.assertEqual(result['score_delta'], -50)


if __name__ == '__main__':
    unittest.main()

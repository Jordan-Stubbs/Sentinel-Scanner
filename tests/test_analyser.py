"""
test_analyser.py

Unit tests for analyser.py — validates rule matching, score
calculation, and rating thresholds. Run from the scanner directory:

    cd ~/scanner
    source venv/bin/activate
    python3 -m unittest tests.test_analyser -v
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from analyser import analyse, calculate_score, get_rating, get_severity_counts


def make_host(ip, hostname, protocols):
    return {'ip': ip, 'hostname': hostname, 'vendor': 'TestVendor', 'protocols': protocols}


class TestAnalyseRuleMatching(unittest.TestCase):

    def test_no_findings_on_empty_scan(self):
        findings = analyse([])
        self.assertEqual(findings, [])

    def test_no_findings_when_no_rules_match(self):
        # Port 443 (https) isn't in any rule's port list
        host = make_host('192.168.1.10', 'test.local', {'tcp': {443: {'service': 'https', 'version': ''}}})
        findings = analyse([host])
        self.assertEqual(findings, [])

    def test_telnet_flagged_as_critical(self):
        host = make_host('192.168.1.10', 'test.local', {'tcp': {23: {'service': 'telnet', 'version': ''}}})
        findings = analyse([host])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['severity'], 'critical')
        self.assertEqual(findings[0]['rule_id'], 'VULN-001')

    def test_multiple_hosts_multiple_findings(self):
        hosts = [
            make_host('192.168.1.10', 'a.local', {'tcp': {23: {'service': 'telnet', 'version': ''}}}),
            make_host('192.168.1.11', 'b.local', {'tcp': {21: {'service': 'ftp', 'version': ''}}}),
        ]
        findings = analyse(hosts)
        self.assertEqual(len(findings), 2)
        hosts_found = {f['host'] for f in findings}
        self.assertEqual(hosts_found, {'192.168.1.10', '192.168.1.11'})

    def test_udp_protocol_does_not_match_tcp_rule(self):
        # All current rules are 'tcp' — a udp port should never match
        host = make_host('192.168.1.10', 'test.local', {'udp': {23: {'service': 'telnet', 'version': ''}}})
        findings = analyse([host])
        self.assertEqual(findings, [])


class TestScoreCalculation(unittest.TestCase):

    def test_perfect_score_with_no_findings(self):
        self.assertEqual(calculate_score([]), 100)

    def test_score_decreases_with_findings(self):
        findings = [{'severity': 'critical'}]
        score = calculate_score(findings)
        self.assertLess(score, 100)

    def test_score_never_goes_below_zero(self):
        # A large number of critical findings should still floor at 0, not go negative
        findings = [{'severity': 'critical'} for _ in range(50)]
        score = calculate_score(findings)
        self.assertGreaterEqual(score, 0)

    def test_diminishing_returns_on_repeated_severity(self):
        # Each additional finding of the same severity should hurt less
        # than the one before it (diminishing returns), so two findings
        # should cost less than double what one finding costs.
        score_one = calculate_score([{'severity': 'high'}])
        score_two = calculate_score([{'severity': 'high'}, {'severity': 'high'}])
        cost_one = 100 - score_one
        cost_two = 100 - score_two
        self.assertLess(cost_two, cost_one * 2)

    def test_critical_hurts_more_than_low(self):
        score_critical = calculate_score([{'severity': 'critical'}])
        score_low = calculate_score([{'severity': 'low'}])
        self.assertLess(score_critical, score_low)


class TestRatingThresholds(unittest.TestCase):

    def test_good_rating_at_80(self):
        self.assertEqual(get_rating(80), 'GOOD')

    def test_good_rating_at_100(self):
        self.assertEqual(get_rating(100), 'GOOD')

    def test_moderate_rating_at_60(self):
        self.assertEqual(get_rating(60), 'MODERATE')

    def test_poor_rating_at_40(self):
        self.assertEqual(get_rating(40), 'POOR')

    def test_critical_rating_below_40(self):
        self.assertEqual(get_rating(39), 'CRITICAL')

    def test_critical_rating_at_zero(self):
        self.assertEqual(get_rating(0), 'CRITICAL')


class TestSeverityCounts(unittest.TestCase):

    def test_counts_empty_findings(self):
        counts = get_severity_counts([])
        self.assertEqual(counts, {'critical': 0, 'high': 0, 'medium': 0, 'low': 0})

    def test_counts_mixed_severities(self):
        findings = [
            {'severity': 'critical'},
            {'severity': 'critical'},
            {'severity': 'high'},
            {'severity': 'low'},
        ]
        counts = get_severity_counts(findings)
        self.assertEqual(counts, {'critical': 2, 'high': 1, 'medium': 0, 'low': 1})


if __name__ == '__main__':
    unittest.main()

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

from analyser import analyse, calculate_score, get_rating, get_severity_counts, RULES


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


class TestAllRulesFireCorrectly(unittest.TestCase):
    """
    Data-driven coverage of every rule in analyser.RULES — loops over
    the actual rule list rather than hardcoding each rule as a
    separate case, so this stays self-updating if rules are ever
    added, removed, or changed. Confirms each rule fires on its own
    defined port/protocol with the correct rule_id and severity, and
    nothing else.
    """

    def test_rule_count_is_40(self):
        # Regression guard — catches an accidental rule deletion/addition
        # going unnoticed. Update this number deliberately if the rule
        # set genuinely changes size. (19 original rules + 10 added
        # 2026-09-16: Elasticsearch/Kibana, Docker API, NFS, rsync,
        # RTSP/IP Camera, CouchDB, RabbitMQ, Modbus, WinRM, LDAP.
        # + 1 added 2026-09-17: split the old combined SIP rule into
        # separate plain (5060) and TLS (5061) entries with accurate,
        # distinct wording for each.
        # + 6 added 2026-09-17: home-network-specific batch — Jellyfin,
        # CUPS/IPP, Home Assistant, Chromecast/Cast, Plex, Portainer.
        # + 4 added 2026-09-17: low-severity batch — Finger, Ident,
        # Echo, and Minecraft. This is treated as the practical floor
        # of the hand-written rule set going forward.)
        self.assertEqual(len(RULES), 40)

    def test_no_duplicate_rule_ids(self):
        ids = [rule['id'] for rule in RULES]
        self.assertEqual(len(ids), len(set(ids)), "Duplicate rule IDs found in RULES")

    def test_every_rule_fires_on_its_own_port(self):
        for rule in RULES:
            with self.subTest(rule_id=rule['id']):
                port = rule['ports'][0]
                host = make_host('1.1.1.1', 'test.local', {
                    rule['protocol']: {port: {'service': 'test', 'version': ''}}
                })
                findings = analyse([host])

                self.assertEqual(
                    len(findings), 1,
                    f"Rule {rule['id']} ({rule['name']}) did not fire exactly once "
                    f"on port {port}/{rule['protocol']}"
                )
                self.assertEqual(findings[0]['rule_id'], rule['id'])
                self.assertEqual(findings[0]['severity'], rule['severity'])
                self.assertEqual(findings[0]['name'], rule['name'])

    def test_every_rule_port_has_a_valid_severity(self):
        valid_severities = {'critical', 'high', 'medium', 'low'}
        for rule in RULES:
            with self.subTest(rule_id=rule['id']):
                self.assertIn(rule['severity'], valid_severities)

    def test_every_rule_has_non_empty_remediation(self):
        for rule in RULES:
            with self.subTest(rule_id=rule['id']):
                self.assertTrue(rule['remediation'].strip())


if __name__ == '__main__':
    unittest.main()

"""
test_llm_reporter.py

Unit tests for llm_reporter.py — validates that build_report_data()
correctly separates rule findings from CVE findings, and that
build_final_report() correctly assembles the AI-written sections with
the deterministic (Python-generated) findings/CVE sections. These are
the functions at the centre of the 2026-08-24 main.py integration fix.

No network or Ollama calls are made — query_ollama()'s output is
simulated directly as a string.

Run from the scanner directory:

    cd ~/scanner
    source venv/bin/activate
    python3 -m unittest tests.test_llm_reporter -v
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from llm_reporter import build_report_data, build_final_report, format_recommended_fixes, format_cve_summary


def make_analysis(findings, score=50, rating='POOR'):
    return {'score': score, 'rating': rating, 'findings': findings}


class TestBuildReportData(unittest.TestCase):

    def test_separates_rule_findings_from_cve_findings(self):
        findings = [
            {'name': 'Telnet Open', 'severity': 'critical', 'host': '1.1.1.1', 'remediation': 'Disable telnet.'},
            {'name': 'CVE: CVE-2023-1234', 'severity': 'high', 'host': '1.1.1.1',
             'cve_id': 'CVE-2023-1234', 'cvss_score': 7.5, 'remediation': 'Patch it.'},
        ]
        data = build_report_data(make_analysis(findings))
        self.assertEqual(len(data['recommended_fixes']), 1)
        self.assertEqual(len(data['cve_summary']), 1)
        self.assertEqual(data['recommended_fixes'][0]['name'], 'Telnet Open')
        self.assertEqual(data['cve_summary'][0]['cve_id'], 'CVE-2023-1234')

    def test_picks_most_critical_finding_by_severity(self):
        findings = [
            {'name': 'Minor Issue', 'severity': 'low', 'host': '1.1.1.1', 'remediation': 'x'},
            {'name': 'Major Issue', 'severity': 'critical', 'host': '2.2.2.2', 'remediation': 'y'},
            {'name': 'Medium Issue', 'severity': 'medium', 'host': '3.3.3.3', 'remediation': 'z'},
        ]
        data = build_report_data(make_analysis(findings))
        self.assertEqual(data['critical_name'], 'Major Issue')
        self.assertEqual(data['critical_host'], '2.2.2.2')

    def test_handles_no_findings_gracefully(self):
        data = build_report_data(make_analysis([], score=100, rating='GOOD'))
        self.assertEqual(data['critical_name'], 'No findings')
        self.assertEqual(data['critical_host'], 'None')
        self.assertEqual(data['recommended_fixes'], [])
        self.assertEqual(data['cve_summary'], [])

    def test_preserves_score_and_rating(self):
        data = build_report_data(make_analysis([], score=73, rating='MODERATE'))
        self.assertEqual(data['score'], 73)
        self.assertEqual(data['rating'], 'MODERATE')


class TestFormatFunctions(unittest.TestCase):

    def test_format_recommended_fixes_empty(self):
        data = build_report_data(make_analysis([]))
        text = format_recommended_fixes(data)
        self.assertIn('No findings requiring remediation', text)

    def test_format_recommended_fixes_lists_all(self):
        findings = [
            {'name': 'A', 'severity': 'high', 'host': '1.1.1.1', 'remediation': 'fix a'},
            {'name': 'B', 'severity': 'medium', 'host': '2.2.2.2', 'remediation': 'fix b'},
        ]
        data = build_report_data(make_analysis(findings))
        text = format_recommended_fixes(data)
        self.assertIn('A on 1.1.1.1: fix a', text)
        self.assertIn('B on 2.2.2.2: fix b', text)

    def test_format_cve_summary_empty(self):
        data = build_report_data(make_analysis([]))
        text = format_cve_summary(data)
        self.assertIn('No CVEs found', text)


class TestBuildFinalReport(unittest.TestCase):

    def test_all_four_sections_present(self):
        findings = [{'name': 'Telnet Open', 'severity': 'critical', 'host': '1.1.1.1', 'remediation': 'Disable it.'}]
        data = build_report_data(make_analysis(findings, score=24, rating='CRITICAL'))

        fake_ai_text = (
            "EXECUTIVE SUMMARY\n"
            "The network security score is 24/100 with a CRITICAL rating. "
            "The most critical issue is Telnet Open on 1.1.1.1.\n\n"
            "CONCLUSION\n"
            "Immediate remediation is required. Telnet Open should be fixed first."
        )

        report = build_final_report(fake_ai_text, data)

        self.assertIn('EXECUTIVE SUMMARY', report)
        self.assertIn('RECOMMENDED FIXES', report)
        self.assertIn('CVE SUMMARY', report)
        self.assertIn('CONCLUSION', report)
        self.assertIn('Telnet Open on 1.1.1.1', report)

    def test_falls_back_when_ai_text_missing_sections(self):
        # Simulates the model failing to follow the expected header
        # format — build_final_report() should still produce a
        # complete, non-empty report using the fallback text.
        data = build_report_data(make_analysis([], score=100, rating='GOOD'))
        report = build_final_report('some unrelated garbled text', data)

        self.assertIn('EXECUTIVE SUMMARY', report)
        self.assertIn('100/100', report)
        self.assertIn('CONCLUSION', report)

    def test_section_order_is_consistent(self):
        data = build_report_data(make_analysis([], score=100, rating='GOOD'))
        report = build_final_report('EXECUTIVE SUMMARY\ntest\n\nCONCLUSION\ntest', data)

        exec_pos   = report.index('EXECUTIVE SUMMARY')
        fixes_pos  = report.index('RECOMMENDED FIXES')
        cve_pos    = report.index('CVE SUMMARY')
        concl_pos  = report.index('CONCLUSION')

        self.assertTrue(exec_pos < fixes_pos < cve_pos < concl_pos)


if __name__ == '__main__':
    unittest.main()

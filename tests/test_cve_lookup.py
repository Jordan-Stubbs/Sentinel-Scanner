"""
test_cve_lookup.py

Unit tests for cve_lookup.py — validates version extraction, CVSS
severity mapping, and (most importantly) the offline cache matching
logic that was loosened on 2026-08-24 so version numbers are a
scoring bonus rather than a hard requirement.

These tests never touch the network or the real cve_cache.json —
query_nvd_offline() is tested against a temporary fake cache file.

Run from the scanner directory:

    cd ~/scanner
    source venv/bin/activate
    python3 -m unittest tests.test_cve_lookup -v
"""

import sys
import os
import json
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import cve_lookup


class TestCleanVersion(unittest.TestCase):

    def test_extracts_simple_version(self):
        self.assertEqual(cve_lookup.clean_version('OpenSSH 6.6.0p1 Ubuntu'), '6.6.0')

    def test_extracts_version_with_two_parts(self):
        self.assertEqual(cve_lookup.clean_version('nginx 1.18'), '1.18')

    def test_returns_none_for_empty_string(self):
        self.assertIsNone(cve_lookup.clean_version(''))

    def test_returns_none_when_no_version_present(self):
        self.assertIsNone(cve_lookup.clean_version('unknown service'))

    def test_returns_none_for_whitespace_only(self):
        self.assertIsNone(cve_lookup.clean_version('   '))


class TestBuildSearchQuery(unittest.TestCase):

    def test_includes_version_when_present(self):
        self.assertEqual(cve_lookup.build_search_query('OpenSSH', '6.6.0'), 'OpenSSH 6.6.0')

    def test_omits_version_when_none(self):
        self.assertEqual(cve_lookup.build_search_query('OpenSSH', None), 'OpenSSH')


class TestCvssToSeverity(unittest.TestCase):

    def test_critical_at_9(self):
        self.assertEqual(cve_lookup.cvss_to_severity(9.0), 'critical')

    def test_critical_at_10(self):
        self.assertEqual(cve_lookup.cvss_to_severity(10.0), 'critical')

    def test_high_at_7(self):
        self.assertEqual(cve_lookup.cvss_to_severity(7.0), 'high')

    def test_medium_at_4(self):
        self.assertEqual(cve_lookup.cvss_to_severity(4.0), 'medium')

    def test_low_below_4(self):
        self.assertEqual(cve_lookup.cvss_to_severity(3.9), 'low')


class TestOfflineCacheMatching(unittest.TestCase):
    """
    Covers the query_nvd_offline() loosening from 2026-08-24: version
    terms should now be a ranking bonus, not a hard requirement.
    """

    def setUp(self):
        # Build a small fake cache and point cve_lookup at it instead
        # of the real /home/admin/scanner/cve_cache.json.
        self.fake_cache = {
            'CVE-2000-0001': {
                'id': 'CVE-2000-0001',
                'cvss_score': 7.5,
                'description': 'OpenSSH does not properly drop privileges when UseLogin is enabled.',
                'published': '2000-01-01',
            },
            'CVE-2023-0002': {
                'id': 'CVE-2023-0002',
                'cvss_score': 6.5,
                'description': 'OpenSSH 6.6.0 client has a memory disclosure vulnerability.',
                'published': '2023-01-01',
            },
            'CVE-2019-0003': {
                'id': 'CVE-2019-0003',
                'cvss_score': 5.0,
                'description': 'Apache HTTP server allows directory traversal.',
                'published': '2019-01-01',
            },
        }

        self._tmp = tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        )
        json.dump(self.fake_cache, self._tmp)
        self._tmp.close()

        # Monkeypatch the module-level path so we never touch the real cache
        self._original_path = cve_lookup.CVE_CACHE_PATH
        cve_lookup.CVE_CACHE_PATH = self._tmp.name

    def tearDown(self):
        cve_lookup.CVE_CACHE_PATH = self._original_path
        os.unlink(self._tmp.name)

    def test_returns_none_when_cache_file_missing(self):
        cve_lookup.CVE_CACHE_PATH = '/nonexistent/path/cve_cache.json'
        result = cve_lookup.query_nvd_offline('OpenSSH 6.6.0')
        self.assertIsNone(result)

    def test_matches_product_name_even_without_version_in_description(self):
        # CVE-2000-0001 mentions "OpenSSH" but not "6.6.0" — should
        # still match under the loosened logic (this was the whole
        # point of the 2026-08-24 fix).
        results = cve_lookup.query_nvd_offline('OpenSSH 6.6.0')
        ids = {r['id'] for r in results}
        self.assertIn('CVE-2000-0001', ids)

    def test_version_matching_entry_is_ranked_first(self):
        # CVE-2023-0002 mentions both "OpenSSH" and "6.6.0" — it should
        # be scored higher and come before CVE-2000-0001, which only
        # matches on product name.
        results = cve_lookup.query_nvd_offline('OpenSSH 6.6.0')
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0]['id'], 'CVE-2023-0002')

    def test_does_not_match_unrelated_product(self):
        results = cve_lookup.query_nvd_offline('OpenSSH 6.6.0')
        ids = {r['id'] for r in results}
        self.assertNotIn('CVE-2019-0003', ids)

    def test_respects_max_results_cap(self):
        # Build a bigger cache to confirm the MAX_CVE_PER_SERVICE cap holds
        big_cache = {
            f'CVE-2020-{i:04d}': {
                'id': f'CVE-2020-{i:04d}',
                'cvss_score': 5.0,
                'description': 'Apache HTTP server vulnerability of some kind.',
                'published': '2020-01-01',
            }
            for i in range(10)
        }
        with open(cve_lookup.CVE_CACHE_PATH, 'w') as f:
            json.dump(big_cache, f)

        results = cve_lookup.query_nvd_offline('Apache')
        self.assertLessEqual(len(results), cve_lookup.MAX_CVE_PER_SERVICE)


if __name__ == '__main__':
    unittest.main()

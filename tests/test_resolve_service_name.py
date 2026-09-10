"""
test_resolve_service_name.py

Unit tests for cve_lookup.py's resolve_service_name() — the function
that decides what product name (if any) to search CVEs for, given
nmap's detected service category and product string.

Directly covers the bug found via live testing 2026-09-08: a Flask/
Werkzeug dashboard on a generic 'http' port was being matched against
unrelated Apache CVEs (SpamAssassin, Airflow) because the old logic
always guessed "Apache" for any http-category service regardless of
whether nmap actually identified a specific product.

Run from the scanner directory:

    cd ~/scanner
    source venv/bin/activate
    python3 -m unittest tests.test_resolve_service_name -v
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from cve_lookup import resolve_service_name


class TestResolveServiceName(unittest.TestCase):

    def test_ambiguous_category_with_no_product_is_skipped(self):
        # This is the exact bug case: generic 'http' with nothing
        # more specific detected must no longer default to "Apache".
        self.assertIsNone(resolve_service_name('http', ''))
        self.assertIsNone(resolve_service_name('https', ''))

    def test_ambiguous_category_with_real_product_uses_it(self):
        self.assertEqual(
            resolve_service_name('http', 'Werkzeug httpd'),
            'Werkzeug httpd'
        )
        self.assertEqual(
            resolve_service_name('http', 'nginx'),
            'nginx'
        )

    def test_genuine_apache_still_correctly_identified(self):
        # The fix must not lose real detection — only remove the
        # blind guess when nmap couldn't identify anything specific.
        self.assertEqual(
            resolve_service_name('http', 'Apache httpd'),
            'Apache httpd'
        )

    def test_reliable_category_still_has_a_safe_default(self):
        # ssh/ftp/telnet remain reliable enough to guess even without
        # a specific detected product.
        self.assertEqual(resolve_service_name('ssh', ''), 'OpenSSH')
        self.assertEqual(resolve_service_name('ftp', ''), 'vsftpd')

    def test_reliable_category_prefers_real_product_over_default(self):
        # Even for a "safe to guess" category, a real detected
        # product should still win over the static fallback.
        self.assertEqual(
            resolve_service_name('ssh', 'Dropbear sshd'),
            'Dropbear sshd'
        )

    def test_explicit_exclusion_always_skipped(self):
        # tcpwrapped/iphone-sync etc. are excluded outright — even if
        # nmap somehow reports a product string for them.
        self.assertIsNone(resolve_service_name('tcpwrapped', ''))
        self.assertIsNone(resolve_service_name('tcpwrapped', 'SomeApp'))
        self.assertIsNone(resolve_service_name('iphone-sync', ''))

    def test_unrecognised_category_with_no_product_is_skipped(self):
        # Previously this fell through to service.capitalize() and
        # searched blindly for whatever nmap's raw category name was.
        # Now it correctly skips instead of guessing.
        self.assertIsNone(resolve_service_name('some-totally-unknown-service', ''))

    def test_unrecognised_category_with_real_product_still_works(self):
        self.assertEqual(
            resolve_service_name('some-totally-unknown-service', 'CustomApp'),
            'CustomApp'
        )

    def test_case_insensitive_service_matching(self):
        self.assertEqual(resolve_service_name('SSH', ''), 'OpenSSH')
        self.assertIsNone(resolve_service_name('HTTP', ''))

    def test_handles_none_inputs_gracefully(self):
        self.assertIsNone(resolve_service_name(None, None))
        self.assertIsNone(resolve_service_name('http', None))


if __name__ == '__main__':
    unittest.main()

"""
test_traffic_monitor.py

Unit tests for traffic_monitor.py's evaluate_port_hits() and
evaluate_arp_hits() — the pure, testable detection logic, kept
deliberately separate from the actual packet capture (which needs a
live network and root privileges, so isn't covered by unit tests,
matching this project's existing testing philosophy).

Requires scapy to be installed (traffic_monitor.py imports it at
module level) — run from the scanner directory:

    cd ~/scanner
    source venv/bin/activate
    python3 -m unittest tests.test_traffic_monitor -v
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from traffic_monitor import (
    evaluate_port_hits,
    evaluate_arp_hits,
    PORT_SCAN_THRESHOLD,
    ARP_SWEEP_THRESHOLD,
)


class TestEvaluatePortHits(unittest.TestCase):

    def test_flags_source_above_threshold(self):
        port_hits = {'192.168.1.50': set(range(1, 21))}  # 20 ports
        flags = evaluate_port_hits(port_hits)
        self.assertEqual(len(flags), 1)
        self.assertEqual(flags[0]['source_ip'], '192.168.1.50')
        self.assertEqual(flags[0]['distinct_ports'], 20)

    def test_does_not_flag_normal_traffic(self):
        port_hits = {'192.168.1.10': {80, 443}}
        self.assertEqual(evaluate_port_hits(port_hits), [])

    def test_does_not_flag_just_under_threshold(self):
        port_hits = {'192.168.1.20': set(range(1, PORT_SCAN_THRESHOLD))}
        self.assertEqual(evaluate_port_hits(port_hits), [])

    def test_flags_exactly_at_threshold(self):
        port_hits = {'192.168.1.99': set(range(1, PORT_SCAN_THRESHOLD + 1))}
        flags = evaluate_port_hits(port_hits)
        self.assertEqual(len(flags), 1)

    def test_multiple_flags_sorted_most_severe_first(self):
        port_hits = {
            'a': set(range(1, 16)),
            'b': set(range(1, 51)),
            'c': set(range(1, 21)),
        }
        flags = evaluate_port_hits(port_hits)
        self.assertEqual([f['source_ip'] for f in flags], ['b', 'c', 'a'])

    def test_empty_input_returns_empty_list(self):
        self.assertEqual(evaluate_port_hits({}), [])

    def test_ports_list_capped_for_display(self):
        port_hits = {'x': set(range(1, 101))}  # 100 ports
        flags = evaluate_port_hits(port_hits)
        self.assertLessEqual(len(flags[0]['ports']), 30)

    def test_custom_threshold_respected(self):
        port_hits = {'x': {1, 2, 3, 4, 5}}
        self.assertEqual(evaluate_port_hits(port_hits, threshold=10), [])
        self.assertEqual(len(evaluate_port_hits(port_hits, threshold=5)), 1)


class TestEvaluateArpHits(unittest.TestCase):

    def test_flags_source_above_threshold(self):
        arp_hits = {'192.168.1.5': {f'192.168.1.{i}' for i in range(1, 13)}}  # 12
        flags = evaluate_arp_hits(arp_hits)
        self.assertEqual(len(flags), 1)
        self.assertEqual(flags[0]['source_ip'], '192.168.1.5')
        self.assertEqual(flags[0]['distinct_targets'], 12)

    def test_does_not_flag_single_lookup(self):
        arp_hits = {'192.168.1.6': {'192.168.1.1'}}
        self.assertEqual(evaluate_arp_hits(arp_hits), [])

    def test_flags_exactly_at_threshold(self):
        arp_hits = {'x': {f'10.0.0.{i}' for i in range(ARP_SWEEP_THRESHOLD)}}
        flags = evaluate_arp_hits(arp_hits)
        self.assertEqual(len(flags), 1)

    def test_empty_input_returns_empty_list(self):
        self.assertEqual(evaluate_arp_hits({}), [])


if __name__ == '__main__':
    unittest.main()

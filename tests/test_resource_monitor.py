"""
test_resource_monitor.py

Unit tests for resource_monitor.py. Since this module reads real
system files (/proc/meminfo, /proc/stat) and calls real system tools
(vcgencmd) or network endpoints (Ollama's API), most of these tests
check *shape and graceful degradation* rather than exact values,
which will legitimately vary by machine.

Run from the scanner directory:

    cd ~/scanner
    source venv/bin/activate
    python3 -m unittest tests.test_resource_monitor -v
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import resource_monitor


class TestReadMemory(unittest.TestCase):

    def test_returns_expected_keys(self):
        result = resource_monitor.read_memory()
        self.assertIsNotNone(result, "read_memory() should succeed on any real Linux machine")
        expected_keys = {'total_gb', 'used_gb', 'available_gb', 'percent_used',
                          'swap_total_gb', 'swap_used_gb'}
        self.assertEqual(set(result.keys()), expected_keys)

    def test_values_are_non_negative(self):
        result = resource_monitor.read_memory()
        for key, value in result.items():
            self.assertGreaterEqual(value, 0, f"{key} should never be negative")

    def test_used_plus_available_is_close_to_total(self):
        result = resource_monitor.read_memory()
        # Allow a small tolerance for rounding to 1 decimal place
        self.assertAlmostEqual(
            result['used_gb'] + result['available_gb'],
            result['total_gb'],
            delta=0.2
        )


class TestReadCpuTemp(unittest.TestCase):

    def test_returns_none_or_a_plausible_temperature(self):
        # Correctly returns None on machines/VMs with no accessible
        # sensor (e.g. this test environment) - that's valid, not a
        # failure. If a value IS returned, it must be plausible.
        result = resource_monitor.read_cpu_temp()
        if result is not None:
            self.assertGreater(result, 0)
            self.assertLess(result, 150)


class TestReadOllamaStatus(unittest.TestCase):

    def test_returns_loaded_key_even_when_ollama_unreachable(self):
        # Whether or not Ollama is actually running on this machine,
        # the function must never raise - always return a dict with
        # a 'loaded' key.
        result = resource_monitor.read_ollama_status()
        self.assertIn('loaded', result)
        self.assertIsInstance(result['loaded'], bool)


class TestSampleCpuPercent(unittest.TestCase):

    def test_returns_a_percentage_or_none(self):
        # Use a short interval to keep the test suite fast
        result = resource_monitor.sample_cpu_percent(interval=0.2)
        if result is not None:
            self.assertGreaterEqual(result, 0)
            self.assertLessEqual(result, 100)


class TestTakeSnapshot(unittest.TestCase):

    def test_returns_all_five_fields(self):
        result = resource_monitor.take_snapshot(cpu_sample_interval=0.2)
        expected_keys = {'cpu_percent', 'memory', 'cpu_temp', 'ollama', 'uptime'}
        self.assertEqual(set(result.keys()), expected_keys)
        # memory should always succeed on a real Linux machine
        self.assertIsNotNone(result['memory'])


if __name__ == '__main__':
    unittest.main()

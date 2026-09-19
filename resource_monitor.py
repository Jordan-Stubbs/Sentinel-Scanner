"""
resource_monitor.py

Shared resource-reading functions used by both:
- app.py - continuous live polling for the dashboard's System
  Resources tile (delta-based CPU%, using state between requests)
- main.py - point-in-time snapshots saved into scan history, so
  resource usage during a scan can be reviewed later rather than
  only being visible live in the dashboard at the moment it happens

Kept in its own module so neither app.py nor main.py has to import
from the other.
"""

import os
import subprocess
import json
import time
import urllib.request


def read_memory():
    """Parse /proc/meminfo for RAM and swap stats, returned in GB."""
    try:
        meminfo = {}
        with open('/proc/meminfo') as f:
            for line in f:
                key, value = line.split(':', 1)
                meminfo[key.strip()] = int(value.strip().split()[0])  # kB

        total_gb      = meminfo.get('MemTotal', 0) / (1024 * 1024)
        available_gb  = meminfo.get('MemAvailable', 0) / (1024 * 1024)
        used_gb       = total_gb - available_gb
        swap_total_gb = meminfo.get('SwapTotal', 0) / (1024 * 1024)
        swap_free_gb  = meminfo.get('SwapFree', 0) / (1024 * 1024)
        swap_used_gb  = swap_total_gb - swap_free_gb

        return {
            'total_gb':      round(total_gb, 1),
            'used_gb':       round(used_gb, 1),
            'available_gb':  round(available_gb, 1),
            'percent_used':  round((used_gb / total_gb) * 100, 1) if total_gb else 0,
            'swap_total_gb': round(swap_total_gb, 1),
            'swap_used_gb':  round(swap_used_gb, 1),
        }
    except Exception:
        return None


def read_cpu_temp():
    """Read CPU temperature. Tries the Pi's vcgencmd first, then the
    standard Linux thermal-zone interface. Returns None gracefully if
    neither is available (e.g. inside a VM with no sensor passthrough)."""
    try:
        result = subprocess.run(
            ['vcgencmd', 'measure_temp'],
            capture_output=True, text=True, timeout=2
        )
        output = result.stdout.strip()
        if output.startswith('temp='):
            temp_str = output.replace('temp=', '').replace("'C", '')
            return round(float(temp_str), 1)
    except Exception:
        pass

    try:
        base = '/sys/class/thermal'
        if os.path.isdir(base):
            zones = sorted(d for d in os.listdir(base) if d.startswith('thermal_zone'))
            preferred_keywords = ('cpu', 'pkg', 'soc', 'core')

            candidates = []
            for zone in zones:
                temp_path = os.path.join(base, zone, 'temp')
                type_path = os.path.join(base, zone, 'type')
                if not os.path.exists(temp_path):
                    continue
                zone_type = ''
                if os.path.exists(type_path):
                    with open(type_path) as f:
                        zone_type = f.read().strip().lower()
                candidates.append((zone_type, temp_path))

            candidates.sort(key=lambda c: not any(k in c[0] for k in preferred_keywords))

            for _, temp_path in candidates:
                with open(temp_path) as f:
                    millidegrees = int(f.read().strip())
                celsius = millidegrees / 1000.0
                if 0 < celsius < 150:
                    return round(celsius, 1)
    except Exception:
        pass

    return None


def read_ollama_status():
    """Check whether Phi-3 Mini is currently resident in Ollama's RAM."""
    try:
        req = urllib.request.Request('http://localhost:11434/api/ps')
        with urllib.request.urlopen(req, timeout=2) as response:
            data   = json.loads(response.read().decode('utf-8'))
            models = data.get('models', [])
            if models:
                m = models[0]
                size_gb = m.get('size', 0) / (1024 ** 3)
                return {
                    'loaded':  True,
                    'name':    m.get('name', 'unknown'),
                    'size_gb': round(size_gb, 1)
                }
            return {'loaded': False}
    except Exception:
        return {'loaded': False}


def read_uptime():
    """Read system uptime from /proc/uptime, returned as a short
    human-readable string (e.g. '3d 4h', '5h 23m', '12m'). Directly
    motivated by real debugging: this was the first diagnostic check
    when tracking down the ollama-preload permission bug - a boot-
    time service that had silently failed only became suspicious once
    it was clear the Pi had recently rebooted. Surfacing this on the
    dashboard itself saves an SSH round-trip for that exact class of
    "did something break at boot" question."""
    try:
        with open('/proc/uptime') as f:
            total_seconds = float(f.readline().split()[0])

        days, remainder = divmod(int(total_seconds), 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, _ = divmod(remainder, 60)

        if days > 0:
            return f'{days}d {hours}h'
        elif hours > 0:
            return f'{hours}h {minutes}m'
        else:
            return f'{minutes}m'
    except Exception:
        return None


def _read_cpu_totals():
    with open('/proc/stat') as f:
        parts = f.readline().split()
    values = list(map(int, parts[1:]))
    idle  = values[3] + values[4]  # idle + iowait
    total = sum(values)
    return total, idle


def sample_cpu_percent(interval=1.0):
    """
    Blocking, one-shot CPU usage sample - takes two /proc/stat
    readings 'interval' seconds apart and returns the usage percent
    across that window.

    This differs from app.py's continuous delta-based polling (which
    compares against the previous dashboard request, no extra wait
    needed): a one-off snapshot during a scan pipeline has no
    "previous request" to compare against, so it has to take both
    readings itself, briefly blocking.
    """
    try:
        total1, idle1 = _read_cpu_totals()
        time.sleep(interval)
        total2, idle2 = _read_cpu_totals()

        total_delta = total2 - total1
        idle_delta  = idle2 - idle1
        if total_delta <= 0:
            return None

        usage = 100 * (1 - (idle_delta / total_delta))
        return round(max(0.0, min(100.0, usage)), 1)
    except Exception:
        return None


def take_snapshot(cpu_sample_interval=1.0):
    """
    A full point-in-time resource snapshot: CPU%, RAM, CPU temp,
    Ollama model status, and system uptime. Blocks for
    cpu_sample_interval seconds while sampling CPU usage - negligible
    overhead against a multi-minute scan, but real, so callers doing
    this several times per scan should be aware of the small
    cumulative cost.
    """
    return {
        'cpu_percent': sample_cpu_percent(cpu_sample_interval),
        'memory':      read_memory(),
        'cpu_temp':    read_cpu_temp(),
        'ollama':      read_ollama_status(),
        'uptime':      read_uptime(),
    }

"""
traffic_monitor.py

On-demand SOC-style reconnaissance detection. Sniffs live traffic for
a fixed duration and watches for two patterns:

  - Port scan: one source IP opening new TCP connections (SYN set,
    ACK not set - a genuine connection attempt) to an unusually high
    number of distinct ports on THIS device. On a switched network,
    unicast traffic between two OTHER devices is never delivered to
    this device's interface at all - so "traffic addressed to this
    device" is the only reliable signal available without a mirrored
    switch port. This is a genuine, honest limitation: a scan against
    a different device on the network is invisible to this tool.

    Only SYN-without-ACK packets are counted, not every packet
    addressed here - reply traffic to the Pi's OWN outbound
    connections (e.g. a DNS lookup) would otherwise look identical to
    an inbound scan, since each outbound request typically uses a
    different random ephemeral source port and the reply lands back
    on that port. Confirmed live: without this filter, Cloudflare's
    public DNS resolver (1.1.1.1) was flagged as "scanning" the Pi -
    it was just answering several separate DNS lookups the Pi itself
    made. UDP is deliberately not checked for the same reason: UDP
    has no equivalent flag distinguishing a new probe from a reply,
    so a reliable check isn't possible without deeper stateful
    tracking that's out of scope here.

  - ARP sweep: one source sending ARP "who-has" requests for an
    unusually high number of distinct target IPs in the window - the
    classic signature of a full-subnet host discovery scan (this is
    exactly what this project's own scanner.py does, and is visible
    regardless of the switching limitation above, since ARP requests
    are broadcast to every device on the local segment).

Must be run with elevated privileges (raw socket access), same as
scanner.py. Prints a single JSON result to stdout and nothing else,
so callers (app.py) can capture and parse it directly.

Run standalone for testing:
    sudo python3 traffic_monitor.py 60
"""

import sys
import time
import json
import socket
import os
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, ARP
except ImportError:
    print(json.dumps({
        'success': False,
        'error': "Scapy is not installed. Run: pip install scapy --break-system-packages"
    }))
    sys.exit(1)

import config

def write_status(running, message='', started_at=None, duration=None):
    """Written by this script directly, since it runs as a background
    process (via sudo) that app.py no longer waits on synchronously -
    the dashboard learns what's happening by polling this file rather
    than from a single blocking request/response."""
    with open(config.TRAFFIC_STATUS_PATH, 'w') as f:
        json.dump({
            'running':    running,
            'message':    message,
            'started_at': started_at,
            'duration':   duration,
        }, f)
    try:
        os.chmod(config.TRAFFIC_STATUS_PATH, 0o666)
    except Exception:
        pass

def write_results(result):
    with open(config.TRAFFIC_RESULTS_PATH, 'w') as f:
        json.dump(result, f)
    try:
        os.chmod(config.TRAFFIC_RESULTS_PATH, 0o666)
    except Exception:
        pass

# Distinct destination ports from one source, touching this device,
# within the capture window, before it's flagged as a likely scan.
PORT_SCAN_THRESHOLD = 15

# Distinct target IPs ARP-queried by one source within the window,
# before it's flagged as a likely subnet sweep.
ARP_SWEEP_THRESHOLD = 10


def get_own_ip():
    """Best-effort detection of this device's own IP - port-scan
    detection only makes sense for traffic actually addressed here."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def evaluate_port_hits(port_hits, threshold=PORT_SCAN_THRESHOLD):
    """
    Pure function - takes an already-collected {src_ip: set(ports)}
    mapping and returns the flagged entries, sorted by severity. Kept
    separate from the actual packet capture so this logic can be
    unit tested directly without needing a live network.
    """
    flags = [
        {
            'source_ip':      ip,
            'distinct_ports': len(ports),
            'ports':          sorted(ports)[:30],  # cap for display
        }
        for ip, ports in port_hits.items()
        if len(ports) >= threshold
    ]
    flags.sort(key=lambda f: f['distinct_ports'], reverse=True)
    return flags


def evaluate_arp_hits(arp_hits, threshold=ARP_SWEEP_THRESHOLD):
    """Same pattern as evaluate_port_hits, for ARP sweep detection."""
    flags = [
        {
            'source_ip':        ip,
            'distinct_targets': len(targets),
        }
        for ip, targets in arp_hits.items()
        if len(targets) >= threshold
    ]
    flags.sort(key=lambda f: f['distinct_targets'], reverse=True)
    return flags


def run_traffic_monitor(duration_seconds=60):
    """
    Sniffs live traffic for the given duration and returns a results
    dict. Never raises - capture failures (insufficient privileges,
    no such interface, etc.) are reported in the result rather than
    crashing the caller, matching this project's existing pattern of
    graceful degradation (e.g. CVE lookup falling back to offline
    mode rather than failing the whole pipeline).
    """
    own_ip = get_own_ip()

    port_hits     = defaultdict(set)  # src_ip -> set of dst ports touched (traffic TO own_ip)
    arp_hits      = defaultdict(set)  # src_ip -> set of target IPs ARP-queried
    total_packets = [0]  # mutable via closure; a plain int can't be reassigned inside handle_packet

    def handle_packet(pkt):
        total_packets[0] += 1
        try:
            if pkt.haslayer(ARP) and pkt[ARP].op == 1:  # who-has
                src, tgt = pkt[ARP].psrc, pkt[ARP].pdst
                if src and tgt:
                    arp_hits[src].add(tgt)
                return

            if own_ip and pkt.haslayer(IP) and pkt[IP].dst == own_ip and pkt.haslayer(TCP):
                tcp = pkt[TCP]
                # Only count genuine new-connection attempts (SYN set,
                # ACK not set) - a handshake reply (SYN-ACK) or any
                # later packet in an existing connection (plain ACK,
                # data) is reply/session traffic, not a scan. Without
                # this filter, the Pi's own outbound activity (e.g. a
                # DNS lookup) gets misread as an inbound scan: each
                # outbound request uses a different random ephemeral
                # source port, so the replies land on many different
                # destination ports on the Pi - indistinguishable from
                # a real scan unless SYN-only packets are isolated.
                # (Confirmed live: Cloudflare's DNS resolver 1.1.1.1
                # was flagged as "scanning" the Pi before this fix -
                # it was just answering several separate DNS lookups.)
                if tcp.flags & 0x02 and not tcp.flags & 0x10:  # SYN set, ACK not set
                    port_hits[pkt[IP].src].add(tcp.dport)
        except Exception:
            pass  # never let one malformed packet kill the whole capture

    start = time.time()
    try:
        sniff(prn=handle_packet, timeout=duration_seconds, store=False)
    except PermissionError:
        return {
            'success': False,
            'error':   'Permission denied - packet capture requires elevated privileges.',
        }
    except Exception as e:
        return {
            'success': False,
            'error':   f'Capture failed: {e}',
        }

    elapsed = round(time.time() - start, 1)

    return {
        'success':          True,
        'duration_seconds': elapsed,
        'own_ip':           own_ip,
        # Diagnostic - total packets seen during the capture, regardless
        # of whether anything matched the detection thresholds. If this
        # is 0 (or suspiciously low) while genuine test traffic was
        # generated, that points to a capture/interface problem rather
        # than a detection-logic problem.
        'total_packets':    total_packets[0],
        'port_scan_flags':  evaluate_port_hits(port_hits),
        'arp_sweep_flags':  evaluate_arp_hits(arp_hits),
        'timestamp':        time.strftime('%Y-%m-%d %H:%M:%S'),
    }


if __name__ == "__main__":
    duration = 60
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except ValueError:
            pass

    # app.py's trigger route already wrote the 'running' status
    # (with started_at and duration) synchronously, immediately, at
    # the moment this process was spawned - not here, since Python
    # startup plus importing scapy can genuinely take several seconds
    # on a Raspberry Pi, and a poll firing during that window would
    # otherwise still see stale leftover status from whatever ran
    # before this. This script only needs to write the FINAL outcome
    # once the capture genuinely completes.
    result = run_traffic_monitor(duration)
    write_results(result)
    write_status(running=False, message='', started_at=None, duration=None)

    # Also print to stdout - harmless, and useful when running this
    # script manually from the command line for testing/debugging.
    print(json.dumps(result))

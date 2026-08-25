import json
import config

RULES = [
    # ── Remote Access / Admin ────────────────────────────────
    {
        'id': 'VULN-001',
        'name': 'Telnet Open',
        'protocol': 'tcp',
        'ports': [23],
        'severity': 'critical',
        'description': 'Telnet transmits all data including passwords in plain text with no encryption.',
        'remediation': 'Disable Telnet immediately and use SSH instead.'
    },
    {
        'id': 'VULN-002',
        'name': 'RDP Exposed',
        'protocol': 'tcp',
        'ports': [3389],
        'severity': 'critical',
        'description': 'Remote Desktop Protocol is exposed. RDP is one of the most commonly exploited services, used in ransomware attacks and brute force campaigns.',
        'remediation': 'Restrict RDP to trusted IPs only or place behind a VPN. Disable if not needed.'
    },
    {
        'id': 'VULN-003',
        'name': 'VNC Remote Desktop Exposed',
        'protocol': 'tcp',
        'ports': [5900, 5901],
        'severity': 'critical',
        'description': 'VNC provides full graphical remote access to a device. Many VNC installations have weak or no authentication.',
        'remediation': 'Disable VNC if unused. If needed, restrict to trusted IPs and require strong authentication.'
    },
    {
        'id': 'VULN-004',
        'name': 'Android Debug Bridge (ADB) Exposed',
        'protocol': 'tcp',
        'ports': [5555],
        'severity': 'critical',
        'description': 'ADB allows full shell access to an Android device over the network without authentication.',
        'remediation': 'Disable ADB over network in developer settings.'
    },

    # ── File Transfer ────────────────────────────────────────
    {
        'id': 'VULN-005',
        'name': 'FTP Open',
        'protocol': 'tcp',
        'ports': [21],
        'severity': 'high',
        'description': 'FTP transmits credentials and data in plain text with no encryption.',
        'remediation': 'Replace FTP with SFTP or FTPS.'
    },
    {
        'id': 'VULN-006',
        'name': 'SMB / Windows File Sharing Exposed',
        'protocol': 'tcp',
        'ports': [445, 139],
        'severity': 'high',
        'description': 'SMB is exposed on the network. SMB vulnerabilities have been exploited by major ransomware including WannaCry and NotPetya.',
        'remediation': 'Block SMB at the network perimeter. Ensure Windows is fully patched. Disable SMBv1.'
    },

    # ── Databases ────────────────────────────────────────────
    {
        'id': 'VULN-007',
        'name': 'MySQL Database Exposed',
        'protocol': 'tcp',
        'ports': [3306],
        'severity': 'critical',
        'description': 'A MySQL database port is openly accessible on the network. Databases should never be directly exposed.',
        'remediation': 'Restrict MySQL to localhost or trusted IPs only. Use a firewall rule to block external access.'
    },
    {
        'id': 'VULN-008',
        'name': 'PostgreSQL Database Exposed',
        'protocol': 'tcp',
        'ports': [5432],
        'severity': 'critical',
        'description': 'A PostgreSQL database port is openly accessible on the network.',
        'remediation': 'Restrict PostgreSQL to localhost or trusted IPs only via pg_hba.conf and firewall rules.'
    },
    {
        'id': 'VULN-009',
        'name': 'MongoDB Exposed',
        'protocol': 'tcp',
        'ports': [27017],
        'severity': 'critical',
        'description': 'MongoDB is exposed on the network. Many MongoDB installations have no authentication enabled by default, allowing anyone to read and delete data.',
        'remediation': 'Enable MongoDB authentication and bind it to localhost. Block port 27017 at the firewall.'
    },
    {
        'id': 'VULN-010',
        'name': 'Redis Exposed',
        'protocol': 'tcp',
        'ports': [6379],
        'severity': 'critical',
        'description': 'Redis is exposed on the network. Redis has no authentication by default and can be used to read data or gain remote code execution.',
        'remediation': 'Bind Redis to localhost, enable requirepass authentication, and block port 6379 at the firewall.'
    },
    {
        'id': 'VULN-011',
        'name': 'Memcached Exposed',
        'protocol': 'tcp',
        'ports': [11211],
        'severity': 'high',
        'description': 'Memcached is exposed on the network. It has no authentication and has been used in large-scale DDoS amplification attacks.',
        'remediation': 'Bind Memcached to localhost only and block port 11211 at the firewall.'
    },

    # ── Network Services ─────────────────────────────────────
    {
        'id': 'VULN-012',
        'name': 'SOCKS Proxy Exposed',
        'protocol': 'tcp',
        'ports': [1080],
        'severity': 'high',
        'description': 'An open SOCKS proxy can be abused by attackers to route malicious traffic through your network anonymously.',
        'remediation': 'Disable or firewall the SOCKS proxy if not intentional.'
    },
    {
        'id': 'VULN-013',
        'name': 'SNMP Exposed',
        'protocol': 'tcp',
        'ports': [161, 162],
        'severity': 'high',
        'description': 'SNMP can expose detailed device information including hardware, software, and network configuration. SNMPv1/v2 use plain text community strings.',
        'remediation': 'Disable SNMP if unused. If needed, upgrade to SNMPv3 with authentication and restrict access.'
    },
    {
        'id': 'VULN-014',
        'name': 'DNS Open Resolver',
        'protocol': 'tcp',
        'ports': [53],
        'severity': 'medium',
        'description': 'A DNS service is running and may be configured as an open resolver, which can be abused for DNS amplification DDoS attacks.',
        'remediation': 'Configure DNS to only respond to authorised clients. Disable recursion for external queries.'
    },
    {
        'id': 'VULN-015',
        'name': 'SMTP Mail Server Exposed',
        'protocol': 'tcp',
        'ports': [25],
        'severity': 'medium',
        'description': 'An SMTP mail server is running. Open or misconfigured SMTP servers can be used as spam relays.',
        'remediation': 'Ensure SMTP relay is restricted to authorised users only. Disable if not needed.'
    },

    # ── IoT / Embedded ───────────────────────────────────────
    {
        'id': 'VULN-016',
        'name': 'Unencrypted MQTT (IoT)',
        'protocol': 'tcp',
        'ports': [1883],
        'severity': 'high',
        'description': 'MQTT is an IoT messaging protocol running without encryption. Anyone on the network can intercept or inject messages to connected devices.',
        'remediation': 'Use MQTT over TLS (port 8883) and require client authentication.'
    },
    {
        'id': 'VULN-017',
        'name': 'Unencrypted HTTP Admin Interface',
        'protocol': 'tcp',
        'ports': [80, 8080, 8000],
        'severity': 'medium',
        'description': 'Device has a web interface served over unencrypted HTTP. Credentials and session data can be intercepted.',
        'remediation': 'Access admin interfaces over HTTPS only.'
    },
    {
        'id': 'VULN-018',
        'name': 'SIP VoIP Port Exposed',
        'protocol': 'tcp',
        'ports': [5060, 5061],
        'severity': 'medium',
        'description': 'SIP port is open. Misconfigured VoIP systems can allow toll fraud and eavesdropping on calls.',
        'remediation': 'Restrict SIP access to trusted IPs only.'
    },

    # ── SSH ──────────────────────────────────────────────────
    {
        'id': 'VULN-019',
        'name': 'Outdated SSH Version',
        'protocol': 'tcp',
        'ports': [22],
        'severity': 'medium',
        'description': 'SSH is running but may be an outdated version with known vulnerabilities.',
        'remediation': 'Ensure SSH is updated to the latest version and disable password authentication in favour of key-based auth.'
    },
]

SEVERITY_WEIGHTS = {
    'critical': 1.0,
    'high':     0.7,
    'medium':   0.4,
    'low':      0.2
}

def analyse(scan_results):
    findings = []
    for host in scan_results:
        ip       = host['ip']
        hostname = host['hostname']
        vendor   = host.get('vendor', '')

        for proto, ports in host['protocols'].items():
            for port_num, port_info in ports.items():
                for rule in RULES:
                    if proto == rule['protocol'] and int(port_num) in rule['ports']:
                        findings.append({
                            'host':        ip,
                            'hostname':    hostname,
                            'vendor':      vendor,
                            'port':        port_num,
                            'rule_id':     rule['id'],
                            'name':        rule['name'],
                            'severity':    rule['severity'],
                            'description': rule['description'],
                            'remediation': rule['remediation']
                        })
    return findings

def calculate_score(findings):
    if not findings:
        return 100

    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for f in findings:
        sev = f['severity']
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Diminishing returns — each extra finding of same severity hurts less
    penalty = 0
    for sev, count in severity_counts.items():
        weight = SEVERITY_WEIGHTS[sev]
        for i in range(count):
            penalty += weight * (0.7 ** i) * 20

    return max(0, round(100 - penalty))

def get_rating(score):
    if score >= 80:
        return 'GOOD'
    elif score >= 60:
        return 'MODERATE'
    elif score >= 40:
        return 'POOR'
    else:
        return 'CRITICAL'

def get_severity_counts(findings):
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for f in findings:
        sev = f['severity']
        if sev in counts:
            counts[sev] += 1
    return counts

if __name__ == "__main__":
    with open(config.SCAN_RESULTS_PATH) as f:
        data = json.load(f)

    scan_results = data['hosts'] if isinstance(data, dict) else data

    findings = analyse(scan_results)
    score    = calculate_score(findings)
    rating   = get_rating(score)
    counts   = get_severity_counts(findings)

    print(f"\n{'='*50}")
    print(f"  SECURITY SCORE: {score}/100  |  RATING: {rating}")
    print(f"{'='*50}\n")

    if not findings:
        print("[+] No vulnerabilities detected.")
    else:
        print(f"[!] {len(findings)} finding(s):\n")
        for f in findings:
            print(f"  [{f['severity'].upper()}] {f['name']}")
            print(f"  Host: {f['host']} ({f['hostname']}) — Port {f['port']}")
            print(f"  {f['description']}")
            print(f"  Fix: {f['remediation']}\n")

    with open(config.ANALYSIS_RESULTS_PATH, 'w') as f:
        json.dump({
            'score':           score,
            'rating':          rating,
            'findings':        findings,
            'severity_counts': counts
        }, f, indent=2)

    print("[+] Analysis saved to analysis_results.json")

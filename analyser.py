import json
import config

RULES = [
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
        'ports': [5900, 5901, 5902, 5903, 5904],
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
        'severity': 'critical',
        'description': 'SMB is exposed on the network. SMB vulnerabilities have been exploited by major ransomware including WannaCry and NotPetya.',
        'remediation': 'Block SMB at the network perimeter. Ensure Windows is fully patched. Disable SMBv1.'
    },
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
        # KNOWN LIMITATION (documented 2026-09-17): DNS primarily
        # operates over UDP, but this scanner only performs TCP scans
        # (nmap -sV -O --open, no -sU). A DNS server that answers
        # exclusively on UDP/53 would be invisible to this rule. In
        # practice this hasn't caused a real miss - common DNS server
        # software (dnsmasq, BIND, NSD) also answers on TCP/53, since
        # it's required for zone transfers - but a minimal/embedded
        # UDP-only implementation could still be missed. Deliberately
        # left as-is rather than adding UDP scanning, given the real
        # scan-time cost that would add for an unconfirmed benefit.
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
        'name': 'SIP VoIP Port Exposed (Unencrypted)',
        'protocol': 'tcp',
        'ports': [5060],
        'severity': 'medium',
        'description': 'An unencrypted SIP port is open. Misconfigured VoIP systems can allow toll fraud, and since this transport isn\'t encrypted, calls and signalling can also potentially be eavesdropped on.',
        'remediation': 'Restrict SIP access to trusted IPs only, and consider migrating to SIP over TLS (port 5061) to remove the eavesdropping risk.'
    },
    {
        'id': 'VULN-019',
        'name': 'Outdated SSH Version',
        'protocol': 'tcp',
        'ports': [22],
        'severity': 'medium',
        'description': 'SSH is running but may be an outdated version with known vulnerabilities.',
        'remediation': 'Ensure SSH is updated to the latest version and disable password authentication in favour of key-based auth.'
    },
    {
        'id': 'VULN-020',
        'name': 'Elasticsearch / Kibana Exposed',
        'protocol': 'tcp',
        'ports': [9200, 5601],
        'severity': 'critical',
        'description': 'An Elasticsearch or Kibana instance is directly accessible with no authentication. Exposed Elasticsearch databases are one of the most common causes of large-scale data breaches, since anyone who can reach the port can read, modify, or delete all indexed data.',
        'remediation': "Enable Elasticsearch's built-in security features (authentication and TLS), or place it behind a firewall/VPN so it's never reachable from the wider network."
    },
    {
        'id': 'VULN-021',
        'name': 'Docker API Exposed',
        'protocol': 'tcp',
        'ports': [2375],
        'severity': 'critical',
        'description': 'The Docker Engine API is exposed without authentication. Anyone who can reach this port can run arbitrary containers with full host access, effectively giving them complete control of this machine.',
        'remediation': 'Never expose the Docker API without TLS client-certificate authentication. Bind it to localhost only, or use a Unix socket instead of a network port.'
    },
    {
        'id': 'VULN-022',
        'name': 'NFS Exposed',
        'protocol': 'tcp',
        'ports': [2049],
        'severity': 'high',
        'description': 'An NFS (Network File System) share is exposed. Like SMB, NFS often allows remote read/write access to files with weak or no authentication, depending on configuration.',
        'remediation': "Restrict NFS exports to specific trusted IP addresses, and ensure exports aren't configured with unrestricted (no_root_squash / world-readable) access."
    },
    {
        'id': 'VULN-023',
        'name': 'rsync Daemon Exposed',
        'protocol': 'tcp',
        'ports': [873],
        'severity': 'high',
        'description': 'An rsync daemon is running and directly reachable. Depending on configuration, this can allow anonymous remote read or write access to files on this device.',
        'remediation': "Require authentication for rsync modules, or restrict access to trusted IPs via rsync's own hosts allow/deny settings."
    },
    {
        'id': 'VULN-024',
        'name': 'RTSP / IP Camera Stream Exposed',
        'protocol': 'tcp',
        'ports': [554],
        'severity': 'high',
        'description': 'An RTSP video/audio stream (commonly used by IP cameras and baby monitors) is exposed. If unauthenticated, anyone who can reach this port may be able to view or listen to the live feed.',
        'remediation': "Set a strong password on the camera/device's admin interface, and confirm RTSP itself requires authentication rather than allowing anonymous stream access."
    },
    {
        'id': 'VULN-025',
        'name': 'CouchDB Exposed',
        'protocol': 'tcp',
        'ports': [5984],
        'severity': 'critical',
        'description': 'A CouchDB instance is directly accessible. Older CouchDB versions have a known unauthenticated remote code execution vulnerability (CVE-2017-12635 / CVE-2017-12636), and even patched versions should never be exposed without authentication.',
        'remediation': "Enable CouchDB's admin party protection (require authentication), update to a patched version, and restrict network access."
    },
    {
        'id': 'VULN-026',
        'name': 'RabbitMQ Management Exposed',
        'protocol': 'tcp',
        'ports': [15672],
        'severity': 'high',
        'description': 'The RabbitMQ management web interface is exposed. This is frequently left on the default guest/guest credentials, which grants full control over the message queue.',
        'remediation': 'Change the default RabbitMQ credentials immediately, and restrict the management interface to trusted IPs only.'
    },
    {
        'id': 'VULN-027',
        'name': 'Modbus (Industrial Control) Exposed',
        'protocol': 'tcp',
        'ports': [502],
        'severity': 'medium',
        'description': 'A Modbus TCP service is exposed. Modbus has no authentication built into the protocol at all, so anyone who can reach this port can potentially read or write industrial control data. This is unusual to see on a typical home or office network and may indicate a misconfigured smart-home or building-automation gateway.',
        'remediation': 'Modbus should never be reachable outside an isolated control network. Investigate what device is running this and move it behind a dedicated, firewalled segment.'
    },
    {
        'id': 'VULN-028',
        'name': 'WinRM Exposed',
        'protocol': 'tcp',
        'ports': [5985, 5986],
        'severity': 'medium',
        'description': 'Windows Remote Management (WinRM) is exposed, allowing remote PowerShell and management access to this machine if valid credentials are obtained.',
        'remediation': 'Restrict WinRM to trusted management networks only, ensure HTTPS (port 5986) is used rather than HTTP (5985), and enforce strong account credentials.'
    },
    {
        'id': 'VULN-029',
        'name': 'LDAP Directory Service Exposed',
        'protocol': 'tcp',
        'ports': [389],
        'severity': 'medium',
        'description': 'An LDAP directory service is exposed. Depending on configuration, this may permit anonymous (unauthenticated) queries against the directory, potentially revealing usernames, group structures, or other sensitive organisational data. Confirming whether anonymous bind is actually permitted requires directly testing the LDAP service, which this scanner does not currently do automatically.',
        'remediation': 'Disable anonymous bind unless specifically required, and restrict LDAP access to trusted internal clients only.'
    },
    {
        'id': 'VULN-030',
        'name': 'SIP VoIP Port Exposed (TLS)',
        'protocol': 'tcp',
        'ports': [5061],
        'severity': 'medium',
        'description': "An encrypted SIP-TLS port is open. The transport itself is encrypted, so eavesdropping isn't the concern here - but toll fraud via weak or default account credentials is still possible regardless of transport encryption.",
        'remediation': 'Ensure SIP accounts use strong, unique credentials - encryption alone does not prevent toll fraud from a compromised or weak account.'
    },
    {
        'id': 'VULN-031',
        'name': 'Jellyfin Media Server Exposed',
        'protocol': 'tcp',
        'ports': [8096],
        'severity': 'medium',
        'description': 'A Jellyfin media server is directly reachable. If not intended to be accessed from outside a VPN or trusted network, this exposes your personal media library and potentially account credentials to anyone who can reach it.',
        'remediation': 'Restrict Jellyfin to trusted networks or a VPN rather than exposing it directly, and ensure a strong password is set on all accounts.'
    },
    {
        'id': 'VULN-032',
        'name': 'CUPS / IPP Print Server Exposed',
        'protocol': 'tcp',
        'ports': [631],
        'severity': 'high',
        'description': 'A CUPS or IPP print server is directly reachable. Exposed print servers have been the source of serious real-world vulnerabilities, including remote code execution in some historical CUPS releases, beyond the more routine risk of print job interception or spoofed print jobs.',
        'remediation': 'Ensure CUPS is fully updated, restrict access to the local network only, and disable remote administration if not specifically needed.'
    },
    {
        'id': 'VULN-033',
        'name': 'Home Assistant Exposed',
        'protocol': 'tcp',
        'ports': [8123],
        'severity': 'critical',
        'description': 'A Home Assistant instance is directly reachable. Home Assistant is often the central control point for a smart home - locks, cameras, alarms, and other connected devices - so unauthorised access here can mean far more than a typical service compromise.',
        'remediation': 'Never expose Home Assistant directly to the internet. Use its built-in remote access (Nabu Casa) or a VPN instead, and ensure multi-factor authentication is enabled.'
    },
    {
        'id': 'VULN-034',
        'name': 'Chromecast / Google Cast Exposed',
        'protocol': 'tcp',
        'ports': [8008, 8009],
        'severity': 'low',
        'description': "A Chromecast or Google Cast-enabled device is discoverable and reachable. This mainly allows someone on the network to cast content to the device without authorisation - a nuisance rather than a serious security risk, but still worth being aware of.",
        'remediation': 'This is largely inherent to how Cast devices work on a local network. If it\'s a concern, isolate smart-TV/casting devices on a separate guest network segment.'
    },
    {
        'id': 'VULN-035',
        'name': 'Plex Media Server Exposed',
        'protocol': 'tcp',
        'ports': [32400],
        'severity': 'medium',
        'description': 'A Plex media server is directly reachable. Similar to other self-hosted media servers, this exposes your personal library and account access to anyone who can reach it, and Plex has had real historical vulnerabilities of its own.',
        'remediation': "Keep Plex fully updated, use its official remote-access feature rather than manual port-forwarding where possible, and ensure a strong account password is set."
    },
    {
        'id': 'VULN-036',
        'name': 'Portainer (Docker Management UI) Exposed',
        'protocol': 'tcp',
        'ports': [9000],
        'severity': 'high',
        'description': 'A Portainer instance (a web UI for managing Docker) is directly reachable. Portainer has its own authentication, but is frequently left on default or weak admin credentials, which would grant full control over every container on the host.',
        'remediation': "Change Portainer's default credentials immediately, and restrict access to trusted networks or a VPN rather than exposing it directly."
    },
    {
        'id': 'VULN-037',
        'name': 'Finger Service Exposed',
        'protocol': 'tcp',
        'ports': [79],
        'severity': 'low',
        'description': 'The Finger protocol is exposed, which can reveal usernames, login times, and other account details to anyone who queries it. Largely obsolete today, but still occasionally found on older Unix-like systems.',
        'remediation': "Disable the Finger service unless there's a specific reason to keep it running."
    },
    {
        'id': 'VULN-038',
        'name': 'Ident (AUTH) Service Exposed',
        'protocol': 'tcp',
        'ports': [113],
        'severity': 'low',
        'description': 'The Ident (AUTH) protocol is exposed, which can reveal which user account owns a given network connection. A minor information disclosure risk on its own, though it has occasionally been used to assist in profiling a target.',
        'remediation': 'Disable Ident/AUTH unless a specific service (e.g. some older IRC networks) requires it.'
    },
    {
        'id': 'VULN-039',
        'name': 'Echo Service Exposed',
        'protocol': 'tcp',
        'ports': [7],
        'severity': 'low',
        'description': 'The Echo service is exposed, which simply reflects back whatever data is sent to it. Not dangerous on its own, but a genuinely unnecessary legacy service that shouldn\'t be running today.',
        'remediation': 'Disable the Echo service - it serves no practical purpose on a modern network.'
    },
    {
        'id': 'VULN-040',
        'name': 'Minecraft Server Exposed',
        'protocol': 'tcp',
        'ports': [25565],
        'severity': 'low',
        'description': "A Minecraft server is directly reachable. This is common and often intentional for home-hosted game servers, and doesn't expose the host system itself - but an unprotected server can still be joined, griefed, or targeted for denial-of-service by anyone who finds it.",
        'remediation': 'If this is intentional, consider requiring a whitelist or authentication (e.g. online-mode account verification, or a proxy like Velocity) rather than leaving the server fully open to anyone.'
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
        os_guess = host.get('os', 'Unknown')

        for proto, ports in host['protocols'].items():
            for port_num, port_info in ports.items():
                for rule in RULES:
                    if proto == rule['protocol'] and int(port_num) in rule['ports']:
                        findings.append({
                            'host':        ip,
                            'hostname':    hostname,
                            'vendor':      vendor,
                            'os':          os_guess,
                            'product':     port_info.get('product', ''),
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
            print(f"  Host: {f['host']} ({f['hostname']}) - Port {f['port']}")
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

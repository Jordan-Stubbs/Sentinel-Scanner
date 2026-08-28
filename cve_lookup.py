import json
import urllib.request
import urllib.parse
import urllib.error
import os
import re
import time
import config

# Path to local offline CVE cache
CVE_CACHE_PATH = config.CVE_CACHE_PATH

# How many CVEs to fetch per service from NVD
MAX_CVE_PER_SERVICE = 3

# Ports to skip CVE lookup on — internal tools, unknown services etc.
SKIP_PORTS = {
    '8080',   # Generic proxy/dev ports
    '8888',   # Generic dev ports
    '8009',   # AJP connector
    '9080',   # Generic
    '49152',  # Dynamic/ephemeral ports
    '62078',  # iPhone sync
    '8089',   # Splunk / tcpwrapped
    '6668',   # IRC variants
    '1111',   # UPnP
    '2046',   # UPnP
    '3000',   # Generic dev
    '3001',   # Generic dev
    '7000',   # RTSP/generic
    '9000',   # Generic
    '10001',  # Generic
    '8443',   # Generic HTTPS alt
}
# Always exclude the dashboard's own port, whatever it's currently
# set to (config.DASHBOARD_PORT) — this is what actually fixes the
# recurring bug, since it stays correct even if the port changes
# again in the future, rather than needing a new hardcoded entry
# added by hand each time.
SKIP_PORTS.add(config.DASHBOARD_PORT)

def cvss_to_severity(score):
    if score >= 9.0:
        return 'critical'
    elif score >= 7.0:
        return 'high'
    elif score >= 4.0:
        return 'medium'
    else:
        return 'low'

def clean_version(version_str):
    """Extract clean version number from nmap version string."""
    if not version_str or version_str.strip() == '':
        return None
    # Extract first version-like pattern e.g. "6.6.0" from "OpenSSH 6.6.0p1 Ubuntu"
    match = re.search(r'(\d+\.\d+[\.\d]*)', version_str)
    if match:
        return match.group(1)
    return None

def build_search_query(service_name, version):
    """Build a precise search query including version number."""
    if version:
        return f"{service_name} {version}"
    return service_name

def query_nvd_online(keyword, retries=2):
    """Query the NVD API online."""
    encoded = urllib.parse.quote(keyword)
    url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch={encoded}&resultsPerPage={MAX_CVE_PER_SERVICE}"
    )

    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'NetworkVulnerabilityScanner/1.0',
                    'Accept':     'application/json'
                }
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
                return data.get('vulnerabilities', [])
        except urllib.error.URLError:
            if attempt < retries - 1:
                time.sleep(2)
            continue
        except Exception:
            continue
    return None  # None = offline/failed, [] = no results

def is_relevant_cve(description, service_name, version):
    """
    Filter out CVEs that clearly don't match the detected service/version.
    Prevents old irrelevant CVEs being returned for generic keyword matches.
    """
    desc_lower = description.lower()
    service_lower = service_name.lower()

    # Must mention the service name in the description
    if service_lower not in desc_lower:
        # Try common aliases
        aliases = {
            'openssh': ['ssh', 'openssh'],
            'openssl': ['ssl', 'openssl', 'ssleay'],
            'apache':  ['apache', 'httpd'],
            'bind':    ['bind', 'named', 'dns'],
            'vsftpd':  ['vsftpd', 'ftp'],
            'samba':   ['samba', 'smb', 'cifs'],
            'mysql':   ['mysql', 'mariadb'],
            'asterisk':['asterisk', 'sip'],
        }
        matched = False
        for key, alias_list in aliases.items():
            if key in service_lower:
                if any(a in desc_lower for a in alias_list):
                    matched = True
                    break
        if not matched:
            return False

    # If we have a version, check the CVE mentions a version range that could include it
    if version:
        # If description mentions a specific version that's clearly newer than ours
        # we can't reliably filter so we just pass it through
        pass

    return True

def parse_nvd_response(vulnerabilities, service_name, version, host, hostname, vendor, port):
    """Parse NVD API response into findings format."""
    findings = []
    for vuln in vulnerabilities:
        try:
            cve    = vuln.get('cve', {})
            cve_id = cve.get('id', 'Unknown')

            # Get English description
            descriptions = cve.get('descriptions', [])
            description  = next(
                (d['value'] for d in descriptions if d.get('lang') == 'en'),
                'No description available.'
            )

            # Filter irrelevant CVEs
            if not is_relevant_cve(description, service_name, version):
                continue

            # Truncate long descriptions
            if len(description) > 250:
                description = description[:247] + '...'

            # Get CVSS score — try v3.1, v3.0, v2 in order
            metrics  = cve.get('metrics', {})
            score    = 0.0
            severity = 'medium'

            for cvss_key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if cvss_key in metrics and metrics[cvss_key]:
                    cvss_data = metrics[cvss_key][0]
                    score     = float(cvss_data.get('cvssData', {}).get('baseScore', 0.0))
                    severity  = cvss_to_severity(score)
                    break

            # Skip very low severity CVEs to reduce noise
            if score < 4.0:
                continue

            published = cve.get('published', '')[:10]

            findings.append({
                'host':        host,
                'hostname':    hostname,
                'vendor':      vendor,
                'port':        port,
                'rule_id':     cve_id,
                'name':        f"CVE: {cve_id}",
                'severity':    severity,
                'description': f"[CVSS {score}] {description}",
                'remediation': f"Review and patch this vulnerability. See: https://nvd.nist.gov/vuln/detail/{cve_id}",
                'cve_id':      cve_id,
                'cvss_score':  score,
                'published':   published,
                'source':      'nvd_online'
            })
        except Exception:
            continue

    return findings

def query_nvd_offline(keyword):
    """
    Query the local CVE cache.

    Matches on product-name terms (required). If the version number
    also appears in a CVE's cached description, that entry is treated
    as a stronger match and ranked first — but the absence of a version
    match no longer excludes an entry outright. NVD descriptions rarely
    spell out an exact version number even for CVEs that genuinely
    affect that version, so requiring it was excluding valid matches
    from the offline cache.
    """
    if not os.path.exists(CVE_CACHE_PATH):
        return None
    try:
        with open(CVE_CACHE_PATH) as f:
            cache = json.load(f)

        terms = keyword.lower().split()

        # Separate product-name terms (must match) from version-like
        # terms (bonus if they match) — a version term contains a digit.
        name_terms    = [t for t in terms if not any(c.isdigit() for c in t)]
        version_terms = [t for t in terms if any(c.isdigit() for c in t)]

        if not name_terms:
            # Keyword was version-only (shouldn't normally happen) —
            # fall back to requiring every term, same as before.
            name_terms = terms
            version_terms = []

        scored_matches = []
        for cve_id, entry in cache.items():
            desc = entry.get('description', '').lower()

            # Product name terms are still a hard requirement.
            if not all(term in desc for term in name_terms):
                continue

            version_hit = bool(version_terms) and any(term in desc for term in version_terms)
            scored_matches.append((version_hit, entry))

        # Entries whose description also mentions the version come first;
        # order within each group otherwise follows cache iteration order.
        scored_matches.sort(key=lambda pair: pair[0], reverse=True)

        matches = [entry for _, entry in scored_matches[:MAX_CVE_PER_SERVICE]]
        return matches
    except Exception:
        return None

def parse_offline_cache(matches, host, hostname, vendor, port):
    """Parse offline cache entries into findings format."""
    findings = []
    for entry in matches:
        try:
            cve_id   = entry.get('id', 'Unknown')
            score    = float(entry.get('cvss_score', 0.0))
            if score < 4.0:
                continue
            severity = cvss_to_severity(score)
            findings.append({
                'host':        host,
                'hostname':    hostname,
                'vendor':      vendor,
                'port':        port,
                'rule_id':     cve_id,
                'name':        f"CVE: {cve_id}",
                'severity':    severity,
                'description': f"[CVSS {score}] {entry.get('description', 'No description.')}",
                'remediation': f"Review and patch this vulnerability. See: https://nvd.nist.gov/vuln/detail/{cve_id}",
                'cve_id':      cve_id,
                'cvss_score':  score,
                'published':   entry.get('published', ''),
                'source':      'nvd_offline'
            })
        except Exception:
            continue
    return findings

# Services worth checking — mapped from nmap service names to proper product names
SERVICES_OF_INTEREST = {
    'ssh':          'OpenSSH',
    'ftp':          'vsftpd',
    'telnet':       'telnet',
    'smtp':         'Postfix',
    'domain':       'BIND',
    'http':         'Apache',
    'https':        'OpenSSL',
    'ms-sql-s':     'Microsoft SQL Server',
    'mysql':        'MySQL',
    'rdp':          'Remote Desktop Protocol',
    'vnc':          'VNC',
    'sip':          'Asterisk',
    'socks5':       'SOCKS',
    'iphone-sync':  None,  # Skip — no meaningful CVE lookup
    'tcpwrapped':   None,  # Skip — service unknown
    'ajp13':        'Apache Tomcat',
    'blackice-icecap': None,
}

def run_cve_lookup(scan_results):
    """
    Main function — runs CVE lookup for all detected services.
    Only queries services where nmap detected a specific version string.
    Returns list of CVE findings and whether online mode was used.
    """
    all_cve_findings = []
    online_mode      = True
    services_checked = set()

    for host in scan_results:
        ip       = host.get('ip', '')
        hostname = host.get('hostname', '')
        vendor   = host.get('vendor', '')

        for proto, ports in host.get('protocols', {}).items():
            for port_num, port_info in ports.items():
                # Skip excluded ports
                if str(port_num) in SKIP_PORTS:
                    continue

                service = port_info.get('service', '').lower()
                version = port_info.get('version', '').strip()

                # Skip services we can't meaningfully look up
                if service in SERVICES_OF_INTEREST and SERVICES_OF_INTEREST[service] is None:
                    continue

                # Only proceed if nmap detected a version string
                clean_ver = clean_version(version)
                if not clean_ver:
                    print(f"  [CVE] Skipping {service} on port {port_num} — no version detected")
                    continue

                # Get the proper product name
                service_name = SERVICES_OF_INTEREST.get(service, service.capitalize())

                # Build search query with version
                keyword = build_search_query(service_name, clean_ver)

                # Skip duplicates
                if keyword in services_checked:
                    continue
                services_checked.add(keyword)

                print(f"  [CVE] Checking: {keyword} (port {port_num})")

                # Try online first
                vulns = query_nvd_online(keyword)

                if vulns is None:
                    # Online failed — try offline cache
                    online_mode = False
                    print(f"  [CVE] Offline mode — checking local cache for: {keyword}")
                    offline_matches = query_nvd_offline(keyword)
                    if offline_matches:
                        findings = parse_offline_cache(
                            offline_matches, ip, hostname, vendor, port_num
                        )
                        all_cve_findings.extend(findings)
                elif vulns:
                    findings = parse_nvd_response(
                        vulns, service_name, clean_ver,
                        ip, hostname, vendor, port_num
                    )
                    all_cve_findings.extend(findings)

                # Respect NVD rate limit — max 5 requests per 30 seconds without API key
                time.sleep(0.6)

    return all_cve_findings, online_mode

if __name__ == "__main__":
    print("[*] Loading scan results...")
    with open(config.SCAN_RESULTS_PATH) as f:
        data = json.load(f)

    scan_results = data['hosts'] if isinstance(data, dict) else data

    print("[*] Running CVE lookup...")
    findings, online = run_cve_lookup(scan_results)

    mode = "ONLINE" if online else "OFFLINE"
    print(f"\n[+] CVE lookup complete ({mode} mode)")
    print(f"[+] Found {len(findings)} CVE finding(s):\n")

    for f in findings:
        print(f"  [{f['severity'].upper()}] {f['name']}")
        print(f"  Host: {f['host']} ({f['hostname']}) — Port {f['port']}")
        print(f"  {f['description']}")
        print(f"  Fix: {f['remediation']}\n")

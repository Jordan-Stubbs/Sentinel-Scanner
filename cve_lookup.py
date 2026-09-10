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
# set to (config.DASHBOARD_PORT) — stays correct even if the port
# changes again in future, rather than needing a new hardcoded entry
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
    """
    desc_lower = description.lower()
    service_lower = service_name.lower()

    if service_lower not in desc_lower:
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

    return True

def parse_nvd_response(vulnerabilities, service_name, version, host, hostname, vendor, os_guess, product, port):
    """Parse NVD API response into findings format."""
    findings = []
    for vuln in vulnerabilities:
        try:
            cve    = vuln.get('cve', {})
            cve_id = cve.get('id', 'Unknown')

            descriptions = cve.get('descriptions', [])
            description  = next(
                (d['value'] for d in descriptions if d.get('lang') == 'en'),
                'No description available.'
            )

            if not is_relevant_cve(description, service_name, version):
                continue

            if len(description) > 250:
                description = description[:247] + '...'

            metrics  = cve.get('metrics', {})
            score    = 0.0
            severity = 'medium'

            for cvss_key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if cvss_key in metrics and metrics[cvss_key]:
                    cvss_data = metrics[cvss_key][0]
                    score     = float(cvss_data.get('cvssData', {}).get('baseScore', 0.0))
                    severity  = cvss_to_severity(score)
                    break

            if score < 4.0:
                continue

            published = cve.get('published', '')[:10]

            findings.append({
                'host':        host,
                'hostname':    hostname,
                'vendor':      vendor,
                'os':          os_guess,
                'product':     product,
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
    Query the local CVE cache. Matches on product-name terms
    (required). Version-number terms are a scoring bonus if they
    also appear in the description, but not a hard requirement.
    """
    if not os.path.exists(CVE_CACHE_PATH):
        return None
    try:
        with open(CVE_CACHE_PATH) as f:
            cache = json.load(f)

        terms = keyword.lower().split()
        name_terms    = [t for t in terms if not any(c.isdigit() for c in t)]
        version_terms = [t for t in terms if any(c.isdigit() for c in t)]

        if not name_terms:
            name_terms = terms
            version_terms = []

        scored_matches = []
        for cve_id, entry in cache.items():
            desc = entry.get('description', '').lower()

            if not all(term in desc for term in name_terms):
                continue

            version_hit = bool(version_terms) and any(term in desc for term in version_terms)
            scored_matches.append((version_hit, entry))

        scored_matches.sort(key=lambda pair: pair[0], reverse=True)

        matches = [entry for _, entry in scored_matches[:MAX_CVE_PER_SERVICE]]
        return matches
    except Exception:
        return None

def parse_offline_cache(matches, host, hostname, vendor, os_guess, product, port):
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
                'os':          os_guess,
                'product':     product,
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

# Services worth checking — mapped from nmap service category to a
# proper product name, used ONLY as a fallback when nmap couldn't
# identify a specific product for that port (see resolve_service_name
# below). Deliberately does NOT include 'http'/'https': too many
# different real-world products share these generic categories
# (Apache, nginx, a Flask/Werkzeug dev server, IIS, custom apps...)
# to safely guess one — guessing wrong here produces confidently
# wrong CVEs (this happened twice in practice: a Flask dashboard on
# two different ports both got matched against unrelated Apache
# SpamAssassin/Airflow CVEs). A lookup for http/https now only
# proceeds if nmap actually detected a specific product name.
SERVICES_OF_INTEREST = {
    'ssh':          'OpenSSH',
    'ftp':          'vsftpd',
    'telnet':       'telnet',
    'smtp':         'Postfix',
    'domain':       'BIND',
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

def resolve_service_name(service, product):
    """
    Decide what product name to search CVEs for, given nmap's generic
    service category and (if any) its specifically detected product.

    Priority:
    1. A real detected product name from nmap — trusted directly,
       regardless of category, since it's actual signal rather than
       a guess.
    2. SERVICES_OF_INTEREST's static fallback guess — only for
       categories judged reliable enough to guess safely even
       without a specific product (e.g. 'ssh' is overwhelmingly
       OpenSSH in practice).
    3. Otherwise: return None, meaning "don't guess — skip this
       port's CVE lookup entirely." This deliberately replaces the
       old behaviour of capitalising any unrecognised service name
       and searching for it blindly.

    Returns the product name to search for, or None if the lookup
    should be skipped.
    """
    service = (service or '').lower()
    product = (product or '').strip()

    # Explicit exclusions (e.g. tcpwrapped, iphone-sync) always skip,
    # even if nmap somehow reported a product string for them.
    if service in SERVICES_OF_INTEREST and SERVICES_OF_INTEREST[service] is None:
        return None

    if product:
        return product

    # Falls back to the static guess if this category has one, or
    # None (skip) if it doesn't — a single lookup covers both cases.
    return SERVICES_OF_INTEREST.get(service)

def run_cve_lookup(scan_results):
    """
    Main function — runs CVE lookup for all detected services.
    Only queries services where nmap detected a specific version
    string AND either a specific product name or a category judged
    reliable enough to guess safely (see resolve_service_name).
    Returns list of CVE findings and whether online mode was used.
    """
    all_cve_findings = []
    online_mode      = True
    services_checked = set()

    for host in scan_results:
        ip       = host.get('ip', '')
        hostname = host.get('hostname', '')
        vendor   = host.get('vendor', '')
        os_guess = host.get('os', 'Unknown')

        for proto, ports in host.get('protocols', {}).items():
            for port_num, port_info in ports.items():
                if str(port_num) in SKIP_PORTS:
                    continue

                service = port_info.get('service', '').lower()
                product = port_info.get('product', '')
                version = port_info.get('version', '').strip()

                clean_ver = clean_version(version)
                if not clean_ver:
                    print(f"  [CVE] Skipping {service} on port {port_num} — no version detected")
                    continue

                service_name = resolve_service_name(service, product)
                if service_name is None:
                    print(f"  [CVE] Skipping {service} on port {port_num} — no specific product detected, category too ambiguous to guess safely")
                    continue

                keyword = build_search_query(service_name, clean_ver)

                if keyword in services_checked:
                    continue
                services_checked.add(keyword)

                print(f"  [CVE] Checking: {keyword} (port {port_num})")

                vulns = query_nvd_online(keyword)

                if vulns is None:
                    online_mode = False
                    print(f"  [CVE] Offline mode — checking local cache for: {keyword}")
                    offline_matches = query_nvd_offline(keyword)
                    if offline_matches:
                        findings = parse_offline_cache(
                            offline_matches, ip, hostname, vendor, os_guess, product, port_num
                        )
                        all_cve_findings.extend(findings)
                elif vulns:
                    findings = parse_nvd_response(
                        vulns, service_name, clean_ver,
                        ip, hostname, vendor, os_guess, product, port_num
                    )
                    all_cve_findings.extend(findings)

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

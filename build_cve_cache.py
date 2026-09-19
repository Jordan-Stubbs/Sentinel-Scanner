"""
build_cve_cache.py

Builds (or refreshes) an offline CVE cache so that cve_lookup.py's
query_nvd_offline() fallback has real data to search when the Pi has
no internet access or NVD is unreachable.

Queries the NVD API once per recognised service (from
cve_lookup.SERVICES_OF_INTEREST) and writes the results to
cve_cache.json in the same format cve_lookup.py already expects:

    {
      "CVE-XXXX-XXXXX": {
        "id":          "CVE-XXXX-XXXXX",
        "cvss_score":  7.5,
        "description": "...",
        "published":   "YYYY-MM-DD"
      },
      ...
    }

USAGE (run manually, while the Pi has internet access):

    cd ~/scanner
    source venv/bin/activate
    python3 build_cve_cache.py

Takes a few minutes - NVD's public rate limit without an API key is
5 requests per 30 seconds, so this sleeps 7s between requests to stay
safely under that. Re-run periodically (e.g. every few weeks) to keep
the cache reasonably current before a demo or evaluation session.
"""

import json
import time
import os
import urllib.request
import urllib.parse
import urllib.error

from cve_lookup import SERVICES_OF_INTEREST, CVE_CACHE_PATH

RESULTS_PER_SERVICE = 50   # CVEs to fetch per service/product
REQUEST_DELAY        = 7   # seconds between requests, safely under NVD's 5/30s limit
MIN_CVSS_SCORE        = 4.0  # skip low-severity/noise CVEs, mirrors cve_lookup.py's own filter


def query_nvd(keyword, results_per_page=RESULTS_PER_SERVICE, retries=3):
    """Query the NVD API for a given keyword, with basic retry on failure."""
    encoded = urllib.parse.quote(keyword)
    url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch={encoded}&resultsPerPage={results_per_page}"
    )

    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'NetworkVulnerabilityScanner/1.0 (offline-cache-builder)',
                    'Accept':     'application/json'
                }
            )
            with urllib.request.urlopen(req, timeout=15) as response:
                data = json.loads(response.read().decode('utf-8'))
                return data.get('vulnerabilities', [])
        except urllib.error.URLError as e:
            print(f"    [!] Request failed ({e}) - retrying in 5s...")
            time.sleep(5)
        except Exception as e:
            print(f"    [!] Unexpected error ({e}) - retrying in 5s...")
            time.sleep(5)

    print(f"    [!] Giving up on '{keyword}' after {retries} attempts.")
    return []


def parse_entries(vulnerabilities):
    """Convert raw NVD API results into the cache entry format."""
    entries = {}
    for vuln in vulnerabilities:
        try:
            cve    = vuln.get('cve', {})
            cve_id = cve.get('id')
            if not cve_id:
                continue

            descriptions = cve.get('descriptions', [])
            description  = next(
                (d['value'] for d in descriptions if d.get('lang') == 'en'),
                'No description available.'
            )

            # Get CVSS score - try v3.1, v3.0, v2 in order, same priority as cve_lookup.py
            metrics = cve.get('metrics', {})
            score   = 0.0
            for cvss_key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if cvss_key in metrics and metrics[cvss_key]:
                    score = float(metrics[cvss_key][0].get('cvssData', {}).get('baseScore', 0.0))
                    break

            if score < MIN_CVSS_SCORE:
                continue

            if len(description) > 250:
                description = description[:247] + '...'

            published = cve.get('published', '')[:10]

            entries[cve_id] = {
                'id':          cve_id,
                'cvss_score':  score,
                'description': description,
                'published':   published,
            }
        except Exception:
            continue

    return entries


def build_cache():
    # Skip services mapped to None (e.g. tcpwrapped) - same list cve_lookup.py already uses
    products = sorted({p for p in SERVICES_OF_INTEREST.values() if p})
    print(f"[*] Building offline CVE cache for {len(products)} product(s)...")

    cache = {}
    if os.path.exists(CVE_CACHE_PATH):
        try:
            with open(CVE_CACHE_PATH) as f:
                cache = json.load(f)
            print(f"[*] Loaded {len(cache)} existing cache entries - will merge and update.")
        except Exception:
            print("[!] Existing cache file unreadable - starting fresh.")

    for i, product in enumerate(products, 1):
        print(f"  [{i}/{len(products)}] Querying: {product}")
        vulns       = query_nvd(product)
        new_entries = parse_entries(vulns)
        cache.update(new_entries)
        print(f"      -> {len(new_entries)} CVE(s) added/updated (CVSS >= {MIN_CVSS_SCORE})")
        time.sleep(REQUEST_DELAY)

    with open(CVE_CACHE_PATH, 'w') as f:
        json.dump(cache, f, indent=2)

    print(f"\n[+] Cache saved to {CVE_CACHE_PATH}")
    print(f"[+] Total CVEs cached: {len(cache)}")


if __name__ == "__main__":
    build_cache()

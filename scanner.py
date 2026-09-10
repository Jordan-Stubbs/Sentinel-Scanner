import nmap
import json
import subprocess
import config

# MAC vendor prefix lookup — first 8 chars of MAC (XX:XX:XX)
# Covers the most common home/SME device manufacturers
VENDOR_MAP = {
    'b8:27:eb': 'Raspberry Pi',
    'dc:a6:32': 'Raspberry Pi',
    'e4:5f:01': 'Raspberry Pi',
    'd8:3a:dd': 'Raspberry Pi',
    '00:50:56': 'VMware',
    '08:00:27': 'VirtualBox',
    'ac:84:c6': 'Apple',
    'a4:c3:f0': 'Apple',
    'f0:18:98': 'Apple',
    '00:17:f2': 'Apple',
    'bc:92:6b': 'Apple',
    'f4:db:e6': 'Apple',
    '18:65:90': 'Apple',
    'ac:bc:32': 'Apple',
    '00:1a:11': 'Google',
    '54:60:09': 'Google',
    'f4:f5:d8': 'Google',
    'fc:a1:83': 'Amazon / Fire Device',
    '40:b4:cd': 'Amazon / Fire Device',
    '74:75:48': 'Amazon / Fire Device',
    '00:bb:3a': 'Amazon / Fire Device',
    'a0:02:dc': 'Samsung',
    '8c:77:12': 'Samsung',
    'b4:3a:28': 'Samsung',
    '00:26:37': 'Samsung',
    '00:13:e0': 'Samsung',
    '00:1d:25': 'Samsung',
    '14:eb:b6': 'TP-Link',
    '50:c7:bf': 'TP-Link',
    'c4:e9:84': 'TP-Link',
    'b0:be:76': 'TP-Link',
    '10:fe:ed': 'TP-Link',
    '00:0f:e2': 'TP-Link',
    '90:9a:4a': 'Netgear',
    '00:14:6c': 'Netgear',
    'c0:3f:0e': 'Netgear',
    '20:e5:2a': 'Netgear',
    '00:26:f2': 'Netgear',
    '00:1e:2a': 'Netgear',
    '00:1f:33': 'Netgear',
    'c8:d7:19': 'Asus',
    '00:1a:92': 'Asus',
    'ac:22:0b': 'Asus',
    '10:78:d2': 'Asus',
    '2c:fd:a1': 'Asus',
    '04:92:26': 'Asus',
    '00:90:4c': 'Epson',
    '00:26:ab': 'Epson',
    '00:0c:29': 'VMware',
    '00:25:90': 'Dell',
    '18:03:73': 'Dell',
    'f8:db:88': 'Dell',
    'b8:ca:3a': 'Dell',
    '00:1a:4b': 'Dell',
    '00:24:e8': 'Dell',
    '00:22:19': 'Dell',
    '8c:ec:4b': 'Lenovo',
    '00:21:cc': 'Lenovo',
    '28:d2:44': 'Lenovo',
    'f8:16:54': 'Lenovo',
    '54:ee:75': 'Lenovo',
    '00:21:5e': 'Lenovo',
    'ac:61:ea': 'FRITZ!Box / AVM',
    '00:04:0e': 'FRITZ!Box / AVM',
    'c4:86:e9': 'FRITZ!Box / AVM',
    '3c:a6:2f': 'FRITZ!Box / AVM',
    'd0:76:8f': 'FRITZ!Box / AVM',
    'e0:28:6d': 'FRITZ!Box / AVM',
}

def get_vendor(mac):
    if not mac or mac == 'Unknown':
        return 'Unknown'
    prefix = mac.lower()[:8]
    return VENDOR_MAP.get(prefix, 'Unknown')

def scan_network(target):
    scanner = nmap.PortScanner()
    print(f"[*] Scanning {target}...")

    # -sV = service version, -O = OS detection, --open = open ports only
    scanner.scan(hosts=target, arguments='-sV -O --open')

    results = []
    for host in scanner.all_hosts():
        mac = 'Unknown'
        vendor = 'Unknown'
        try:
            addresses = scanner[host].get('addresses', {})
            mac = addresses.get('mac', 'Unknown')
            if mac and mac != 'Unknown':
                vendor = get_vendor(mac)
                if vendor == 'Unknown':
                    vendor = scanner[host].get('vendor', {}).get(mac, 'Unknown')
        except Exception:
            pass

        os_match = 'Unknown'
        try:
            os_matches = scanner[host].get('osmatch', [])
            if os_matches:
                os_match = os_matches[0].get('name', 'Unknown')
        except Exception:
            pass

        host_data = {
            'ip':       host,
            'hostname': scanner[host].hostname(),
            'state':    scanner[host].state(),
            'mac':      mac,
            'vendor':   vendor,
            'os':       os_match,
            'protocols': {}
        }

        for proto in scanner[host].all_protocols():
            host_data['protocols'][proto] = {}
            for port in scanner[host][proto].keys():
                port_info = scanner[host][proto][port]
                host_data['protocols'][proto][port] = {
                    'state':   port_info['state'],
                    'service': port_info['name'],
                    # nmap's specific detected product (e.g. "Werkzeug
                    # httpd", "Apache httpd", "nginx") — previously
                    # discarded here, which meant cve_lookup.py had no
                    # way to tell a generic "http" category apart from
                    # a specific real product, and had to fall back to
                    # a static guess (always "Apache") that produced
                    # confidently-wrong CVEs for anything else running
                    # on a web port.
                    'product': port_info.get('product', ''),
                    'version': port_info['version']
                }

        results.append(host_data)

    return results

if __name__ == "__main__":
    ip_output = subprocess.check_output(['hostname', '-I']).decode().strip()
    local_ip  = ip_output.split()[0]
    network   = '.'.join(local_ip.split('.')[:3]) + '.0/24'

    print(f"[*] Local IP: {local_ip}")
    print(f"[*] Scanning network: {network}")

    results = scan_network(network)

    print(f"\n[+] Found {len(results)} hosts\n")
    for host in results:
        vendor_str = f" | {host['vendor']}" if host['vendor'] != 'Unknown' else ''
        mac_str    = f" | MAC: {host['mac']}" if host['mac'] != 'Unknown' else ''
        print(f"Host: {host['ip']} ({host['hostname']}){vendor_str}{mac_str}")
        if host['os'] != 'Unknown':
            print(f"  OS: {host['os']}")
        for proto, ports in host['protocols'].items():
            for port, info in ports.items():
                print(f"  {port}/{proto} - {info['service']} {info['version']} [{info['state']}]")
        print()

    total_ports = sum(
        len(ports)
        for host in results
        for ports in host['protocols'].values()
    )

    with open(config.SCAN_RESULTS_PATH, 'w') as f:
        json.dump({
            'meta': {
                'local_ip':    local_ip,
                'network':     network,
                'total_hosts': len(results),
                'total_ports': total_ports,
            },
            'hosts': results
        }, f, indent=2)

    print(f"[+] Results saved to scan_results.json")
    print(f"[+] {len(results)} hosts | {total_ports} open ports")

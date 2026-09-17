# Portable Network Vulnerability Scanner

A self-contained network vulnerability assessment tool built for the
Raspberry Pi 4 (also works on other Debian-based Linux machines with
enough RAM). Scans your local network, cross-references findings
against known CVEs, and generates a plain-English AI security report
— all fully offline-capable, using a local LLM (Phi-3 Mini via
Ollama) rather than sending anything to the cloud.

## Features

- **Network scanning** — `nmap`-based scan of the local subnet:
  hosts, open ports, service/product detection, OS fingerprinting,
  and MAC vendor lookup
- **40 vulnerability rules** spanning remote access, databases, file
  sharing, industrial/IoT, smart-home, and self-hosted media services,
  contributing to an overall 0–100 security score — see the
  dashboard's own "Vulnerability Checks" page for the full,
  always-current list, produced from the same rules the scanner
  actually runs
- **CVE cross-referencing** against the National Vulnerability
  Database, with an offline cache fallback for when there's no
  internet — matched against the specific product `nmap` actually
  detects, not a generic guess
- **AI-generated security report** (Phi-3 Mini, fully local/offline),
  with an optional toggle to skip it for a faster, lighter scan
- **Device fingerprinting** surfaced throughout — OS guess and
  detected product shown on every finding, plus a full "Discovered
  Hosts" inventory of every device found, regardless of whether it
  has any findings
- **Scan history** with score/severity trend charts and side-by-side
  diff comparison between any two past scans
- **Traffic Monitor** — an on-demand, fixed-duration packet capture
  that watches for port-scan and network-sweep reconnaissance
  patterns, correlated against known findings from your last scan
  (see below)
- **Exports** — PDF, CSV, and JSON, all including full findings,
  device data, and the discovered-hosts inventory
- **Dashboard** protected with HTTP Basic Auth, with live CPU/RAM/
  temperature/uptime monitoring

## Requirements

- A Debian-based Linux machine (Raspberry Pi OS, Ubuntu, Debian) with
  internet access for the initial install
- At least 4GB RAM recommended (built and tested on a Pi 4 with 8GB)
- `sudo` access
- Python 3

## Install

```bash
chmod +x install.sh
./install.sh
```

The installer will:
- Install `nmap` and Ollama if they're not already present
- Pull the `phi3:mini` model
- Set up a Python virtual environment
- Configure the minimum sudo permissions needed (nmap requires root
  for OS detection, and the traffic monitor requires it for raw
  packet capture)
- Ask you to set a username/password for the dashboard, and which
  port it should run on (defaults to 5000)
- Set up two background services: the dashboard itself, and a
  preload service that keeps the AI model resident in RAM so scans
  don't have a cold-start delay

It's safe to re-run at any point — every file it generates is
rebuilt fresh each time, not appended to.

## After installing

Open `http://<this-machine's-IP>:<port>` in a browser and log in with
the credentials you set during install. Click "Run New Scan" to
start your first scan.

## Traffic Monitor

Separate from the vulnerability scan pipeline, Traffic Monitor is an
on-demand packet capture (30/60/120s) that watches for two
reconnaissance patterns:

- **Port scans** — a device opening new TCP connections to an
  unusually high number of ports on this machine
- **Network sweeps** — a device sending ARP requests for an unusually
  high number of addresses on the subnet (the same pattern this
  tool's own network scan produces)

It's mutually exclusive with the vulnerability scanner (only one can
run at a time), and any flagged device is checked against your most
recent scan's findings, so a flag can tell you "this device also has
3 known finding(s)" rather than being an isolated data point.

**Honest limitation:** on a typical switched network, this machine
only ever sees traffic addressed to itself, plus broadcast traffic
like ARP requests — it cannot see a scan directed at a different
device elsewhere on the network. That would require a mirrored
switch port, which most home and small-office networks don't have.

## Running the test suite

```bash
source venv/bin/activate
python3 -m unittest discover -s tests -v
```

## Optional: offline CVE cache

The installer offers to build this automatically, but you can also
run it manually any time (needs internet):

```bash
source venv/bin/activate
python3 build_cve_cache.py
```

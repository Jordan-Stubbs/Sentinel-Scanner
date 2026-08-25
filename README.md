# Portable Network Vulnerability Scanner

A self-contained network vulnerability assessment tool built for the
Raspberry Pi 4 (also works on other Debian-based Linux machines with
enough RAM). Scans your local network, cross-references findings
against known CVEs, and generates a plain-English AI security report
— all fully offline-capable, using a local LLM (Phi-3 Mini via
Ollama) rather than sending anything to the cloud.

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
  for OS detection)
- Ask you to set a username/password for the dashboard
- Set up two background services: the dashboard itself, and a
  preload service that keeps the AI model resident in RAM so scans
  don't have a cold-start delay

It's safe to re-run at any point — every file it generates is
rebuilt fresh each time, not appended to.

## After installing

Open `http://<this-machine's-IP>:5000` in a browser and log in with
the credentials you set during install. Click "Run New Scan" to
start your first scan.

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

#!/bin/bash
# preload_ollama.sh
#
# Waits for the Ollama service to come up, then sends an empty-prompt
# request with keep_alive=-1 so Phi-3 Mini is loaded into RAM
# immediately at boot and stays resident permanently - matching the
# keep_alive=-1 behaviour already used in llm_reporter.py's own
# query_ollama() calls at scan time.
#
# Installed and run automatically by ollama-preload.service.

# Wait for Ollama's API to be reachable (up to ~60s)
for i in $(seq 1 60); do
    if curl -s -o /dev/null http://localhost:11434; then
        break
    fi
    sleep 1
done

curl -s -X POST http://localhost:11434/api/generate \
    -H "Content-Type: application/json" \
    -d '{"model": "phi3:mini", "prompt": "", "stream": false, "keep_alive": -1}' \
    > /dev/null

echo "[+] Phi-3 Mini preload request sent to Ollama."

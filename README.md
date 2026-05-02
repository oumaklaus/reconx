# ReconX

```
	____                      _  __
   / __ \___  _________  ____| |/ /
  / /_/ / _ \/ ___/ __ \/ __ \   /
 / _, _/  __/ /__/ /_/ / / / /  |
/_/ |_|\___/\___/\____/_/ /_/_/|_|
```

An active reconnaissance and attack surface management tool. Point it at a target — it handles the rest.

> **For authorized use only.** Only scan targets you own or have explicit permission to test.

Built for personal use on Hack The Box labs, now open-sourced for others who want a streamlined recon workflow.

Contributions are welcome from anyone.

## Usage

```bash
# Full recon — nmap + httpx + ffuf + nuclei + analysis
reconx target.htb

# Quick — port scan only
reconx target.htb --quick

# Web-focused — ports + HTTP probe + dir enum + vuln scan
reconx target.htb --web

# Domain target
reconx target.htb --mode full

# Custom output directory
reconx target.htb --output-dir ./reconx-output

# Legacy: ingest existing scan files
reconx ingest nmap.xml httpx.jsonl nuclei.jsonl --profile deep
```

That's it. No long setup commands. No feeding files manually.

## What Happens When You Run It

```
reconx target.htb
```

1. **Checks dependencies** — nmap, httpx, ffuf, nuclei, seclists. Installs anything missing.
2. **Phase 1: Port Scan** — full nmap with service detection, OS fingerprinting
3. **Phase 2: HTTP Probe** — httpx against discovered web ports, tech stack detection
4. **Phase 3: Dir Enum** — ffuf with seclists against each web port
5. **Phase 4: Vuln Scan** — nuclei against all discovered endpoints
6. **Phase 5: Analysis** — correlates everything into an asset graph, enriches with CVE data, scores findings
7. **Reports** — Rich TUI with severity-colored findings, saves full results to workspace

## Install

```bash
cd ~/reconx
# Run directly (Kali/Parrot — tools pre-installed):
PYTHONPATH=. python3 -m reconx target.htb

# Or add alias to .zshrc:
echo 'alias reconx="PYTHONPATH=~/reconx python3 -m reconx"' >> ~/.zshrc
source ~/.zshrc
reconx target.htb
```

## Architecture

```
reconx/
├── runners/                 # Tool execution
│   ├── deps.py              # Auto-detect & install nmap/httpx/ffuf/nuclei/seclists
│   ├── base.py              # Abstract runner framework
│   ├── nmap_runner.py       # Nmap execution (quick/full/stealth modes)
│   ├── httpx_runner.py      # HTTP probing with tech detection
│   ├── ffuf_runner.py       # Directory enumeration with seclists
│   └── nuclei_runner.py     # Vulnerability scanning
├── recon/                   # Recon orchestration
│   ├── target.py            # Target parsing (IP/domain/CIDR)
│   └── pipeline.py          # Phase-based recon flow
├── core/                    # Analysis engine
│   ├── assets.py            # Typed asset graph (Host/Port/Service/Endpoint/Finding)
│   ├── evidence.py          # Provenance tracking
│   ├── dedup.py             # Identity-based deduplication
│   ├── correlation.py       # CVE matching + endpoint pattern detection
│   ├── orchestrator.py      # Ingestion pipeline
│   └── storage.py           # SQLite persistence
├── enrichment/              # CVE intelligence
│   ├── cpe_generator.py     # CPE 2.3 candidate generation
│   └── cve_enrichment.py    # CVE enrichment pipeline
├── adapters/                # Scanner output parsers
├── cli/                     # CLI entrypoint
├── ui/                      # Rich TUI rendering
├── config/                  # Settings (YAML/env vars)
└── tests/                   # 60 unit + integration tests
```

## Scan Modes

| Mode | What it does | Use when |
|---|---|---|
| `--quick` | nmap top-1000 ports only | Initial recon, fast triage |
| `--web` | nmap + httpx + ffuf + nuclei | Web app targets |
| `--full` | Everything, all ports, deep scan | Full engagement (default) |

## Tests

```bash
PYTHONPATH=. python3 -m pytest tests/ -xvs
```

## License

MIT. See LICENSE.
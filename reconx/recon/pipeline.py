"""Phase-based recon pipeline with live terminal output.

Intelligent tool chaining:
  1. Nmap → extracts domains from redirects/certs
  2. If domain found → vhost/subdomain enum with ffuf
  3. Service-specific tools based on discovered ports
  4. Dir enum + vuln scan on web ports
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reconx.recon.target import Target
from reconx.runners.base import RunResult
from reconx.runners.deps import check_tool

logger = logging.getLogger(__name__)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

SSL_PORTS = {443, 8443, 993, 995, 465}
SMB_PORTS = {139, 445}


@dataclass
class ReconResult:
    target: Target
    workspace: Path
    output_files: list[Path] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    web_ports: list[int] = field(default_factory=list)
    ssl_ports: list[int] = field(default_factory=list)
    smb_ports: list[int] = field(default_factory=list)
    web_urls: list[str] = field(default_factory=list)
    discovered_domains: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    has_waf: bool = False
    waf_name: str | None = None
    is_wordpress: bool = False
    total_duration: float = 0.0


class ReconPipeline:
    def __init__(self, target: Target, workspace: Path, *, mode: str = "full", console: Any = None):
        self.target = target
        self.workspace = workspace
        workspace.mkdir(parents=True, exist_ok=True)
        self.mode = mode
        self.c = console or (Console() if HAS_RICH else None)

    def run(self) -> ReconResult:
        r = ReconResult(target=self.target, workspace=self.workspace)
        start = time.monotonic()
        self._banner()

        # Passive recon for domain targets
        if self.target.kind == "domain" and self.mode != "quick":
            self._phase_passive(r)

        # Port scan (always)
        self._phase_portscan(r)

        if self.mode == "quick":
            r.total_duration = time.monotonic() - start
            return r

        # Subdomain/vhost enum if we found a domain
        if r.discovered_domains and self.mode != "quick":
            self._phase_vhost_enum(r)

        # Service enum on web ports
        if r.web_ports:
            self._phase_service_enum(r)
            self._phase_dir_enum(r)

        # SMB enum
        if r.smb_ports and self._has("enum4linux"):
            self._phase_smb_enum(r)

        # Vuln scan
        self._phase_vuln(r)

        r.total_duration = time.monotonic() - start
        return r

    # ── Phase: Passive Recon ──────────────────────────────────────────────

    def _phase_passive(self, r: ReconResult):
        domain = self.target.domain or self.target.value
        if self._has("subfinder"):
            self._header("SUBFINDER", f"Subdomain Enumeration — {domain}")
            from reconx.runners.subfinder_runner import SubfinderRunner
            runner = SubfinderRunner(self.workspace)
            run = runner.run_live(domain, timeout=120, console=self.c,
                line_filter=lambda l: f"    [green]→[/] [bold]{l.strip()}[/]" if l.strip() else None)
            if run.output_path:
                r.subdomains = [l.strip() for l in run.output_path.read_text().splitlines() if l.strip()]
                r.output_files.append(run.output_path)
            self._done(run, f"{len(r.subdomains)} subdomain(s) found")

    # ── Phase: Port Scan ──────────────────────────────────────────────────

    def _phase_portscan(self, r: ReconResult):
        self._header("NMAP", f"Scanning {self.target.value}")
        from reconx.runners.nmap_runner import NmapRunner
        runner = NmapRunner(self.workspace)
        nmap_mode = "quick" if self.mode == "quick" else "full"

        def filt(line):
            l = line.strip()
            if not l:
                return None
            if "/tcp" in l or "/udp" in l:
                return f"    [bold green]{l}[/]"
            if l.startswith("PORT") or l.startswith("SERVICE"):
                return f"    [bold cyan]{l}[/]"
            if "OS details:" in l or "Running:" in l:
                return f"    [bold yellow]{l}[/]"
            if l.startswith("|"):
                return f"    [dim cyan]{l}[/]"
            if l.startswith("Nmap scan report") or l.startswith("Nmap done"):
                return f"    [dim]{l}[/]"
            if "redirect" in l.lower():
                return f"    [bold magenta]{l}[/]"
            if "WARNING" in l or "Note:" in l or l.startswith("Starting"):
                return None
            return f"    [dim]{l}[/]"

        run = runner.run_live(self.target.value, timeout=900, console=self.c,
                               line_filter=filt, mode=nmap_mode)
        if run.success and run.output_path:
            r.output_files.append(run.output_path)
            ports = self._parse_nmap_ports(run.output_path)
            r.open_ports = ports["all"]
            r.web_ports = ports["web"]
            r.ssl_ports = ports["ssl"]
            r.smb_ports = ports["smb"]
            r.web_urls = self._ports_to_urls(self.target.value, r.web_ports)

            # Extract domains from nmap (redirects, certs, hostnames)
            domains = self._extract_domains_from_nmap(run.output_path)
            r.discovered_domains = domains
            if domains and self.c and HAS_RICH:
                self.c.print(f"    [bold magenta]Domains found: {', '.join(domains)}[/]")

        self._done(run, f"{len(r.open_ports)} open ports | web: {r.web_ports}")

    # ── Phase: VHost/Subdomain Enum ───────────────────────────────────────

    def _phase_vhost_enum(self, r: ReconResult):
        from reconx.runners.ffuf_runner import FfufRunner
        runner = FfufRunner(self.workspace)

        for domain in r.discovered_domains:
            self._header("FFUF", f"VHost/Subdomain Enum — *.{domain}")
            cmd = runner.build_vhost_command(self.target.value, domain)
            safe = re.sub(r"[^a-zA-Z0-9._\-]", "_", domain)
            out = self.workspace / f"ffuf_vhost_{safe}.json"

            run = self._run_live(cmd, out, "ffuf", 300,
                line_filter=self._ffuf_result_filter)

            if run.output_path:
                r.output_files.append(run.output_path)
                subs = self._parse_ffuf_results(run.output_path)
                for sub in subs:
                    full = f"{sub}.{domain}"
                    if full not in r.subdomains:
                        r.subdomains.append(full)

            # Show found subdomains clearly
            if r.subdomains and self.c and HAS_RICH:
                self.c.print(f"\n  [bold green]Found subdomains:[/]")
                for s in r.subdomains:
                    self.c.print(f"    [bold cyan]• {s}[/]")
            self._done(run, f"{len(r.subdomains)} subdomain(s)")

    # ── Phase: Service Enum ───────────────────────────────────────────────

    def _phase_service_enum(self, r: ReconResult):
        # WAF
        if r.web_urls and self._has("wafw00f"):
            url = r.web_urls[0]
            self._header("WAFW00F", "WAF Detection")
            from reconx.runners.wafw00f_runner import Wafw00fRunner
            runner = Wafw00fRunner(self.workspace)

            def waf_filt(l):
                l = l.strip()
                if not l:
                    return None
                if "no waf" in l.lower() or "no firewall" in l.lower():
                    return f"    [bold green]✓ No WAF detected[/]"
                if "is behind" in l.lower():
                    return f"    [bold red]⚠ {l}[/]"
                if l.startswith("[*]"):
                    return f"    [dim]{l}[/]"
                return None

            run = runner.run_live(url, timeout=60, console=self.c, line_filter=waf_filt)
            if run.output_path:
                r.output_files.append(run.output_path)
                r.has_waf, r.waf_name = self._parse_waf(run.output_path)
            self._done(run, f"[red]WAF: {r.waf_name}[/]" if r.has_waf else "[green]No WAF[/]")

        # WhatWeb
        if r.web_urls and self._has("whatweb"):
            self._header("WHATWEB", "Technology Fingerprinting")
            from reconx.runners.whatweb_runner import WhatwebRunner
            runner = WhatwebRunner(self.workspace)
            run = runner.run_live(r.web_urls[0], timeout=120, console=self.c,
                line_filter=lambda l: f"    [cyan]{l.strip()}[/]" if l.strip() and "ERROR" not in l else None)
            if run.output_path:
                r.output_files.append(run.output_path)
                r.technologies = self._parse_whatweb(run.output_path)
                r.is_wordpress = any("wordpress" in t.lower() for t in r.technologies)
            if r.technologies and self.c and HAS_RICH:
                self.c.print(f"\n  [bold green]Technologies detected:[/]")
                for t in r.technologies:
                    color = "bold red" if "wordpress" in t.lower() else "cyan"
                    self.c.print(f"    [{color}]• {t}[/]")
            self._done(run, f"{len(r.technologies)} tech(s)")

        # httpx (only if Go version is available)
        from reconx.runners.httpx_runner import HttpxRunner
        runner = HttpxRunner(self.workspace)
        if runner.available:
            self._header("HTTPX", "HTTP Probing")
            stdin_data = runner.get_stdin_urls(self.target.value, r.web_ports)

            def httpx_filt(line):
                if not line.strip():
                    return None
                try:
                    d = json.loads(line)
                    code = d.get("status_code", "?")
                    url = d.get("url", "?")
                    title = d.get("title", "")
                    techs = ", ".join(d.get("tech", []))
                    c = "green" if 200 <= int(code) < 300 else "yellow" if int(code) < 400 else "red"
                    parts = f"[{c}][{code}][/] [bold]{url}[/]"
                    if title:
                        parts += f"  {title}"
                    if techs:
                        parts += f"  [cyan]{techs}[/]"
                    return f"    {parts}"
                except Exception:
                    if line.strip():
                        return f"    [dim]{line.strip()}[/]"
                    return None

            run = runner.run_live(self.target.value, timeout=120, console=self.c,
                                   line_filter=httpx_filt, stdin_data=stdin_data, ports=r.web_ports)
            if run.output_path:
                r.output_files.append(run.output_path)
            self._done(run, f"{run.stdout_lines} endpoint(s)")
        else:
            if self.c and HAS_RICH:
                self.c.print("\n  [yellow]⚠ httpx-toolkit not installed (apt install httpx-toolkit) — skipping HTTP probe[/]")

        # SSL
        if r.ssl_ports and self._has("sslscan"):
            for port in r.ssl_ports[:2]:
                self._header("SSLSCAN", f"SSL/TLS (port {port})")
                from reconx.runners.sslscan_runner import SslscanRunner
                sr = SslscanRunner(self.workspace)
                run = sr.run_live(self.target.value, timeout=60, console=self.c,
                    line_filter=lambda l: f"    [red]{l.strip()}[/]" if "vulnerable" in l.lower() or "weak" in l.lower()
                        else f"    [green]{l.strip()}[/]" if "accepted" in l.lower()
                        else f"    [dim]{l.strip()}[/]" if l.strip() else None,
                    port=port)
                if run.output_path:
                    r.output_files.append(run.output_path)
                self._done(run, f"Port {port}")

    # ── Phase: SMB Enum ───────────────────────────────────────────────────

    def _phase_smb_enum(self, r: ReconResult):
        self._header("ENUM4LINUX", "SMB Enumeration")
        from reconx.runners.enum4linux_runner import Enum4linuxRunner
        runner = Enum4linuxRunner(self.workspace)
        run = runner.run_live(self.target.value, timeout=300, console=self.c,
            line_filter=lambda l: f"    [bold yellow]{l}[/]" if l.startswith("[+]")
                else f"    [red]{l}[/]" if l.startswith("[-]")
                else f"    [dim]{l}[/]" if l.strip() and not l.startswith("[*]") else None)
        if run.output_path:
            r.output_files.append(run.output_path)
        self._done(run, "SMB enum complete")

    # ── Phase: Dir Enum ───────────────────────────────────────────────────

    def _phase_dir_enum(self, r: ReconResult):
        from reconx.runners.ffuf_runner import FfufRunner
        runner = FfufRunner(self.workspace)

        for port in r.web_ports:
            scheme = "https" if port in SSL_PORTS else "http"
            base = f"{scheme}://{self.target.value}" if port in (80, 443) else f"{scheme}://{self.target.value}:{port}"

            # If we found a domain, use it instead of IP
            if r.discovered_domains:
                domain = r.discovered_domains[0]
                base = f"{scheme}://{domain}" if port in (80, 443) else f"{scheme}://{domain}:{port}"

            self._header("FFUF", f"Directory Enum → {base}")
            run = runner.run_live(self.target.value, timeout=300, console=self.c,
                line_filter=self._ffuf_result_filter,
                url=f"{base}/FUZZ", port=port)
            if run.output_path:
                r.output_files.append(run.output_path)
                # Show found directories clearly
                dirs = self._parse_ffuf_results(run.output_path)
                if dirs and self.c and HAS_RICH:
                    self.c.print(f"\n  [bold green]Found directories:[/]")
                    for d in dirs:
                        self.c.print(f"    [bold cyan]• {base}/{d}[/]")
            self._done(run, f"Port {port}")

    # ── Phase: Vuln Assessment ────────────────────────────────────────────

    def _phase_vuln(self, r: ReconResult):
        self._header("NUCLEI", "Vulnerability Scanning")
        from reconx.runners.nuclei_runner import NucleiRunner
        runner = NucleiRunner(self.workspace)
        targets = r.web_urls + [self.target.value]
        cmd = runner.build_command_with_urls(targets, self.target.value) if r.web_urls else runner.build_command(self.target.value)
        out = runner.output_file(self.target.value)

        def nuc_filt(l):
            l = l.strip()
            if not l:
                return None
            if "[critical]" in l.lower():
                return f"    [bold red]🔴 {l}[/]"
            if "[high]" in l.lower():
                return f"    [bold red]🟠 {l}[/]"
            if "[medium]" in l.lower():
                return f"    [bold yellow]🟡 {l}[/]"
            if "[low]" in l.lower():
                return f"    [cyan]🔵 {l}[/]"
            if "[info]" in l.lower():
                return f"    [dim]ℹ  {l}[/]"
            return None

        run = self._run_live(cmd, out, "nuclei", 600, line_filter=nuc_filt)
        if run.output_path:
            r.output_files.append(run.output_path)
            findings = self._parse_nuclei_findings(run.output_path)
            if findings and self.c and HAS_RICH:
                self.c.print(f"\n  [bold green]Nuclei findings:[/]")
                for f in findings:
                    sev = f.get('severity', 'info')
                    color = {'critical':'bold red','high':'red','medium':'yellow','low':'cyan'}.get(sev, 'dim')
                    self.c.print(f"    [{color}]• [{sev.upper()}] {f.get('name','')} → {f.get('host','')}[/]")
        self._done(run, f"{run.stdout_lines} finding(s)")

        # Nikto
        if r.web_ports and self._has("nikto"):
            port = r.web_ports[0]
            self._header("NIKTO", f"Web Vuln Scan (port {port})")
            from reconx.runners.nikto_runner import NiktoRunner
            runner = NiktoRunner(self.workspace)

            def nikto_filt(l):
                l = l.strip()
                if not l or l.startswith("-"):
                    return None
                if l.startswith("+"):
                    if "OSVDB" in l or "vulnerability" in l.lower():
                        return f"    [bold red]{l}[/]"
                    return f"    [yellow]{l}[/]"
                return None

            run = runner.run_live(self.target.value, timeout=120, console=self.c,
                                  line_filter=nikto_filt, port=port)
            if run.output_path:
                r.output_files.append(run.output_path)
                items = self._parse_nikto_findings(run.output_path)
                if items and self.c and HAS_RICH:
                    self.c.print(f"\n  [bold green]Nikto findings:[/]")
                    for item in items:
                        self.c.print(f"    [yellow]• {item}[/]")
            self._done(run, f"Port {port}")

        # WPScan
        if r.is_wordpress and self._has("wpscan"):
            url = r.web_urls[0] if r.web_urls else f"http://{self.target.value}"
            self._header("WPSCAN", "WordPress Scan")
            from reconx.runners.wpscan_runner import WpscanRunner
            runner = WpscanRunner(self.workspace)
            run = runner.run_live(self.target.value, timeout=300, console=self.c,
                line_filter=lambda l: f"    [bold red]{l}[/]" if "VULNERABLE" in l
                    else f"    [yellow]{l}[/]" if l.startswith("[+]") or l.startswith("[!]")
                    else None,
                url=url)
            if run.output_path:
                r.output_files.append(run.output_path)
            self._done(run, "WordPress scan")

    # ── Helpers ───────────────────────────────────────────────────────────

    def _has(self, name: str) -> bool:
        return check_tool(name).installed

    @staticmethod
    def _strip_ansi(text: str) -> str:
        """Remove ANSI escape codes from text."""
        return re.sub(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\[\?[0-9;]*[a-zA-Z]', '', text)

    def _ffuf_result_filter(self, line: str):
        """Only show actual ffuf findings, skip all noise."""
        l = self._strip_ansi(line).strip()
        if not l:
            return None
        # Skip ffuf banner, progress, config lines
        if any(x in l for x in [":: ", "________________________________________________",
               "FUZZ", "v2.", "v1.", ":: Progress"]):
            return None
        # Result lines have [Status: XXX,
        if "[Status:" in l:
            # Extract the name and status for clean display
            parts = l.split("[Status:", 1)
            name = parts[0].strip()
            status = "[Status:" + parts[1] if len(parts) > 1 else ""
            return f"    [bold green]→[/] [bold]{name}[/]  [dim]{status}[/]"
        return None

    def _run_live(self, cmd, out: Path, tool: str, timeout: int, **kw) -> RunResult:
        line_filter = kw.get("line_filter")
        start = time.monotonic()
        lines = 0
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, cwd=str(self.workspace))
            if proc.stdout:
                for line in proc.stdout:
                    lines += 1
                    if line_filter:
                        d = line_filter(line.rstrip("\n"))
                        if d and self.c and HAS_RICH:
                            self.c.print(d)
            proc.wait(timeout=timeout)
            dur = time.monotonic() - start
            success = proc.returncode == 0
            return RunResult(
                tool=tool,
                success=success,
                output_path=out if out.exists() and out.stat().st_size > 0 else None,
                duration=dur,
                return_code=proc.returncode,
                stdout_lines=lines,
                error=None if success else f"Exit code {proc.returncode}",
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            return RunResult(tool=tool, success=False, output_path=None,
                duration=time.monotonic()-start, return_code=-1, error="Timeout")
        except FileNotFoundError:
            return RunResult(tool=tool, success=False, output_path=None,
                duration=0, return_code=-1, error="Not found")

    def _parse_nmap_ports(self, xml: Path) -> dict:
        ports: dict[str, list[int]] = {"all": [], "web": [], "ssl": [], "smb": []}
        try:
            tree = ET.parse(xml)
            for p in tree.iter("port"):
                state = p.find("state")
                if state is None or state.get("state") != "open":
                    continue
                pid = int(p.get("portid", 0))
                svc = (p.find("service").get("name", "") if p.find("service") is not None else "")
                ports["all"].append(pid)
                if any(k in svc.lower() for k in ("http", "https", "www")) or pid in (80,443,8080,8443,8000,8888,3000,5000,9090):
                    ports["web"].append(pid)
                if pid in SSL_PORTS or "ssl" in svc or "https" in svc:
                    ports["ssl"].append(pid)
                if pid in SMB_PORTS or "smb" in svc or "microsoft-ds" in svc:
                    ports["smb"].append(pid)
        except Exception as e:
            logger.warning("Nmap parse: %s", e)
        return {k: sorted(set(v)) for k, v in ports.items()}

    def _extract_domains_from_nmap(self, xml: Path) -> list[str]:
        """Extract domain names from nmap output (redirects, hostnames, certs)."""
        domains = set()
        try:
            raw = xml.read_text()
            # Redirect targets: "redirect to http://example.htb/"
            for m in re.finditer(r'redirect to https?://([a-zA-Z0-9._-]+\.htb)', raw, re.I):
                domains.add(m.group(1).lower())
            for m in re.finditer(r'redirect to https?://([a-zA-Z0-9._-]+\.[a-z]{2,})', raw, re.I):
                d = m.group(1).lower()
                if not d.replace(".", "").isdigit():  # Skip IPs
                    domains.add(d)
            # Hostnames from nmap XML
            tree = ET.parse(xml)
            for hn in tree.iter("hostname"):
                name = hn.get("name", "").lower()
                if name and not name.replace(".", "").isdigit():
                    domains.add(name)
            # SSL cert commonName / altNames
            for script in tree.iter("script"):
                if script.get("id") in ("ssl-cert", "http-title"):
                    output = script.get("output", "")
                    for m in re.finditer(r'commonName=([a-zA-Z0-9._-]+\.[a-z]{2,})', output):
                        domains.add(m.group(1).lower())
        except Exception:
            pass
        # Remove the target IP itself
        domains.discard(self.target.value)
        return sorted(domains)

    def _parse_ffuf_results(self, path: Path) -> list[str]:
        """Extract found entries from ffuf JSON output."""
        results = []
        try:
            data = json.loads(path.read_text())
            for r in data.get("results", []):
                inp = r.get("input", {}).get("FUZZ", "")
                if inp:
                    results.append(inp)
        except Exception:
            pass
        return results

    def _ports_to_urls(self, target: str, ports: list[int]) -> list[str]:
        urls = []
        for p in ports:
            s = "https" if p in SSL_PORTS else "http"
            urls.append(f"{s}://{target}" if p in (80,443) else f"{s}://{target}:{p}")
        return urls

    def _parse_waf(self, path: Path) -> tuple[bool, str | None]:
        try:
            data = json.loads(path.read_text())
            for e in (data if isinstance(data, list) else [data]):
                if e.get("firewall"):
                    return True, e["firewall"]
        except Exception:
            pass
        return False, None

    def _parse_whatweb(self, path: Path) -> list[str]:
        techs = set()
        try:
            data = json.loads(path.read_text())
            for e in (data if isinstance(data, list) else [data]):
                for n in e.get("plugins", {}):
                    if n not in ("IP", "Country", "HTTPServer", "UncommonHeaders"):
                        techs.add(n)
        except Exception:
            pass
        return sorted(techs)

    # ── Output ────────────────────────────────────────────────────────────

    def _banner(self):
        if self.c and HAS_RICH:
            g = Table.grid(padding=(0, 2))
            g.add_column(style="bold cyan"); g.add_column()
            g.add_row("Target", self.target.value)
            g.add_row("Type", self.target.kind)
            g.add_row("Mode", self.mode)
            self.c.print(Panel(g, title="[bold green]⚡ ReconX", border_style="green", padding=(1, 2)))

    def _header(self, tool: str, desc: str):
        if self.c and HAS_RICH:
            self.c.print(f"\n  [bold white on blue] {tool} [/] [bold]{desc}[/]")
        else:
            print(f"\n  [{tool}] {desc}")

    def _done(self, run: RunResult, msg: str):
        dur = f" [dim][{run.duration:.1f}s][/]" if run.duration > 0 else ""
        if self.c and HAS_RICH:
            icon = "[bold green]✓[/]" if run.success else "[bold red]✗[/]"
            self.c.print(f"  {icon} {msg}{dur}")
        else:
            print(f"  {'OK' if run.success else 'FAIL'}: {msg}")

from __future__ import annotations

import asyncio
import csv
import ipaddress
import json
import logging
import os
import platform
import ctypes
import shutil
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

log = logging.getLogger("venafi.firewall")

# ─────────────────────────────────────────────────────────────────────────────
# Constants – well-known port → service name map
# ─────────────────────────────────────────────────────────────────────────────

WELL_KNOWN_PORTS: Dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    67:    "DHCP-Server",
    68:    "DHCP-Client",
    69:    "TFTP",
    80:    "HTTP",
    110:   "POP3",
    111:   "RPC",
    119:   "NNTP",
    123:   "NTP",
    135:   "MS-RPC",
    137:   "NetBIOS-NS",
    138:   "NetBIOS-DGM",
    139:   "NetBIOS-SSN",
    143:   "IMAP",
    161:   "SNMP",
    162:   "SNMP-Trap",
    389:   "LDAP",
    443:   "HTTPS",
    445:   "SMB",
    465:   "SMTPS",
    514:   "Syslog",
    587:   "SMTP-Submission",
    636:   "LDAPS",
    993:   "IMAPS",
    995:   "POP3S",
    1080:  "SOCKS-Proxy",
    1433:  "MSSQL",
    1521:  "Oracle-DB",
    2049:  "NFS",
    3306:  "MySQL",
    3389:  "RDP",
    4444:  "Metasploit",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "HTTP-Dev",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}

PORT_RISK: Dict[int, str] = {
    21:    "CRITICAL",   # FTP – cleartext, anon login possible
    23:    "CRITICAL",   # Telnet – cleartext
    135:   "CRITICAL",   # MS-RPC – lateral movement
    139:   "CRITICAL",   # NetBIOS
    445:   "CRITICAL",   # SMB – ransomware vector
    3389:  "CRITICAL",   # RDP – brute force target
    4444:  "CRITICAL",   # Metasploit default listener
    5900:  "CRITICAL",   # VNC – often unencrypted
    22:    "HIGH",        # SSH – must be key-only, no password auth
    25:    "HIGH",        # SMTP – relay abuse
    53:    "HIGH",        # DNS – amplification attacks
    80:    "HIGH",        # HTTP – should redirect to 443
    111:   "HIGH",        # RPC portmapper
    161:   "HIGH",        # SNMP v1/v2 – community strings
    1433:  "HIGH",        # MSSQL – exposed DB
    3306:  "HIGH",        # MySQL – exposed DB
    5432:  "HIGH",        # PostgreSQL – exposed DB
    6379:  "HIGH",        # Redis – often unauthenticated
    9200:  "HIGH",        # Elasticsearch – often unauthenticated
    27017: "HIGH",        # MongoDB – often unauthenticated
    8080:  "MEDIUM",      # HTTP-Alt – plain text
    8888:  "MEDIUM",      # Dev server
    110:   "MEDIUM",      # POP3 – cleartext
    143:   "MEDIUM",      # IMAP – cleartext
    443:   "ALLOWED",     # HTTPS – the only permitted port for web servers
    8443:  "LOW",         # HTTPS-Alt – acceptable with policy
}


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

class PortState(str, Enum):
    OPEN     = "OPEN"
    CLOSED   = "CLOSED"
    FILTERED = "FILTERED"
    BLOCKED  = "BLOCKED"    # Was open, now blocked by enforcement


@dataclass
class PortResult:
    port:        int
    protocol:    str          # TCP | UDP
    state:       PortState
    service:     str          = ""
    banner:      str          = ""
    risk:        str          = "UNKNOWN"
    response_ms: float        = 0.0
    blocked_at:  Optional[str] = None   # ISO timestamp if we blocked it

    @property
    def is_open(self) -> bool:
        return self.state == PortState.OPEN

    @property
    def is_allowed(self) -> bool:
        return self.port == 443 and self.protocol == "TCP"

    @property
    def needs_blocking(self) -> bool:
        return self.is_open and not self.is_allowed


@dataclass
class ScanTarget:
    host:        str
    ip:          str           = ""
    hostname:    str           = ""
    scan_time:   str           = ""
    os_guess:    str           = ""
    open_ports:  List[PortResult] = field(default_factory=list)
    blocked_ports: List[int]   = field(default_factory=list)
    scan_duration_s: float     = 0.0

    @property
    def open_count(self) -> int:
        return len([p for p in self.open_ports if p.is_open])

    @property
    def critical_count(self) -> int:
        return len([p for p in self.open_ports if p.risk == "CRITICAL"])

    @property
    def is_compliant(self) -> bool:
        """True only if 443 is open and no other ports are open."""
        open_ports = [p for p in self.open_ports if p.is_open]
        return (
            len(open_ports) == 1
            and open_ports[0].port == 443
            and open_ports[0].protocol == "TCP"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Async port scanner
# ─────────────────────────────────────────────────────────────────────────────

class AsyncPortScanner:
    """
    High-performance async TCP connect scanner.
    """

    def __init__(
        self,
        concurrency:   int   = 500,
        timeout:       float = 1.5,
        banner_timeout: float = 2.0,
        grab_banners:  bool  = True,
    ) -> None:
        self._concurrency    = concurrency
        self._timeout        = timeout
        self._banner_timeout = banner_timeout
        self._grab_banners   = grab_banners

    async def scan_target(
        self,
        host:      str,
        ports:     Optional[List[int]] = None,
        port_range: Tuple[int, int]    = (1, 1024),
    ) -> ScanTarget:
        start_time = asyncio.get_event_loop().time()

        # Resolve host
        ip = await self._resolve(host)
        hostname = await self._reverse_dns(ip)

        target = ScanTarget(
            host=host, ip=ip, hostname=hostname,
            scan_time=datetime.now(timezone.utc).isoformat(),
        )

        # Build port list
        if ports:
            scan_ports = ports
        else:
            scan_ports = list(range(port_range[0], port_range[1] + 1))

        log.info("Scanning %s (%s): %d ports (concurrency=%d, timeout=%.1fs)",
                 host, ip, len(scan_ports), self._concurrency, self._timeout)

        sem     = asyncio.Semaphore(self._concurrency)
        tasks   = [self._scan_port(ip, port, sem) for port in scan_ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, PortResult) and r.is_open:
                target.open_ports.append(r)

        target.open_ports.sort(key=lambda p: p.port)
        target.scan_duration_s = asyncio.get_event_loop().time() - start_time

        log.info("Scan complete: %s – %d open ports in %.1fs",
                 host, target.open_count, target.scan_duration_s)
        return target

    async def scan_multiple(
        self,
        hosts:      List[str],
        ports:      Optional[List[int]] = None,
        port_range: Tuple[int, int]     = (1, 1024),
    ) -> List[ScanTarget]:
        tasks = [
            self.scan_target(h, ports=ports, port_range=port_range)
            for h in hosts
        ]
        return await asyncio.gather(*tasks, return_exceptions=False)

    async def _scan_port(
        self, ip: str, port: int, sem: asyncio.Semaphore
    ) -> PortResult:
        async with sem:
            t0 = asyncio.get_event_loop().time()
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self._timeout)
                elapsed = (asyncio.get_event_loop().time() - t0) * 1000

                banner = ""
                if self._grab_banners:
                    banner = await self._grab_banner(reader, writer, port)

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                service = WELL_KNOWN_PORTS.get(port, "Unknown")
                risk    = PORT_RISK.get(port, "MEDIUM")

                log.debug("OPEN  %s:%d  (%s)  %.0fms", ip, port, service, elapsed)
                return PortResult(
                    port=port, protocol="TCP", state=PortState.OPEN,
                    service=service, banner=banner[:200], risk=risk,
                    response_ms=round(elapsed, 1),
                )

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return PortResult(
                    port=port, protocol="TCP", state=PortState.CLOSED,
                    service=WELL_KNOWN_PORTS.get(port, ""),
                    risk=PORT_RISK.get(port, "UNKNOWN"),
                )

    async def _grab_banner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        port:   int,
    ) -> str:
        probes: Dict[int, bytes] = {
            80:   b"HEAD / HTTP/1.0\r\n\r\n",
            443:  b"",
            21:   b"",
            22:   b"",
            25:   b"",
            3306: b"",
        }
        probe = probes.get(port, b"")
        if probe:
            try:
                writer.write(probe)
                await writer.drain()
            except Exception:
                return ""

        try:
            data = await asyncio.wait_for(reader.read(256), timeout=self._banner_timeout)
            return data.decode("utf-8", errors="replace").strip()
        except Exception:
            return ""

    @staticmethod
    async def _resolve(host: str) -> str:
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        loop = asyncio.get_event_loop()
        try:
            info = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            return info[0][4][0]
        except Exception:
            log.warning("Could not resolve host: %s – using as-is", host)
            return host

    @staticmethod
    async def _reverse_dns(ip: str) -> str:
        loop = asyncio.get_event_loop()
        try:
            result = await loop.getnameinfo((ip, 0), 0)
            return result[0]
        except Exception:
            return ""


# ─────────────────────────────────────────────────────────────────────────────
# Firewall enforcement engine
# ─────────────────────────────────────────────────────────────────────────────

class FirewallBackend(str, Enum):
    IPTABLES   = "iptables"
    NFTABLES   = "nftables"
    UFW        = "ufw"
    NETSH      = "netsh"
    SIMULATION = "simulation"


class FirewallEnforcer:
    """
    Applies firewall rules to block all ports except 443 (HTTPS).
    """

    PROTECTED_PORTS: Set[int] = {443}

    def __init__(
        self,
        backend:           Optional[FirewallBackend] = None,
        allowed_ports:     Optional[List[int]]       = None,
        allowed_protocols: Optional[List[str]]       = None,
        dry_run:           bool                      = False,
    ) -> None:
        self._backend     = backend or self._detect_backend()
        self._dry_run     = dry_run
        self._allowed     = set(allowed_ports or [443])
        self._allowed_proto = set(allowed_protocols or ["TCP"])
        log.info("Firewall enforcer initialised: backend=%s  allowed_ports=%s  dry_run=%s",
                 self._backend.value, sorted(self._allowed), dry_run)

    @staticmethod
    def _detect_backend() -> FirewallBackend:
        # Robust Administrator/Root check
        is_admin = False
        if platform.system() == "Windows":
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                is_admin = False
        else:
            is_admin = os.getuid() == 0 if hasattr(os, "getuid") else False

        if not is_admin:
            log.warning("Not running with administrative privileges – using simulation mode for firewall rules")
            return FirewallBackend.SIMULATION

        if platform.system() == "Windows":
            return FirewallBackend.NETSH

        if shutil.which("nft"):
            return FirewallBackend.NFTABLES
        if shutil.which("ufw"):
            return FirewallBackend.UFW
        if shutil.which("iptables"):
            return FirewallBackend.IPTABLES

        log.warning("No supported firewall tool found – using simulation mode")
        return FirewallBackend.SIMULATION

    async def enforce_web_server_policy(
        self, target: ScanTarget
    ) -> Tuple[List[int], List[int]]:
        to_block = [p for p in target.open_ports if p.needs_blocking]
        blocked: List[int] = []
        failed:  List[int] = []

        log.info("Enforcing web server policy on %s: %d ports to block",
                 target.host, len(to_block))

        if not to_block:
            log.info("Host %s already compliant (no non-443 open ports)", target.host)
            return [], []

        await self._apply_base_ruleset()

        for port_result in to_block:
            success = await self._block_port(
                host     = target.ip or target.host,
                port     = port_result.port,
                protocol = port_result.protocol,
                service  = port_result.service,
            )
            if success:
                blocked.append(port_result.port)
                port_result.state      = PortState.BLOCKED
                port_result.blocked_at = datetime.now(timezone.utc).isoformat()
                log.warning("BLOCKED port %d/%s (%s) on %s",
                            port_result.port, port_result.protocol,
                            port_result.service, target.host)
            else:
                failed.append(port_result.port)
                log.error("FAILED to block port %d on %s", port_result.port, target.host)

        target.blocked_ports = blocked
        log.info("Enforcement complete on %s: blocked=%d  failed=%d",
                 target.host, len(blocked), len(failed))
        return blocked, failed

    async def _apply_base_ruleset(self) -> None:
        if self._backend == FirewallBackend.IPTABLES:
            await self._run_rules([
                ["iptables", "-F", "INPUT"],
                ["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-m", "state",
                 "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "443",
                 "-m", "state", "--state", "NEW,ESTABLISHED", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-j", "DROP"],
            ])

        elif self._backend == FirewallBackend.NFTABLES:
            nft_rules = (
                "table inet filter { "
                "  chain input { "
                "    type filter hook input priority 0; "
                "    iif lo accept; "
                "    ct state established,related accept; "
                "    tcp dport 443 ct state new,established accept; "
                "    drop; "
                "  } "
                "}"
            )
            await self._run_rules([["nft", "-f", "/dev/stdin"]], stdin=nft_rules)

        elif self._backend == FirewallBackend.UFW:
            await self._run_rules([
                ["ufw", "--force", "reset"],
                ["ufw", "default", "deny", "incoming"],
                ["ufw", "default", "allow", "outgoing"],
                ["ufw", "allow", "443/tcp"],
                ["ufw", "--force", "enable"],
            ])

        elif self._backend == FirewallBackend.NETSH:
            await self._run_rules([
                ["netsh", "advfirewall", "firewall", "set",
                 "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"],
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 "name=Allow-HTTPS", "dir=in", "action=allow",
                 "protocol=TCP", "localport=443"],
            ])

        elif self._backend == FirewallBackend.SIMULATION:
            log.info("[SIM] Would apply base ruleset: ALLOW 443, DROP all others")

    async def _block_port(
        self, host: str, port: int, protocol: str, service: str
    ) -> bool:
        if port in self.PROTECTED_PORTS:
            log.warning("Refusing to block protected port %d", port)
            return False

        proto_flag = protocol.lower()

        rules: Dict[FirewallBackend, List[List[str]]] = {
            FirewallBackend.IPTABLES: [
                ["iptables", "-I", "INPUT", "1", "-p", proto_flag,
                 "--dport", str(port), "-j", "DROP"],
            ],
            FirewallBackend.NFTABLES: [
                ["nft", "add", "rule", "inet", "filter", "input",
                 proto_flag, "dport", str(port), "drop"],
            ],
            FirewallBackend.UFW: [
                ["ufw", "deny", f"{port}/{proto_flag}"],
            ],
            FirewallBackend.NETSH: [
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name=Block-{service}-{port}", "dir=in", "action=block",
                 f"protocol={protocol}", f"localport={port}"],
            ],
        }

        if self._backend == FirewallBackend.SIMULATION:
            log.info("[SIM] Would block: %s port %d/%s (%s)",
                     host, port, protocol, service)
            return True

        cmds = rules.get(self._backend, [])
        for cmd in cmds:
            ok = await self._exec(cmd)
            if not ok:
                return False
        return True

    async def _run_rules(
        self, rules: List[List[str]], stdin: Optional[str] = None
    ) -> None:
        for rule in rules:
            await self._exec(rule, stdin=stdin)

    async def _exec(
        self, cmd: List[str], stdin: Optional[str] = None
    ) -> bool:
        if self._dry_run:
            log.info("[DRY-RUN] $ %s", " ".join(cmd))
            return True

        log.debug("$ %s", " ".join(cmd))
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin  = asyncio.subprocess.PIPE if stdin else None,
                stdout = asyncio.subprocess.PIPE,
                stderr = asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate(
                input=stdin.encode() if stdin else None
            )
            if proc.returncode != 0:
                log.error("Command failed (rc=%d): %s\n%s",
                          proc.returncode, " ".join(cmd),
                          stderr.decode(errors="replace"))
                return False
            return True
        except FileNotFoundError:
            log.error("Command not found: %s", cmd[0])
            return False
        except Exception as exc:
            log.error("Command error: %s – %s", " ".join(cmd), exc)
            return False

    async def list_current_rules(self) -> str:
        if self._backend == FirewallBackend.SIMULATION:
            return "[SIMULATION] No live firewall rules (running without root/administrator)"

        cmds: Dict[FirewallBackend, List[str]] = {
            FirewallBackend.IPTABLES: ["iptables", "-L", "-n", "-v", "--line-numbers"],
            FirewallBackend.NFTABLES: ["nft", "list", "ruleset"],
            FirewallBackend.UFW:      ["ufw", "status", "verbose"],
            FirewallBackend.NETSH:    ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
        }
        cmd = cmds.get(self._backend, [])
        if not cmd:
            return ""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode(errors="replace")
        except Exception as exc:
            return f"Error listing rules: {exc}"


# ─────────────────────────────────────────────────────────────────────────────
# Report generator
# ─────────────────────────────────────────────────────────────────────────────

class FirewallReportGenerator:
    """
    Generates firewall scan reports in JSON, CSV and HTML.
    """

    def __init__(self, report_dir: str = "./reports") -> None:
        self._dir = Path(report_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def generate_all(
        self,
        targets:     List[ScanTarget],
        scan_config: Dict[str, Any],
    ) -> Dict[str, str]:
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
        paths = {}

        paths["json"] = self._write_json(targets, scan_config, ts)
        paths["csv"]  = self._write_csv(targets, ts)
        paths["html"] = self._write_html(targets, scan_config, ts)

        log.info("Reports written: %s", paths)
        return paths

    def _write_json(
        self,
        targets:     List[ScanTarget],
        scan_config: Dict[str, Any],
        ts:          str,
    ) -> str:
        path = self._dir / f"firewall_scan_{ts}.json"

        report = {
            "report_type":   "Firewall Port Scan & Enforcement Report",
            "generated_at":  datetime.now(timezone.utc).isoformat(),
            "scan_config":   scan_config,
            "summary": {
                "total_hosts":      len(targets),
                "compliant_hosts":  sum(1 for t in targets if t.is_compliant),
                "total_open_ports": sum(t.open_count for t in targets),
                "total_blocked":    sum(len(t.blocked_ports) for t in targets),
                "critical_findings": sum(t.critical_count for t in targets),
            },
            "targets": [self._serialise_target(t) for t in targets],
        }

        with open(path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        return str(path)

    def _write_csv(self, targets: List[ScanTarget], ts: str) -> str:
        path = self._dir / f"firewall_scan_{ts}.csv"

        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                "Host", "IP", "Hostname", "Port", "Protocol", "State",
                "Service", "Risk", "Banner", "ResponseMs",
                "Blocked", "BlockedAt", "Compliant", "ScanTime",
            ])
            for target in targets:
                if not target.open_ports:
                    w.writerow([
                        target.host, target.ip, target.hostname,
                        "", "", "NO_OPEN_PORTS", "", "N/A", "", "",
                        "", "", str(target.is_compliant), target.scan_time,
                    ])
                for p in target.open_ports:
                    w.writerow([
                        target.host, target.ip, target.hostname,
                        p.port, p.protocol, p.state.value,
                        p.service, p.risk, p.banner[:80], p.response_ms,
                        str(p.port in target.blocked_ports),
                        p.blocked_at or "",
                        str(target.is_compliant),
                        target.scan_time,
                    ])

        return str(path)

    def _write_html(
        self,
        targets:     List[ScanTarget],
        scan_config: Dict[str, Any],
        ts:          str,
    ) -> str:
        path = self._dir / f"firewall_report_{ts}.html"
        html = self._build_html(targets, scan_config, ts)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return str(path)

    def _build_html(
        self,
        targets:     List[ScanTarget],
        scan_config: Dict[str, Any],
        ts:          str,
    ) -> str:
        total_open    = sum(t.open_count for t in targets)
        total_blocked = sum(len(t.blocked_ports) for t in targets)
        total_crit    = sum(t.critical_count for t in targets)
        compliant     = sum(1 for t in targets if t.is_compliant)
        generated     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        rows_html = ""
        for target in targets:
            if not target.open_ports:
                rows_html += f"""
                <tr>
                    <td><strong>{target.host}</strong><br>
                        <small class="text-muted">{target.ip}</small></td>
                    <td>—</td><td>—</td>
                    <td><span class="badge bg-success">No Open Ports</span></td>
                    <td>—</td><td>—</td>
                    <td><span class="badge bg-success">✓ COMPLIANT</span></td>
                </tr>"""
                continue

            for p in target.open_ports:
                risk_color = {
                    "CRITICAL": "danger",
                    "HIGH":     "warning",
                    "MEDIUM":   "info",
                    "LOW":      "secondary",
                    "ALLOWED":  "success",
                }.get(p.risk, "secondary")

                state_badge = {
                    PortState.OPEN:    '<span class="badge bg-danger">OPEN</span>',
                    PortState.BLOCKED: '<span class="badge bg-dark">BLOCKED ✓</span>',
                    PortState.CLOSED:  '<span class="badge bg-secondary">CLOSED</span>',
                    PortState.FILTERED:'<span class="badge bg-warning">FILTERED</span>',
                }.get(p.state, p.state.value)

                compliant_badge = (
                    '<span class="badge bg-success">✓ COMPLIANT</span>'
                    if target.is_compliant else
                    '<span class="badge bg-danger">✗ NON-COMPLIANT</span>'
                )

                rows_html += f"""
                <tr>
                    <td><strong>{target.host}</strong><br>
                        <small class="text-muted">{target.ip}</small></td>
                    <td><strong>{p.port}</strong></td>
                    <td>{p.protocol}</td>
                    <td>{state_badge}</td>
                    <td>{p.service}</td>
                    <td><span class="badge bg-{risk_color}">{p.risk}</span></td>
                    <td>{compliant_badge}</td>
                </tr>"""

        policy_ports = ", ".join(str(p) for p in sorted(scan_config.get("allowed_ports", [443])))

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Firewall Port Scan Report – {ts}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {{ font-family: 'Segoe UI', sans-serif; background: #f8f9fa; }}
    .header-bar {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
                   color: white; padding: 2rem; border-radius: 8px; margin-bottom: 2rem; }}
    .stat-card {{ border: none; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,.08); }}
    .stat-number {{ font-size: 2.5rem; font-weight: 700; }}
    table {{ font-size: 0.9rem; }}
    .badge {{ font-size: 0.8rem; }}
    .section-title {{ border-left: 4px solid #0d6efd; padding-left: 12px; margin: 1.5rem 0 1rem; }}
    footer {{ margin-top: 3rem; padding: 1rem 0; color: #6c757d; font-size: 0.8rem; }}
  </style>
</head>
<body>
<div class="container-fluid py-4">

  <div class="header-bar">
    <div class="row align-items-center">
      <div class="col">
        <h1 class="mb-1">🛡️ Firewall Port Scan & Enforcement Report</h1>
        <p class="mb-0 opacity-75">Generated: {generated} &nbsp;|&nbsp; Policy: Allow only port {policy_ports}/TCP</p>
      </div>
      <div class="col-auto">
        <span class="badge bg-{'success' if compliant == len(targets) else 'danger'} fs-6 p-3">
          {'✓ ALL COMPLIANT' if compliant == len(targets) else '⚠ ACTION REQUIRED'}
        </span>
      </div>
    </div>
  </div>

  <div class="row g-3 mb-4">
    <div class="col-md-3">
      <div class="card stat-card text-center p-3">
        <div class="stat-number text-primary">{len(targets)}</div>
        <div class="text-muted">Hosts Scanned</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card stat-card text-center p-3">
        <div class="stat-number {'text-danger' if total_open > 0 else 'text-success'}">{total_open}</div>
        <div class="text-muted">Open Ports Found</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card stat-card text-center p-3">
        <div class="stat-number text-dark">{total_blocked}</div>
        <div class="text-muted">Ports Blocked</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card stat-card text-center p-3">
        <div class="stat-number {'text-danger' if total_crit > 0 else 'text-success'}">{total_crit}</div>
        <div class="text-muted">Critical Findings</div>
      </div>
    </div>
  </div>

  <div class="card stat-card mb-4">
    <div class="card-body">
      <h5 class="section-title">Compliance Overview</h5>
      <div class="row">
        <div class="col-md-6">
          <div class="progress" style="height: 30px; border-radius: 8px;">
            <div class="progress-bar bg-success" style="width: {int(compliant/max(len(targets),1)*100)}%">
              {compliant}/{len(targets)} Compliant
            </div>
          </div>
        </div>
        <div class="col-md-6">
          <p class="mb-1"><strong>Policy:</strong> Only TCP port 443 (HTTPS) is permitted inbound</p>
          <p class="mb-0 text-muted"><small>All other ports must be BLOCKED or CLOSED.</small></p>
        </div>
      </div>
    </div>
  </div>

  <div class="card stat-card">
    <div class="card-body">
      <h5 class="section-title">Port Scan Findings</h5>
      <div class="table-responsive">
        <table class="table table-hover table-bordered align-middle">
          <thead class="table-dark">
            <tr>
              <th>Host</th>
              <th>Port</th>
              <th>Protocol</th>
              <th>State</th>
              <th>Service</th>
              <th>Risk Level</th>
              <th>Compliance</th>
            </tr>
          </thead>
          <tbody>
            {rows_html}
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <footer class="text-center">
    Report generated {generated} &bull; Policy: FIPS 140-2 / PCI-DSS / SOC2
  </footer>
</div>
</body>
</html>"""

    @staticmethod
    def _serialise_target(t: ScanTarget) -> Dict[str, Any]:
        return {
            "host":         t.host,
            "ip":           t.ip,
            "hostname":     t.hostname,
            "scan_time":    t.scan_time,
            "scan_duration_s": t.scan_duration_s,
            "compliant":    t.is_compliant,
            "open_count":   t.open_count,
            "blocked_count": len(t.blocked_ports),
            "blocked_ports": t.blocked_ports,
            "open_ports": [
                {
                    "port":        p.port,
                    "protocol":    p.protocol,
                    "state":       p.state.value,
                    "service":     p.service,
                    "risk":        p.risk,
                    "banner":      p.banner,
                    "response_ms": p.response_ms,
                    "blocked_at":  p.blocked_at,
                }
                for p in t.open_ports
            ],
        }


# ─────────────────────────────────────────────────────────────────────────────
# High-level firewall agent (plugs into PKI orchestrator)
# ─────────────────────────────────────────────────────────────────────────────

class FirewallScanAgent:
    """
    Top-level agent that runs firewall scans, auto-blocks ports, and writes reports.
    """

    def __init__(
        self,
        hosts:         List[str],
        port_range:    Tuple[int, int]   = (1, 1024),
        extra_ports:   Optional[List[int]] = None,
        allowed_ports: Optional[List[int]] = None,
        concurrency:   int               = 300,
        timeout:       float             = 1.5,
        auto_block:    bool              = True,
        dry_run:       bool              = False,
        report_dir:    str               = "./reports",
    ) -> None:
        self._hosts         = hosts
        self._port_range    = port_range
        self._extra_ports   = extra_ports
        self._allowed       = allowed_ports or [443]
        self._auto_block    = auto_block
        self._dry_run       = dry_run
        self._report_dir    = report_dir
        self._concurrency   = concurrency
        self._timeout       = timeout

    async def run(self) -> Dict[str, Any]:
        ports: Optional[List[int]] = None
        if self._extra_ports:
            range_ports = list(range(self._port_range[0], self._port_range[1] + 1))
            ports = sorted(set(range_ports + self._extra_ports))

        scanner = AsyncPortScanner(
            concurrency=self._concurrency,
            timeout=self._timeout,
            grab_banners=True,
        )
        targets = await scanner.scan_multiple(
            hosts=self._hosts,
            ports=ports,
            port_range=self._port_range,
        )

        if self._auto_block:
            enforcer = FirewallEnforcer(
                allowed_ports=self._allowed,
                dry_run=self._dry_run,
            )
            for target in targets:
                if not target.is_compliant:
                    blocked, failed = await enforcer.enforce_web_server_policy(target)
                    if blocked:
                        log.warning("Blocked %d port(s) on %s: %s",
                                    len(blocked), target.host, blocked)
                    if failed:
                        log.error("FAILED to block %d port(s) on %s: %s",
                                  len(failed), target.host, failed)

        scan_config = {
            "hosts":        self._hosts,
            "port_range":   self._port_range,
            "allowed_ports": self._allowed,
            "auto_block":   self._auto_block,
            "dry_run":      self._dry_run,
            "concurrency":  self._concurrency,
            "timeout_s":    self._timeout,
        }
        reporter = FirewallReportGenerator(self._report_dir)
        report_paths = reporter.generate_all(targets, scan_config)

        total_open    = sum(t.open_count for t in targets)
        total_blocked = sum(len(t.blocked_ports) for t in targets)
        compliant     = sum(1 for t in targets if t.is_compliant)

        summary = {
            "status":          "complete",
            "hosts_scanned":   len(targets),
            "open_ports_found": total_open,
            "ports_blocked":   total_blocked,
            "compliant_hosts": compliant,
            "non_compliant":   len(targets) - compliant,
            "reports":         report_paths,
            "targets":         [
                {
                    "host":      t.host,
                    "ip":        t.ip,
                    "compliant": t.is_compliant,
                    "open":      [p.port for p in t.open_ports if p.is_open],
                    "blocked":   t.blocked_ports,
                }
                for t in targets
            ],
        }

        return summary

import asyncio
import socket
from typing import List, Tuple, Dict

WELL_KNOWN_PORTS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
}

PORT_RISK = {
    22: "HIGH",
    80: "MEDIUM",
    443: "ALLOWED",
    3306: "HIGH",
    5432: "HIGH",
    8080: "MEDIUM",
}

class FirewallScanAgent:
    """Simple asynchronous port scanner with optional auto‑blocking simulation.

    Parameters
    ----------
    hosts: List[str]
        List of hostnames or IP addresses to scan.
    port_range: Tuple[int, int]
        Inclusive start and end ports.
    auto_block: bool
        If True, ports other than 443 are marked as blocked in the result.
    report_dir: str
        Directory where optional HTML/CSV reports could be saved (not implemented here).
    """

    def __init__(self, hosts: List[str], port_range: Tuple[int, int], auto_block: bool = False, report_dir: str = "reports"):
        self.hosts = hosts
        self.start_port, self.end_port = port_range
        self.auto_block = auto_block
        self.report_dir = report_dir

    async def _scan_port(self, host: str, port: int) -> bool:
        """Attempt to open a TCP connection to *host*: *port*.
        Returns True if connection succeeds (port open), False otherwise.
        """
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=0.5)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def _scan_host(self, host: str) -> Dict:
        open_ports = []
        blocked_ports = []
        for port in range(self.start_port, self.end_port + 1):
            is_open = await self._scan_port(host, port)
            if is_open:
                open_ports.append(port)
                if self.auto_block and port != 443:
                    blocked_ports.append(port)
        return {
            "ip": host,
            "open": open_ports,
            "blocked": blocked_ports,
            "compliant": all(p == 443 for p in open_ports),
        }

    async def run(self) -> Dict:
        """Execute scans for all configured hosts and return a summary dict.
        The structure matches the expectations in *streamlit_app.py*.
        """
        tasks = [self._scan_host(host) for host in self.hosts]
        results = await asyncio.gather(*tasks)
        summary = {
            "targets": [
                {
                    "ip": r["ip"],
                    "open": [{"port": p, "protocol": "TCP", "state": "OPEN", "service": WELL_KNOWN_PORTS.get(p, "Unknown"), "risk": PORT_RISK.get(p, "HIGH") if p != 443 else "ALLOWED"} for p in r["open"]],
                    "blocked": r["blocked"],
                    "compliant": r["compliant"],
                }
                for r in results
            ]
        }
        return summary

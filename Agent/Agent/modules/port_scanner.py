"""
Port Scanner Module
-------------------
Scans the local device and network for open ports.
Identifies services, flags dangerous exposures.
"""

import socket
import logging
import concurrent.futures
from datetime import datetime

log = logging.getLogger("PortScanner")

# Well-known ports and their services
KNOWN_SERVICES = {
    21: {"name": "FTP", "risk": "HIGH", "reason": "FTP transmits data unencrypted"},
    22: {"name": "SSH", "risk": "MEDIUM", "reason": "SSH open — ensure key-based auth only"},
    23: {"name": "Telnet", "risk": "CRITICAL", "reason": "Telnet is unencrypted — disable immediately"},
    25: {"name": "SMTP", "risk": "MEDIUM", "reason": "Mail server exposed"},
    53: {"name": "DNS", "risk": "LOW", "reason": "DNS service running"},
    80: {"name": "HTTP", "risk": "MEDIUM", "reason": "Unencrypted web server"},
    443: {"name": "HTTPS", "risk": "LOW", "reason": "Secure web server"},
    445: {"name": "SMB", "risk": "CRITICAL", "reason": "SMB exposed — common ransomware vector (EternalBlue)"},
    1433: {"name": "MSSQL", "risk": "HIGH", "reason": "SQL Server exposed to network"},
    3306: {"name": "MySQL", "risk": "HIGH", "reason": "MySQL database exposed — check firewall"},
    3389: {"name": "RDP", "risk": "HIGH", "reason": "Remote Desktop exposed — brute force target"},
    5432: {"name": "PostgreSQL", "risk": "HIGH", "reason": "PostgreSQL exposed to network"},
    5900: {"name": "VNC", "risk": "CRITICAL", "reason": "VNC often has weak auth — high risk"},
    6379: {"name": "Redis", "risk": "CRITICAL", "reason": "Redis exposed — often unauthenticated"},
    8080: {"name": "HTTP-Alt", "risk": "MEDIUM", "reason": "Alternative HTTP port open"},
    8443: {"name": "HTTPS-Alt", "risk": "LOW", "reason": "Alternative HTTPS port"},
    9200: {"name": "Elasticsearch", "risk": "CRITICAL", "reason": "Elasticsearch exposed — data leak risk"},
    27017: {"name": "MongoDB", "risk": "CRITICAL", "reason": "MongoDB exposed — often unauthenticated"},
}

RISK_SCORE = {"LOW": 1, "MEDIUM": 3, "HIGH": 7, "CRITICAL": 10}


class PortScanner:
    """Scans ports on localhost and detects risky exposed services."""

    def __init__(self, config: dict):
        self.config = config
        self.timeout = 0.5  # seconds per port

    def scan_localhost(self) -> dict:
        """Scan common ports on this device."""
        return self.scan_target("127.0.0.1", port_range=(1, 10000))

    def scan_target(self, host: str, port_range: tuple = (1, 1024)) -> dict:
        """
        Scan a host for open ports using concurrent socket connections.

        Args:
            host: IP or hostname to scan
            port_range: (start, end) port range inclusive
        """
        log.info(f"Scanning {host} ports {port_range[0]}-{port_range[1]}")
        start_time = datetime.now()

        open_ports = []
        ports_to_scan = range(port_range[0], port_range[1] + 1)

        # Use thread pool for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
            futures = {
                executor.submit(self._check_port, host, port): port
                for port in ports_to_scan
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)

        open_ports.sort(key=lambda x: x["port"])

        # Calculate overall risk score
        risk_score = sum(RISK_SCORE.get(p.get("risk", "LOW"), 1) for p in open_ports)
        critical_ports = [p for p in open_ports if p.get("risk") == "CRITICAL"]

        scan_time = (datetime.now() - start_time).total_seconds()

        result = {
            "target": host,
            "scanned_at": start_time.isoformat(),
            "scan_duration_seconds": round(scan_time, 2),
            "ports_scanned": len(ports_to_scan),
            "open_ports": open_ports,
            "total_open": len(open_ports),
            "risk_score": risk_score,
            "critical_exposures": len(critical_ports),
            "status": "CRITICAL" if critical_ports else ("WARNING" if open_ports else "CLEAN"),
        }

        log.info(
            f"Scan complete | {len(open_ports)} open ports | "
            f"Risk score: {risk_score} | Status: {result['status']}"
        )

        if critical_ports:
            for p in critical_ports:
                log.warning(f"CRITICAL PORT: {p['port']} ({p['service']}) — {p['reason']}")

        return result

    def _check_port(self, host: str, port: int) -> dict:
        """Check if a single port is open. Returns port info dict or None."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                if result == 0:
                    # Port is open — get service info
                    service_info = KNOWN_SERVICES.get(port, {})
                    banner = self._grab_banner(host, port)
                    return {
                        "port": port,
                        "state": "open",
                        "service": service_info.get("name", self._guess_service(port)),
                        "risk": service_info.get("risk", "UNKNOWN"),
                        "reason": service_info.get("reason", "Unknown service"),
                        "banner": banner,
                    }
        except Exception:
            pass
        return None

    def _grab_banner(self, host: str, port: int) -> str:
        """Try to grab the service banner (version info)."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.0)
                sock.connect((host, port))
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
                return banner[:200]  # Limit banner length
        except Exception:
            return ""

    def _guess_service(self, port: int) -> str:
        """Guess service name from well-known port numbers."""
        try:
            return socket.getservbyport(port)
        except Exception:
            return f"unknown-{port}"

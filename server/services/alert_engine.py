"""
Alert Engine
------------
Analyzes incoming agent data and generates security alerts.

Called every time a report comes in.
Returns a list of alerts to be saved to the database.
"""


class AlertEngine:

    @staticmethod
    def check_system(agent_id: str, data: dict) -> list:
        """Check system metrics for problems."""
        alerts = []
        cpu = data.get("cpu", {})
        mem = data.get("memory", {}).get("ram", {})
        disks = data.get("disks", [])
        processes = data.get("processes", [])

        # High CPU usage
        cpu_usage = cpu.get("usage_percent", 0)
        if cpu_usage > 97:
            alerts.append({
                "type": "high_cpu",
                "severity": "HIGH",
                "title": f"CPU usage critical: {cpu_usage}%",
                "description": f"Device CPU is at {cpu_usage}% — possible cryptominer or runaway process.",
                "data": {"cpu_usage": cpu_usage},
            })

        # High RAM usage
        ram_pct = mem.get("percent_used", 0)
        if ram_pct > 97:
            alerts.append({
                "type": "high_memory",
                "severity": "MEDIUM",
                "title": f"Memory usage critical: {ram_pct}%",
                "description": f"RAM at {ram_pct}% — device may become unstable.",
                "data": {"ram_percent": ram_pct},
            })

        # Disk almost full
        for disk in disks:
            if disk.get("health_warning"):
                usage = disk.get("usage", {})
                pct = usage.get("percent_used", 0) if isinstance(usage, dict) else 0
                alerts.append({
                    "type": "disk_full",
                    "severity": "HIGH",
                    "title": f"Disk almost full: {disk['mountpoint']} at {pct}%",
                    "description": f"Drive {disk['device']} is {pct}% full. Backup and cleanup needed.",
                    "data": {"disk": disk},
                })

        # Suspicious processes
        for proc in processes:
            if proc.get("suspicious"):
                alerts.append({
                    "type": "suspicious_process",
                    "severity": "CRITICAL",
                    "title": f"Suspicious process detected: {proc.get('name')}",
                    "description": f"Process '{proc.get('name')}' (PID {proc.get('pid')}) is flagged as potentially malicious.",
                    "data": {"process": proc},
                })

        return alerts

    @staticmethod
    def check_ports(agent_id: str, data: dict) -> list:
        """Check port scan results for dangerous exposures."""
        alerts = []
        open_ports = data.get("open_ports", [])
        status = data.get("status", "CLEAN")

        SEVERITY_MAP = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
        }

        for port in open_ports:
            risk = port.get("risk", "LOW")
            if risk in ("CRITICAL", "HIGH"):
                alerts.append({
                    "type": "port_exposure",
                    "severity": SEVERITY_MAP.get(risk, "MEDIUM"),
                    "title": f"Dangerous port open: {port['port']} ({port['service']})",
                    "description": port.get("reason", "Risky port exposed to network."),
                    "data": {"port": port},
                })

        # Overall critical status
        if status == "CRITICAL":
            critical_count = data.get("critical_exposures", 0)
            alerts.append({
                "type": "critical_exposure",
                "severity": "CRITICAL",
                "title": f"Device has {critical_count} critical port exposure(s)",
                "description": "Immediate action required. Critical services are exposed to the network.",
                "data": {"scan_summary": data},
            })

        return alerts

    # Internal ZYVARON files that change constantly — never alert on these
    INTERNAL_PATHS = (
        "zyvaron.db", "cyberguard_agent.log", "remediation_log.json",
        "vault_db.json", ".venv", "__pycache__", ".pyc",
    )

    @staticmethod
    def check_files(agent_id: str, data: dict) -> list:
        """Check file change events for threats."""
        alerts = []
        deleted = data.get("deleted", [])
        modified = data.get("modified", [])

        def is_internal(path: str) -> bool:
            p = (path or "").lower()
            return any(x in p for x in AlertEngine.INTERNAL_PATHS)

        # Filter out internal ZYVARON files
        user_deleted = [f for f in deleted if not is_internal(f.get("path", ""))]

        # Mass deletion — possible ransomware
        if len(user_deleted) > 10:
            alerts.append({
                "type": "mass_deletion",
                "severity": "CRITICAL",
                "title": f"Mass file deletion detected: {len(user_deleted)} files deleted",
                "description": "Large number of files deleted simultaneously — possible ransomware attack. Immediate recovery recommended.",
                "data": {
                    "deleted_count": len(user_deleted),
                    "sample_paths": [f.get("path") for f in user_deleted[:5]],
                },
            })

        # Individual deleted files — alert ONCE per unique path only
        elif user_deleted:
            seen_paths = set()
            for f in user_deleted[:5]:
                path = f.get("path", "unknown")
                if path not in seen_paths:
                    seen_paths.add(path)
                    alerts.append({
                        "type": "file_deleted",
                        "severity": "HIGH",
                        "title": f"File deleted: {path}",
                        "description": "Protected file was deleted or moved. Recovery available from vault.",
                        "data": {"file": f, "path": path},
                    })

        # Mass modification — ransomware encryption pattern
        if len(modified) > 20:
            alerts.append({
                "type": "mass_modification",
                "severity": "CRITICAL",
                "title": f"Mass file modification: {len(modified)} files changed",
                "description": "Unusually high number of file modifications — possible ransomware encryption in progress.",
                "data": {"modified_count": len(modified)},
            })

        return alerts
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
        """Check system metrics for problems.
        CPU/RAM alerts only trigger at extreme levels that indicate actual threats
        (cryptominer, runaway process) — not normal high usage.
        These show in System Health page, NOT as security alerts.
        """
        alerts = []
        cpu = data.get("cpu", {})
        mem = data.get("memory", {}).get("ram", {})
        disks = data.get("disks", [])
        processes = data.get("processes", [])

        # CPU alert only at truly critical sustained levels (>98% = likely cryptominer/freeze)
        # Normal heavy usage (90-97%) is NOT a security alert - shown in System Health only
        cpu_usage = cpu.get("usage_percent", 0)
        if cpu_usage > 98:
            alerts.append({
                "type": "high_cpu",
                "severity": "HIGH",
                "title": f"CPU usage critical: {cpu_usage}%",
                "description": f"CPU at {cpu_usage}% — possible cryptominer or system freeze. Investigate running processes.",
                "data": {"cpu_usage": cpu_usage},
            })

        # RAM alert only when system is about to become unresponsive (>95%)
        ram_pct = mem.get("percent_used", 0)
        if ram_pct > 95:
            alerts.append({
                "type": "high_memory",
                "severity": "HIGH",
                "title": f"Memory critical: {ram_pct}%",
                "description": f"RAM at {ram_pct}% — system may freeze or crash imminently.",
                "data": {"ram_percent": ram_pct},
            })

        # Disk almost full (keep this threshold — disk full is always a problem)
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
        """Check port scan results for dangerous exposures.
        - Ports blocked by ZYVARON → create as already-RESOLVED alerts (show in history)
        - Unblocked dangerous ports → create as active alerts
        """
        alerts = []
        open_ports = data.get("open_ports", [])
        status = data.get("status", "CLEAN")

        ZYVARON_BLOCKED_PORTS = {3389, 445, 23, 21, 1433, 3306, 5900}
        BLOCKED_NAMES = {
            3389: "RDP", 445: "SMB", 23: "Telnet", 21: "FTP",
            1433: "MSSQL", 3306: "MySQL", 5900: "VNC"
        }

        dangerous_unblocked = []
        for port in open_ports:
            port_num = port.get("port")
            risk = port.get("risk", "LOW")
            if risk in ("CRITICAL", "HIGH"):
                if port_num in ZYVARON_BLOCKED_PORTS:
                    # Already blocked — create pre-resolved alert so it shows in history
                    alerts.append({
                        "type": "port_exposure",
                        "severity": risk,
                        "title": f"Dangerous port open: {port_num} ({BLOCKED_NAMES.get(port_num, port.get('service',''))})",
                        "description": f"Port {port_num} — ZYVARON firewall rule already active. Port is blocked.",
                        "data": {"port": port},
                        "auto_resolve": True,
                    })
                else:
                    dangerous_unblocked.append(port)
                    alerts.append({
                        "type": "port_exposure",
                        "severity": risk,
                        "title": f"Dangerous port open: {port_num} ({port.get('service','')})",
                        "description": port.get("reason", "Risky port exposed to network."),
                        "data": {"port": port},
                    })

        if status == "CRITICAL" and dangerous_unblocked:
            alerts.append({
                "type": "critical_exposure",
                "severity": "CRITICAL",
                "title": f"Device has {len(dangerous_unblocked)} critical port exposure(s)",
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
        """Check file change events for threats.
        NOTE: Individual file deletions are NOT threats — they are handled by
        the File Vault system (stored as FileEvents, shown in File Vault dashboard).
        Only mass deletion (ransomware pattern) generates a threat alert.
        """
        alerts = []
        deleted = data.get("deleted", [])
        modified = data.get("modified", [])

        def is_internal(path: str) -> bool:
            p = (path or "").lower()
            return any(x in p for x in AlertEngine.INTERNAL_PATHS)

        # Filter out internal ZYVARON files
        user_deleted = [f for f in deleted if not is_internal(f.get("path", ""))]

        # Mass deletion only — possible ransomware (10+ files at once = threat)
        if len(user_deleted) > 10:
            alerts.append({
                "type": "mass_deletion",
                "severity": "CRITICAL",
                "title": f"Mass file deletion detected: {len(user_deleted)} files deleted",
                "description": "Large number of files deleted simultaneously — possible ransomware attack. Check File Vault for recovery.",
                "data": {
                    "deleted_count": len(user_deleted),
                    "sample_paths": [f.get("path") for f in user_deleted[:5]],
                },
            })
        # Individual deletions: DO NOT generate threat alerts.
        # They are visible in the File Vault page as deletable/recoverable items.

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


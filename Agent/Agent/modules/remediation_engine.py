"""
ZYVARON Autonomous Remediation Engine v0.2.1
=============================================
Fixes in this version:
  - Ports already blocked by ZYVARON still report SUCCESS back to server
    (so the alert gets resolved in the dashboard)
  - System Idle Process excluded from CPU alerts (false positive)
  - Chrome and other browsers excluded from CPU kill list
  - Cleaner logging
"""

import os
import sys
import logging
import subprocess
import psutil
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger("RemediationEngine")

DANGEROUS_PORTS = {
    445:  {"name": "SMB",   "severity": "CRITICAL", "auto_block": True,  "reason": "EternalBlue ransomware vector"},
    3389: {"name": "RDP",   "severity": "HIGH",     "auto_block": True,  "reason": "Brute force target"},
    23:   {"name": "Telnet","severity": "CRITICAL",  "auto_block": True,  "reason": "Unencrypted protocol"},
    21:   {"name": "FTP",   "severity": "HIGH",     "auto_block": True,  "reason": "Unencrypted file transfer"},
    1433: {"name": "MSSQL", "severity": "HIGH",     "auto_block": True,  "reason": "Database exposed"},
    3306: {"name": "MySQL", "severity": "HIGH",     "auto_block": True,  "reason": "Database exposed"},
    5900: {"name": "VNC",   "severity": "CRITICAL",  "auto_block": True,  "reason": "Remote desktop exposure"},
}


# Software → winget package ID mapping for AUTO mode updates
WINGET_PACKAGE_IDS = {
    "git":             "Git.Git",
    "google chrome":   "Google.Chrome",
    "chrome":          "Google.Chrome",
    "python":          "Python.Python.3.14",
    "mozilla firefox": "Mozilla.Firefox",
    "firefox":         "Mozilla.Firefox",
    "visual studio code": "Microsoft.VisualStudioCode",
    "vscode":          "Microsoft.VisualStudioCode",
    "7-zip":           "7zip.7zip",
    "vlc":             "VideoLAN.VLC",
    "zoom":            "Zoom.Zoom",
    "notepad++":       "Notepad++.Notepad++",
    "node.js":         "OpenJS.NodeJS",
    "nodejs":          "OpenJS.NodeJS",
    "microsoft teams": "Microsoft.Teams",
    "teams":           "Microsoft.Teams",
}


SUSPICIOUS_PROCESSES = [
    "xmrig", "minerd", "cpuminer", "cgminer", "bfgminer",
    "nicehash", "nanominer", "gminer", "t-rex",
    "wannacry", "petya", "locky", "cryptolocker",
    "mimikatz", "meterpreter", "ncat",
]

# Processes that are SAFE and should NEVER be killed even at high CPU
SAFE_PROCESSES = {
    "system idle process", "system", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "services.exe", "lsass.exe", "svchost.exe", "dwm.exe",
    "explorer.exe", "taskmgr.exe", "chrome.exe", "msedge.exe", "firefox.exe",
    "brave.exe", "opera.exe", "code.exe", "python.exe", "python3.exe",
    "powershell.exe", "cmd.exe", "conhost.exe", "antimalware service executable",
    "windows defender", "mpcmdrun.exe", "msmpeng.exe",
}

MASS_DELETION_THRESHOLD = 10


class RemediationAction:
    def __init__(self, action_type, target, success, details, severity="INFO"):
        self.action_type = action_type
        self.target      = target
        self.success     = success
        self.details     = details
        self.severity    = severity
        self.timestamp   = datetime.utcnow().isoformat()

    def to_dict(self):
        return {
            "action_type": self.action_type, "target": self.target,
            "success": self.success, "details": self.details,
            "severity": self.severity, "timestamp": self.timestamp,
        }


class RemediationEngine:

    def __init__(self, file_vault=None, mode: str = "smart"):
        self.file_vault      = file_vault
        self.mode            = mode
        self.actions_taken   = []
        self.blocked_ports   = set()
        self.killed_processes= set()
        self.is_windows      = sys.platform == "win32"
        self.log_path        = Path("remediation_log.json")
        self._load_log()
        logger.info(f"RemediationEngine initialized | Mode: {mode.upper()}")

    def _load_log(self):
        try:
            if self.log_path.exists():
                with open(self.log_path) as f:
                    d = json.load(f)
                    self.blocked_ports    = set(d.get("blocked_ports", []))
                    self.killed_processes = set(d.get("killed_processes", []))
        except Exception:
            pass

    def _save_log(self):
        try:
            with open(self.log_path, "w") as f:
                json.dump({
                    "blocked_ports": list(self.blocked_ports),
                    "killed_processes": list(self.killed_processes),
                    "actions": [a.to_dict() for a in self.actions_taken[-100:]],
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save log: {e}")

    def _record(self, action: RemediationAction):
        self.actions_taken.append(action)
        self._save_log()
        status = "[FIXED]" if action.success else "[FAILED]"
        logger.info(f"REMEDIATION {status} | {action.action_type} | {action.target} | {action.details}")

    def _should_act(self, severity: str) -> bool:
        if self.mode == "auto":   return True
        if self.mode == "smart":  return severity in ("CRITICAL", "HIGH")
        if self.mode == "manual": return False
        return True

    # ── PORT REMEDIATION ─────────────────────────────────────

    def remediate_port(self, port: int) -> Optional[RemediationAction]:
        port_info = DANGEROUS_PORTS.get(port, {
            "name": "Unknown", "severity": "HIGH", "auto_block": True, "reason": "Flagged dangerous"
        })

        if not self._should_act(port_info["severity"]):
            return None

        rule_name = f"ZYVARON-BLOCK-{port_info['name']}-{port}"

        # KEY FIX: If already blocked, still return a SUCCESS action
        # so the server marks the alert as resolved
        if port in self.blocked_ports:
            logger.info(f"Port {port} already blocked — reporting resolved to server")
            action = RemediationAction(
                action_type="PORT_BLOCKED",
                target=f"Port {port} ({port_info['name']})",
                success=True,
                details=f"Windows Firewall rule active: {rule_name}",
                severity=port_info["severity"],
            )
            self._record(action)
            return action

        logger.warning(f"AUTO-REMEDIATING: Blocking port {port} ({port_info['name']}) — {port_info['reason']}")

        if self.is_windows:
            success, details = self._block_port_windows(port, port_info["name"])
        else:
            success, details = self._block_port_linux(port, port_info["name"])

        if success:
            self.blocked_ports.add(port)

        action = RemediationAction(
            action_type="PORT_BLOCKED",
            target=f"Port {port} ({port_info['name']})",
            success=success,
            details=details,
            severity=port_info["severity"],
        )
        self._record(action)
        return action

    def _block_port_windows(self, port: int, service_name: str):
        rule_name = f"ZYVARON-BLOCK-{service_name}-{port}"
        try:
            check = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
                capture_output=True, text=True
            )
            if "No rules match" not in check.stdout:
                return True, f"Firewall rule '{rule_name}' already exists"

            result = subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "protocol=TCP", "dir=in",
                f"localport={port}", "action=block", "enable=yes",
                f"description=ZYVARON auto-blocked {service_name} {datetime.utcnow().isoformat()}"
            ], capture_output=True, text=True)

            if result.returncode == 0:
                logger.info(f"[FIXED] Firewall rule added: {rule_name}")
                return True, f"Windows Firewall rule created: {rule_name}"
            else:
                ps_cmd = (f"New-NetFirewallRule -DisplayName '{rule_name}' "
                          f"-Direction Inbound -Protocol TCP -LocalPort {port} -Action Block")
                ps = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True)
                if ps.returncode == 0:
                    return True, f"PowerShell firewall rule created: {rule_name}"
                return False, f"Failed: {result.stderr}"
        except Exception as e:
            return False, str(e)

    def _block_port_linux(self, port: int, service_name: str):
        try:
            result = subprocess.run(
                ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"],
                capture_output=True, text=True)
            return (True, f"iptables rule added for port {port}") if result.returncode == 0 else (False, result.stderr)
        except Exception as e:
            return False, str(e)

    # ── PROCESS SCANNING ─────────────────────────────────────

    def scan_and_kill_suspicious(self) -> list:
        """Scan for malicious processes — safe processes are NEVER killed."""
        actions = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                name = (proc.info['name'] or '').lower()
                exe  = (proc.info['exe'] or '').lower()

                # NEVER touch safe/system processes
                if name in SAFE_PROCESSES:
                    continue

                # Check against known malware names
                for suspect in SUSPICIOUS_PROCESSES:
                    if suspect in name or suspect in exe:
                        action = self._kill_process(proc.info['pid'], proc.info['name'],
                                                     f"Matches malware pattern: {suspect}")
                        if action:
                            actions.append(action)
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return actions

    def _kill_process(self, pid, name, reason) -> Optional[RemediationAction]:
        if pid in self.killed_processes or not self._should_act("CRITICAL"):
            return None
        logger.warning(f"AUTO-REMEDIATING: Killing {name} (PID {pid}) — {reason}")
        try:
            psutil.Process(pid).kill()
            self.killed_processes.add(pid)
            action = RemediationAction("PROCESS_KILLED", f"{name} (PID {pid})", True,
                                        f"Terminated. Reason: {reason}", "CRITICAL")
            self._record(action)
            return action
        except Exception as e:
            action = RemediationAction("PROCESS_KILL_FAILED", f"{name} (PID {pid})", False, str(e), "CRITICAL")
            self._record(action)
            return action

    # ── FILE RECOVERY ────────────────────────────────────────

    def remediate_deleted_files(self, deleted_files: list) -> list:
        if not self.file_vault:
            return []
        actions = []
        for path in deleted_files:
            if not self._should_act("HIGH"):
                continue
            try:
                recovered = self.file_vault.recover_file(path)
                action = RemediationAction("FILE_RECOVERED", path, recovered,
                    "Recovered from vault" if recovered else "Not in vault", "HIGH")
                self._record(action)
                actions.append(action)
            except Exception as e:
                action = RemediationAction("FILE_RECOVERY_FAILED", path, False, str(e), "HIGH")
                self._record(action)
                actions.append(action)
        return actions

    # ── RANSOMWARE RESPONSE ──────────────────────────────────

    def respond_to_ransomware(self, deleted_count: int) -> list:
        if deleted_count < MASS_DELETION_THRESHOLD:
            return []
        logger.critical(f"RANSOMWARE DETECTED — {deleted_count} files deleted. Emergency response initiated.")
        actions = []
        iso_action = self._isolate_network_windows() if self.is_windows else self._isolate_network_linux()
        if iso_action:
            actions.append(iso_action)
        actions.extend(self.scan_and_kill_suspicious())
        if self.file_vault:
            try:
                self.file_vault.recover_all_deleted()
                action = RemediationAction("MASS_FILE_RECOVERY", "All deleted files", True,
                    f"Emergency recovery for {deleted_count} files", "CRITICAL")
                self._record(action)
                actions.append(action)
            except Exception as e:
                logger.error(f"Mass recovery failed: {e}")
        return actions

    def _isolate_network_windows(self):
        if not self._should_act("CRITICAL"):
            return None
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Disable-NetAdapter -Confirm:$false"],
                capture_output=True, text=True, timeout=10)
            success = result.returncode == 0
            action = RemediationAction("NETWORK_ISOLATED", "All network adapters", success,
                "Network isolation activated" if success else result.stderr, "CRITICAL")
            self._record(action)
            return action
        except Exception as e:
            return None

    def _isolate_network_linux(self):
        try:
            for cmd in [["iptables","-P","INPUT","DROP"],["iptables","-P","OUTPUT","DROP"]]:
                subprocess.run(cmd, check=True)
            action = RemediationAction("NETWORK_ISOLATED", "All traffic", True,
                "iptables DROP ALL", "CRITICAL")
            self._record(action)
            return action
        except:
            return None

    # ── MAIN HANDLER ─────────────────────────────────────────

    def remediate_cve(self, cve_id: str, software: str, severity: str) -> "RemediationAction":
        """
        Handle a CVE alert based on current remediation mode.
        SMART/MANUAL: Log it, provide patch instructions, don't auto-update.
        AUTO: Attempt silent update via winget if package ID is known.
        """
        software_lower = software.lower()

        if self.mode == "manual":
            return RemediationAction(
                action_type="CVE_DETECTED",
                target=cve_id,
                success=True,
                details=f"[MANUAL] {cve_id} in {software} — no automatic action taken",
                severity=severity,
            )

        if self.mode == "auto":
            # Try to find winget package ID for this software
            winget_id = None
            for key, pkg_id in WINGET_PACKAGE_IDS.items():
                if key in software_lower:
                    winget_id = pkg_id
                    break

            if winget_id:
                try:
                    logger.info(f"  [AUTO] Attempting winget update: {winget_id}")
                    result = subprocess.run(
                        ["winget", "upgrade", "--id", winget_id,
                         "--silent", "--accept-package-agreements",
                         "--accept-source-agreements"],
                        capture_output=True, text=True, timeout=120
                    )
                    if result.returncode == 0 or "No applicable upgrade" in result.stdout:
                        success = True
                        detail  = f"winget upgrade {winget_id} — already up to date or updated"
                    else:
                        success = False
                        detail  = f"winget upgrade failed: {result.stderr[:100]}"
                    return RemediationAction(
                        action_type="CVE_AUTO_PATCHED" if success else "CVE_PATCH_FAILED",
                        target=cve_id,
                        success=success,
                        details=detail,
                        severity=severity,
                    )
                except FileNotFoundError:
                    detail = "winget not available — update manually"
                except subprocess.TimeoutExpired:
                    detail = "winget update timed out — update manually"
                except Exception as e:
                    detail = f"Auto-update error: {e}"
                return RemediationAction(
                    action_type="CVE_PATCH_FAILED",
                    target=cve_id,
                    success=False,
                    details=detail,
                    severity=severity,
                )
            else:
                # No winget mapping — give smart instructions
                return RemediationAction(
                    action_type="CVE_PATCH_REQUIRED",
                    target=cve_id,
                    success=True,
                    details=f"No auto-updater for {software} — update manually",
                    severity=severity,
                )

        # SMART mode — document it, alert user, no auto-action
        return RemediationAction(
            action_type="CVE_PATCH_REQUIRED",
            target=cve_id,
            success=True,
            details=f"[SMART] {cve_id} in {software} — patch {software} to latest version",
            severity=severity,
        )

        def process_alerts(self, alerts: list) -> list:
        """
        Main entry: process alert list, run appropriate remediation.
        KEY FIX: Always returns an action for port alerts, even if already blocked,
        so server can mark alert as resolved.
        """
        all_actions = []

        for alert in alerts:
            alert_type = alert.get("type", "")
            title      = alert.get("title", "")

            if alert_type in ("port_exposure", "critical_exposure"):
                # Extract port number from title e.g. "Dangerous port open: 445 (SMB)"
                port_match = re.search(r'\b(\d{2,5})\b', title)
                if port_match:
                    port = int(port_match.group(1))
                    if port in DANGEROUS_PORTS:
                        action = self.remediate_port(port)
                        if action:
                            all_actions.append(action)

            elif alert_type == "mass_deletion":
                count_match = re.search(r'(\d+)', alert.get("description", ""))
                count = int(count_match.group(1)) if count_match else 15
                all_actions.extend(self.respond_to_ransomware(count))

            elif alert_type == "cve_vulnerability":
                # CVE alert — handled differently per mode
                cve_id   = alert.get("data", {}).get("cve_id", alert.get("title",""))
                software = alert.get("data", {}).get("software", "Unknown")
                action   = self.remediate_cve(cve_id, software, alert.get("severity","MEDIUM"))
                if action:
                    all_actions.append(action)

            elif alert_type == "file_deleted":
                # File deletions are NOT threats — they go to File Vault for user-initiated recovery
                # Just mark the alert as resolved with FILE_MONITORED so it doesn't spam the alerts list
                target = alert.get("title", "").replace("File deleted: ", "").strip()
                if not target:
                    target = alert.get("data", {}).get("path", alert.get("target", "unknown"))
                action = RemediationAction(
                    action_type="FILE_MONITORED",
                    target=target,
                    success=True,
                    details="File deletion logged — visible in File Vault for user recovery",
                    severity="LOW",
                )
                self._record(action)
                all_actions.append(action)

        # Only scan for clearly malicious processes (not browsers/system)
        all_actions.extend(self.scan_and_kill_suspicious())
        return all_actions

    def get_summary(self) -> dict:
        successful = [a for a in self.actions_taken if a.success]
        failed     = [a for a in self.actions_taken if not a.success]
        return {
            "total_actions":   len(self.actions_taken),
            "successful":      len(successful),
            "failed":          len(failed),
            "blocked_ports":   list(self.blocked_ports),
            "killed_processes":list(self.killed_processes),
            "recent_actions":  [a.to_dict() for a in self.actions_taken[-10:]],
        }

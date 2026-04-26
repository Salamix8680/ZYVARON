"""
ZYVARON Agent Core v0.3.0
Added: recovery loop — polls server for file recovery requests from dashboard
"""

import asyncio
import logging
import os
import signal
import sys
from datetime import datetime
from pathlib import Path

from modules.system_collector import SystemCollector
from modules.file_vault import FileVault
from modules.port_scanner import PortScanner
from modules.reporter import Reporter
from modules.remediation_engine import RemediationEngine
from modules.cve_checker import CVEChecker

if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("cyberguard_agent.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("AgentCore")

DEFAULT_CONFIG = {
    "agent_id": f"agent_{os.getpid()}",
    "version": "0.3.0",
    "server_url": "http://localhost:8000",
    "local_report_dir": "./reports",
    "vault_dir": "./vault",
    "watch_paths": [
        str(Path.home() / "Documents"),
        str(Path.home() / "Desktop"),
    ],
    "watch_all_drives": False,
    "system_scan_interval":   60,
    "file_scan_interval":     60,
    "port_scan_interval":   3600,
    "snapshot_interval":    300,
    "remediation_interval":   60,
    "recovery_poll_interval": 30,
    "cve_scan_interval":   21600,  # CVE scan every 6 hours (NVD rate limits)
    "collect_system_info": True,
    "collect_files": True,
    "collect_ports": True,
    "remediation_mode": "smart",
}


class CyberGuardAgent:

    def __init__(self, config: dict = None):
        self.config   = {**DEFAULT_CONFIG, **(config or {})}
        self.agent_id = self.config["agent_id"]
        self.running  = False
        self.start_time = None

        self.system_collector = SystemCollector(self.config)
        self.file_vault       = FileVault(self.config)
        self.port_scanner     = PortScanner(self.config)
        self.reporter         = Reporter(
            agent_id=self.agent_id,
            server_url=self.config["server_url"],
        )
        self.remediator = RemediationEngine(
            file_vault=self.file_vault,
            mode=self.config["remediation_mode"],
        )
        self.cve_checker = CVEChecker(self.config)
        log.info(f"ZYVARON Agent initialized | ID: {self.agent_id}")

    async def start(self):
        self.running    = True
        self.start_time = datetime.now()

        log.info("=" * 60)
        log.info("  ZYVARON Agent STARTING")
        log.info(f"  Agent ID    : {self.agent_id}")
        log.info(f"  Version     : {self.config['version']}")
        log.info(f"  Remediation : {self.config['remediation_mode'].upper()}")
        log.info(f"  Time        : {self.start_time.isoformat()}")
        log.info("=" * 60)

        await self._initial_scan()

        tasks = [
            asyncio.create_task(self._system_monitor_loop()),
            asyncio.create_task(self._file_monitor_loop()),
            asyncio.create_task(self._port_monitor_loop()),
            asyncio.create_task(self._snapshot_loop()),
            asyncio.create_task(self._remediation_loop()),
            asyncio.create_task(self._recovery_loop()),
            asyncio.create_task(self._mode_sync_loop()),
            asyncio.create_task(self._cve_scan_loop()),  # Layer 6
        ]
        log.info("All monitoring loops started [OK]")

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            log.info("Agent tasks cancelled — shutting down.")

    async def stop(self):
        self.running = False
        log.info("ZYVARON Agent stopping...")

    # ── Initial Scan ──────────────────────────────────────────

    async def _initial_scan(self):
        log.info("Running initial full scan...")

        if self.config["collect_system_info"]:
            data = self.system_collector.collect()
            await self.reporter.send_system_report(data)
            log.info(f"  System info collected [OK] | OS: {data.get('os', {}).get('platform')}")

        if self.config["collect_files"]:
            data = self.file_vault.initial_index()
            await self.reporter.send_file_report(data)
            log.info(f"  File index built [OK] | {data.get('total_files', 0)} files indexed")
            # Take immediate snapshot so files are protected from minute 1
            try:
                snap = self.file_vault.create_snapshot(label="startup")
                log.info(f"  Startup snapshot created [OK] | {snap.get('total_files', 0)} files | ID: {snap.get('snapshot_id')}")
                await self.reporter.send_snapshot_report(snap)
            except Exception as e:
                log.warning(f"  Startup snapshot failed: {e}")

        if self.config["collect_ports"]:
            data = self.port_scanner.scan_localhost()
            await self.reporter.send_port_report(data)
            log.info(f"  Port scan done [OK] | {len(data.get('open_ports', []))} open ports found")

        await self._run_remediation_cycle()
        log.info("Initial scan complete [OK]")

    # ── Monitoring Loops ──────────────────────────────────────

    async def _system_monitor_loop(self):
        while self.running:
            await asyncio.sleep(self.config["system_scan_interval"])
            try:
                data = self.system_collector.collect()
                await self.reporter.send_system_report(data)
            except Exception as e:
                log.error(f"System monitor error: {e}")

    async def _file_monitor_loop(self):
        while self.running:
            await asyncio.sleep(self.config["file_scan_interval"])
            try:
                changes = self.file_vault.check_integrity()
                if changes["total_changes"] > 0:
                    await self.reporter.send_file_report(changes)
                    log.warning(f"File changes detected: {changes['total_changes']} change(s)")

                    deleted = [f.get("path") for f in changes.get("deleted", []) if f.get("path")]
                    if deleted:
                        log.warning(f"  {len(deleted)} deleted file(s) — user can recover via File Vault dashboard")

                    # Only trigger ransomware response for mass deletion (10+ at once)
                    if len(changes.get("deleted", [])) >= 10:
                        log.critical("RANSOMWARE SUSPECTED — mass deletion, initiating emergency response")
                        self.remediator.respond_to_ransomware(len(changes["deleted"]))
            except Exception as e:
                log.error(f"File monitor error: {e}")

    async def _port_monitor_loop(self):
        while self.running:
            await asyncio.sleep(self.config["port_scan_interval"])
            try:
                data = self.port_scanner.scan_localhost()
                await self.reporter.send_port_report(data)
                log.info(f"Port scan completed | {len(data.get('open_ports', []))} open ports")
                for port_info in data.get("open_ports", []):
                    port = port_info.get("port")
                    DANGEROUS = {445, 3389, 23, 21, 1433, 3306, 5900}
                    if port in DANGEROUS:
                        action = self.remediator.remediate_port(port)
                        if action and action.success:
                            log.info(f"  Auto-blocked: port {port}")
            except Exception as e:
                log.error(f"Port scanner error: {e}")

    async def _snapshot_loop(self):
        while self.running:
            await asyncio.sleep(self.config["snapshot_interval"])
            try:
                changes = self.file_vault.get_changes_since_last_snapshot()
                if changes > 0:
                    result = self.file_vault.create_snapshot()
                    log.info(f"Snapshot created | {result.get('files_snapped', 0)} files | ID: {result.get('snapshot_id')} | Reason: {changes} file(s) changed")
                    # Report snapshot info to server so dashboard can display it
                    await self.reporter.send_snapshot_report(result)
                else:
                    log.debug("Snapshot skipped — no file changes since last snapshot")
            except Exception as e:
                log.error(f"Snapshot error: {e}")

    async def _remediation_loop(self):
        while self.running:
            await asyncio.sleep(self.config["remediation_interval"])
            await self._run_remediation_cycle()

    # ── CVE SCAN LOOP (Layer 6) ───────────────────────────────

    async def _cve_scan_loop(self):
        """
        Runs a CVE vulnerability scan on startup, then every 6 hours.
        Scans installed software against NVD CVE database.
        Results sent to server and displayed on dashboard CVE page.
        """
        # Initial scan after a 60s delay (let agent settle first)
        await asyncio.sleep(60)
        while self.running:
            try:
                log.info("CVE vulnerability scan starting...")
                result = await self.cve_checker.run_full_scan()
                await self.reporter.send_cve_report(result)
                log.info(
                    f"CVE scan reported | {result['total_cves']} CVEs | "
                    f"Critical: {result['critical_count']} | High: {result['high_count']}"
                )
            except Exception as e:
                log.error(f"CVE scan error: {e}")
            await asyncio.sleep(self.config["cve_scan_interval"])

    # ── MODE SYNC LOOP ────────────────────────────────────────

    async def _mode_sync_loop(self):
        """
        Polls server every 30s for the mode set in the dashboard.
        Updates self.remediator.mode live — mode changes take effect within 30 seconds.
          smart  — auto-blocks ports (CRITICAL/HIGH only)
          auto   — fully autonomous: blocks ports + recovers deleted files
          manual — detect and alert only, zero automatic actions
        """
        while self.running:
            try:
                new_mode = await self.reporter.fetch_remediation_mode()
                if new_mode != self.remediator.mode:
                    old_mode = self.remediator.mode
                    self.remediator.mode = new_mode
                    log.info(f"  Mode changed: {old_mode.upper()} → {new_mode.upper()}")
            except Exception as e:
                log.debug(f"Mode sync error: {e}")
            await asyncio.sleep(30)

    async def _run_remediation_cycle(self):
        try:
            alerts = await self.reporter.fetch_alerts()
            if not alerts:
                return
            unresolved = [a for a in alerts if not a.get("resolved", False)]
            if not unresolved:
                return

            mode = self.remediator.mode
            log.info(f"Remediation check | {len(unresolved)} unresolved | Mode: {mode.upper()}")

            if mode == "manual":
                log.info("  [MANUAL MODE] Detect-only — no automatic actions")
                return

            actions = self.remediator.process_alerts(unresolved)

            for action in actions:
                if action.success:
                    log.info(f"  [FIXED] {action.action_type} | {action.target} | {action.details}")
                    await self.reporter.resolve_alert_by_type(
                        action.action_type, action.target, action.details)
                else:
                    log.warning(f"  [FAILED] {action.action_type} | {action.target}")

            if actions:
                s = self.remediator.get_summary()
                log.info(f"Remediation summary | Total: {s['total_actions']} | "
                         f"Success: {s['successful']} | Failed: {s['failed']} | "
                         f"Ports blocked: {s['blocked_ports']}")
        except Exception as e:
            log.error(f"Remediation cycle error: {e}")

    # ── FILE RECOVERY LOOP ────────────────────────────────────

    async def _recovery_loop(self):
        """
        Polls server every 30 seconds for file recovery requests.
        When dashboard user clicks RECOVER, this loop picks it up
        and restores the file from vault snapshot automatically.
        """
        while self.running:
            await asyncio.sleep(self.config["recovery_poll_interval"])
            try:
                requests = await self.reporter.poll_recovery_requests()
                if not requests:
                    continue

                # Deduplicate AND reject malformed paths in one pass
                seen_paths = set()
                valid_requests = []
                for req in requests:
                    fp = req.get("file_path", "")
                    if not fp:
                        continue
                    # Valid Windows path must have drive letter + backslash: C:\...
                    is_valid = (
                        len(fp) >= 3
                        and fp[1] == ":"
                        and fp[2] == "\\"
                    )
                    if not is_valid:
                        # Immediately mark as resolved so it stops looping
                        log.warning(f"  [INVALID PATH] Discarding malformed: {fp}")
                        await self.reporter.confirm_recovery(fp, False)
                        continue
                    if fp in seen_paths:
                        # Duplicate in same batch — mark resolved
                        await self.reporter.confirm_recovery(fp, False)
                        continue
                    seen_paths.add(fp)
                    valid_requests.append(req)

                if not valid_requests:
                    continue

                log.info(f"Recovery requests: {len(valid_requests)} valid file(s)")
                for req in valid_requests:
                    file_path = req.get("file_path")
                    log.info(f"  Recovering: {file_path}")
                    result = self.file_vault.recover_file(file_path)
                    success = result.get("success", False)
                    error   = result.get("error", "")

                    if success:
                        log.info(f"  [RECOVERED] {file_path} | Hash verified: {result.get('hash_verified')}")
                    elif "No snapshots" in error:
                        log.warning(f"  [NO SNAPSHOT] {file_path} — waiting for first snapshot (runs every 5 min)")
                        # Mark resolved so it stops looping endlessly
                        # Dashboard will re-show if file still missing after next scan
                        await self.reporter.confirm_recovery(file_path, False)
                        continue
                    else:
                        log.warning(f"  [FAILED] {file_path} | {error}")

                    await self.reporter.confirm_recovery(file_path, success)

            except Exception as e:
                log.error(f"Recovery loop error: {e}")

    # ── Status ────────────────────────────────────────────────

    def status(self) -> dict:
        uptime = (datetime.now() - self.start_time).seconds if self.start_time else 0
        return {
            "agent_id": self.agent_id,
            "running": self.running,
            "uptime_seconds": uptime,
            "version": self.config["version"],
            "remediation_mode": self.config["remediation_mode"],
            "remediation": self.remediator.get_summary(),
        }


def main():
    agent = CyberGuardAgent()

    def shutdown(sig, frame):
        log.info("Shutdown signal received")
        agent.running = False
        # Cancel all running tasks gracefully — avoids 'Event loop stopped' error
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                for task in asyncio.all_tasks(loop):
                    task.cancel()
        except Exception:
            pass

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        asyncio.run(agent.start())
    except (KeyboardInterrupt, SystemExit, asyncio.CancelledError):
        log.info("Agent tasks cancelled — shutting down cleanly.")
        log.info("Agent tasks cancelled — shutting down.")


if __name__ == "__main__":
    main()


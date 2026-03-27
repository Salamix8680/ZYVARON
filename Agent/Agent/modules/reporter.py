"""
Reporter Module — ZYVARON v0.3.0
Added: poll_recovery_requests() so agent auto-restores files requested from dashboard
"""

import json
import logging
import time
from datetime import datetime
from pathlib import Path

log = logging.getLogger("Reporter")


class Reporter:

    def __init__(self, agent_id: str, server_url: str = "http://localhost:8000"):
        self.agent_id   = agent_id
        self.server_url = server_url
        self.report_dir = Path("./reports")
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.retry_queue = []
        log.info(f"Reporter initialized | Server: {self.server_url} | Local: {self.report_dir}")

    # ── Send Methods ──────────────────────────────────────────

    async def send_system_report(self, data: dict):
        await self._send({"type": "system_info", "data": data})

    async def send_file_report(self, data: dict):
        await self._send({"type": "file_index", "data": data})

    async def send_port_report(self, data: dict):
        await self._send({"type": "port_scan", "data": data})

    async def send_snapshot_report(self, snap: dict):
        """Notify server a snapshot was created so dashboard can track count/time."""
        await self._send({"type": "snapshot", "data": {
            "snapshot_id":  snap.get("snapshot_id"),
            "total_files":  snap.get("total_files", 0),
            "created_at":   snap.get("created_at"),
            "label":        snap.get("label"),
        }})

    async def send_cve_report(self, data: dict):
        """Send CVE scan results to server."""
        try:
            import aiohttp
            payload = {"agent_id": self.agent_id, "data": data}
            async with aiohttp.ClientSession() as session:
                await session.post(
                    f"{self.server_url}/api/cve/scan",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                )
        except Exception as e:
            log.debug(f"CVE report send error: {e}")

    async def _send(self, payload: dict) -> bool:
        report = {
            "agent_id": self.agent_id,
            "sent_at": datetime.now().isoformat(),
            "type": payload.get("type", "unknown"),
            "data": payload.get("data", {}),
        }
        self._save_local(report)
        success = await self._post(f"{self.server_url}/api/agent/report", report)
        if not success:
            self.retry_queue.append(report)
        return success

    # ── Alerts ────────────────────────────────────────────────

    async def fetch_alerts(self) -> list:
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.server_url}/api/alerts/",
                    params={"device_id": self.agent_id},
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("alerts", [])
        except Exception as e:
            log.debug(f"Failed to fetch alerts: {e}")
        return []

    async def fetch_remediation_mode(self) -> str:
        """Fetch the current remediation mode set by the dashboard user."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.server_url}/api/alerts/remediation-mode",
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("mode", "smart").lower()
        except Exception as e:
            log.debug(f"Failed to fetch remediation mode: {e}")
        return "smart"  # default fallback

    async def resolve_alert_by_type(self, action_type: str, target: str, details: str):
        try:
            import aiohttp
            payload = {
                "agent_id": self.agent_id,
                "action_type": action_type,
                "target": target,
                "details": details,
                "resolved_at": datetime.utcnow().isoformat(),
            }
            async with aiohttp.ClientSession() as session:
                await session.post(
                    f"{self.server_url}/api/alerts/resolve-by-type",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=5)
                )
        except Exception as e:
            log.debug(f"Failed to resolve alert: {e}")

    # ── File Recovery ─────────────────────────────────────────

    async def poll_recovery_requests(self) -> list:
        """
        Check server for pending file recovery requests.
        Dashboard user clicked RECOVER → agent gets it here → restores file.
        """
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.server_url}/api/files/events",
                    params={"device_id": self.agent_id, "event_type": "recovery_requested"},
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        # Only return unresolved ones
                        return [e for e in data.get("events", []) if not e.get("resolved")]
        except Exception as e:
            log.debug(f"Failed to poll recovery requests: {e}")
        return []

    async def confirm_recovery(self, file_path: str, success: bool):
        """Tell server whether file recovery succeeded."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                await session.post(
                    f"{self.server_url}/api/files/recover/confirm",
                    json={
                        "device_id": self.agent_id,   # server expects device_id
                        "agent_id": self.agent_id,    # send both for compatibility
                        "file_path": file_path,
                        "success": success,
                        "confirmed_at": datetime.utcnow().isoformat(),
                    },
                    timeout=aiohttp.ClientTimeout(total=5)
                )
        except Exception as e:
            log.debug(f"Failed to confirm recovery: {e}")

    # ── Internal ──────────────────────────────────────────────

    def _save_local(self, report: dict):
        try:
            ts = int(time.time())
            filepath = self.report_dir / f"{report['type']}_{ts}.json"
            with open(filepath, "w") as f:
                json.dump(report, f, indent=2)
        except Exception as e:
            log.error(f"Local save failed: {e}")

    async def _post(self, url: str, data: dict) -> bool:
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, json=data,
                    timeout=aiohttp.ClientTimeout(total=10),
                    headers={"Content-Type": "application/json", "X-Agent-ID": self.agent_id}
                ) as resp:
                    return resp.status in (200, 201)
        except ImportError:
            return False
        except Exception as e:
            log.debug(f"POST failed: {e}")
            return False

    async def flush_retry_queue(self):
        if not self.retry_queue:
            return
        successful = []
        for report in self.retry_queue:
            if await self._post(f"{self.server_url}/api/agent/report", report):
                successful.append(report)
        for r in successful:
            self.retry_queue.remove(r)

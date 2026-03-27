"""
System Collector Module
-----------------------
Collects hardware info, OS details, running processes,
disk/storage health, and memory/CPU stats from the device.
"""

import os
import platform
import socket
import uuid
import logging
from datetime import datetime
from pathlib import Path

import psutil

log = logging.getLogger("SystemCollector")


class SystemCollector:
    """
    Collects all system information from the host device.
    Works on Linux, Windows, macOS.
    """

    def __init__(self, config: dict):
        self.config = config
        self.device_id = self._get_device_id()

    def _get_device_id(self) -> str:
        """Generate a stable unique device ID based on MAC address."""
        mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
        hostname = socket.gethostname()
        return f"{hostname}-{mac}"

    def collect(self) -> dict:
        """Run all collectors and return combined system snapshot."""
        log.debug("Collecting system information...")
        return {
            "timestamp": datetime.now().isoformat(),
            "device_id": self.device_id,
            "os": self._collect_os_info(),
            "cpu": self._collect_cpu_info(),
            "memory": self._collect_memory_info(),
            "disks": self._collect_disk_info(),
            "network_interfaces": self._collect_network_info(),
            "processes": self._collect_top_processes(),
        }

    # ── OS Info ───────────────────────────────────────────────────────────────

    def _collect_os_info(self) -> dict:
        """Collect operating system details."""
        return {
            "platform": platform.system(),              # 'Linux', 'Windows', 'Darwin'
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "hostname": socket.gethostname(),
            "python_version": platform.python_version(),
            "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            "uptime_seconds": int((datetime.now().timestamp() - psutil.boot_time())),
        }

    # ── CPU Info ──────────────────────────────────────────────────────────────

    def _collect_cpu_info(self) -> dict:
        """Collect CPU usage and specs."""
        freq = psutil.cpu_freq()
        return {
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "usage_percent": psutil.cpu_percent(interval=1),
            "per_core_usage": psutil.cpu_percent(interval=1, percpu=True),
            "frequency_mhz": {
                "current": round(freq.current, 2) if freq else None,
                "min": round(freq.min, 2) if freq else None,
                "max": round(freq.max, 2) if freq else None,
            },
            "load_avg_1m": os.getloadavg()[0] if hasattr(os, 'getloadavg') else None,
        }

    # ── Memory Info ───────────────────────────────────────────────────────────

    def _collect_memory_info(self) -> dict:
        """Collect RAM and swap usage."""
        ram = psutil.virtual_memory()
        swap = psutil.swap_memory()

        def to_gb(bytes_val):
            return round(bytes_val / (1024 ** 3), 2)

        return {
            "ram": {
                "total_gb": to_gb(ram.total),
                "available_gb": to_gb(ram.available),
                "used_gb": to_gb(ram.used),
                "percent_used": ram.percent,
            },
            "swap": {
                "total_gb": to_gb(swap.total),
                "used_gb": to_gb(swap.used),
                "percent_used": swap.percent,
            },
        }

    # ── Disk Info ─────────────────────────────────────────────────────────────

    def _collect_disk_info(self) -> list:
        """
        Collect info about every mounted disk/partition.
        Includes: usage stats + SMART-style health data where available.
        """
        disks = []

        for partition in psutil.disk_partitions(all=False):
            disk_entry = {
                "device": partition.device,
                "mountpoint": partition.mountpoint,
                "filesystem": partition.fstype,
                "usage": None,
                "io_stats": None,
                "health_warning": False,
            }

            # Usage stats
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_entry["usage"] = {
                    "total_gb": round(usage.total / (1024 ** 3), 2),
                    "used_gb": round(usage.used / (1024 ** 3), 2),
                    "free_gb": round(usage.free / (1024 ** 3), 2),
                    "percent_used": usage.percent,
                }
                # Flag if disk is getting full (>85%)
                if usage.percent > 85:
                    disk_entry["health_warning"] = True
                    disk_entry["warning_reason"] = f"Disk {usage.percent}% full"
            except PermissionError:
                disk_entry["usage"] = "permission_denied"

            # IO counters per disk
            try:
                io_counters = psutil.disk_io_counters(perdisk=True)
                device_name = Path(partition.device).name
                if device_name in io_counters:
                    io = io_counters[device_name]
                    disk_entry["io_stats"] = {
                        "read_count": io.read_count,
                        "write_count": io.write_count,
                        "read_bytes": io.read_bytes,
                        "write_bytes": io.write_bytes,
                    }
            except Exception:
                pass

            disks.append(disk_entry)

        return disks

    # ── Network Interfaces ────────────────────────────────────────────────────

    def _collect_network_info(self) -> list:
        """Collect network interface stats."""
        interfaces = []
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        io = psutil.net_io_counters(pernic=True)

        for iface_name, addr_list in addrs.items():
            iface_entry = {
                "name": iface_name,
                "is_up": stats[iface_name].isup if iface_name in stats else False,
                "speed_mbps": stats[iface_name].speed if iface_name in stats else 0,
                "addresses": [],
                "bytes_sent": io[iface_name].bytes_sent if iface_name in io else 0,
                "bytes_recv": io[iface_name].bytes_recv if iface_name in io else 0,
            }

            for addr in addr_list:
                iface_entry["addresses"].append({
                    "family": str(addr.family),
                    "address": addr.address,
                    "netmask": addr.netmask,
                })

            interfaces.append(iface_entry)

        return interfaces

    # ── Process Info ──────────────────────────────────────────────────────────

    def _collect_top_processes(self, top_n: int = 10) -> list:
        """Collect top N processes by CPU usage. Flags suspicious ones."""
        processes = []

        SUSPICIOUS_NAMES = {
            "mimikatz", "netcat", "nc", "ncat", "meterpreter",
            "cryptominer", "xmrig", "minerd",
        }

        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username', 'status']):
            try:
                info = proc.info
                info["suspicious"] = info.get("name", "").lower() in SUSPICIOUS_NAMES
                processes.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # Sort by CPU usage descending, return top N
        processes.sort(key=lambda x: x.get("cpu_percent", 0), reverse=True)
        return processes[:top_n]

    def get_storage_devices(self) -> list:
        """
        Return just the storage devices — used by FileVault
        to know what drives to scan and protect.
        """
        devices = []
        for partition in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                devices.append({
                    "mountpoint": partition.mountpoint,
                    "device": partition.device,
                    "filesystem": partition.fstype,
                    "total_gb": round(usage.total / (1024 ** 3), 2),
                    "free_gb": round(usage.free / (1024 ** 3), 2),
                })
            except Exception:
                continue
        return devices

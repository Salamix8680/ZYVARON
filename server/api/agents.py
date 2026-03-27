"""
Agent API — ZYVARON v0.2.0
Receives all data from agent: system info, port scans, file events.
Deduplicates devices by hostname so restarts don't create ghost devices.
Deduplicates alerts so same threat never appears twice.
"""

from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Any

from db.database import get_db, Device, SystemReport, PortScanReport, FileEvent, Alert
from services.alert_engine import AlertEngine

router = APIRouter()


class ReportPayload(BaseModel):
    agent_id: str
    sent_at: str
    type: str
    data: dict[str, Any]


@router.post("/report")
def receive_report(payload: ReportPayload, db: Session = Depends(get_db)):
    agent_id  = payload.agent_id
    report_type = payload.type
    data      = payload.data

    # Register / update device — keyed by HOSTNAME not agent_id
    # This prevents duplicate devices on every restart
    _upsert_device(agent_id, data, db)

    alerts = []
    if report_type == "system_info":
        _store_system_report(agent_id, data, db)
        alerts = AlertEngine.check_system(agent_id, data)
    elif report_type == "port_scan":
        _store_port_scan(agent_id, data, db)
        alerts = AlertEngine.check_ports(agent_id, data)
    elif report_type in ("file_index", "file_changes"):
        _store_file_events(agent_id, data, db)
        alerts = AlertEngine.check_files(agent_id, data)
        # Update indexed_files count on device
        if report_type == "file_index":
            device = db.query(Device).filter(Device.id == agent_id).first()
            if device:
                device.indexed_files = data.get("total_files", 0)
    elif report_type == "snapshot":
        # Store snapshot as a FileEvent so dashboard can count snapshots and show last time
        snap_id = data.get("snapshot_id", "")
        created = data.get("created_at")
        # Avoid duplicate snapshot records
        existing_snap = db.query(FileEvent).filter(
            FileEvent.device_id  == agent_id,
            FileEvent.event_type == "snapshot",
            FileEvent.file_path  == snap_id,
        ).first()
        if not existing_snap:
            db.add(FileEvent(
                device_id   = agent_id,
                event_type  = "snapshot",
                file_path   = snap_id,
                severity    = "LOW",
                resolved    = True,   # snapshots are always "resolved" — not actionable
            ))
        db.commit()
        return {"status": "received", "type": "snapshot"}

    # Deduplicate: only insert alert if same alert type hasn't fired recently
    # Cooldown prevents CPU/RAM alerts re-firing every 60s after being resolved
    new_alerts = 0
    from datetime import timedelta
    COOLDOWN_MINUTES = {
        "high_cpu": 10,       # CPU alert: wait 10 min before re-alerting
        "high_memory": 10,    # RAM alert: wait 10 min
        "disk_full": 30,      # Disk: wait 30 min
        "port_exposure": 0,   # Ports: always alert (they need fixing)
        "critical_exposure": 0,
        "file_deleted": 0,    # File events: always alert
        "mass_deletion": 0,
        "suspicious_process": 5,
    }
    for alert_data in alerts:
        alert_type = alert_data["type"]
        cooldown = COOLDOWN_MINUTES.get(alert_type, 5)

        # Check for any existing unresolved alert of same type
        existing_unresolved = db.query(Alert).filter(
            Alert.device_id == agent_id,
            Alert.alert_type == alert_type,
            Alert.title == alert_data["title"],
            Alert.resolved == False,
        ).first()
        if existing_unresolved:
            continue  # Already active, don't duplicate

        # For system metric alerts: also check if same type was recently resolved (cooldown)
        if cooldown > 0:
            cutoff = datetime.utcnow() - timedelta(minutes=cooldown)
            recently_resolved = db.query(Alert).filter(
                Alert.device_id == agent_id,
                Alert.alert_type == alert_type,
                Alert.resolved == True,
                Alert.resolved_at >= cutoff,
            ).first()
            if recently_resolved:
                continue  # Recently resolved, in cooldown — skip

        auto_resolve = alert_data.get("auto_resolve", False)
        alert = Alert(
            device_id=agent_id,
            alert_type=alert_data["type"],
            severity=alert_data["severity"],
            title=alert_data["title"],
            description=alert_data["description"],
            data=alert_data.get("data", {}),
        )
        if auto_resolve:
            # Port already blocked by ZYVARON — store as resolved immediately
            alert.resolved    = True
            alert.resolved_at = datetime.utcnow()
        db.add(alert)
        new_alerts += 1

    db.commit()
    return {"status": "received", "type": report_type, "alerts_generated": new_alerts}


@router.get("/ping")
def ping(agent_id: str, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == agent_id).first()
    if device:
        device.last_seen = datetime.utcnow()
        device.is_active = True
        db.commit()
    return {"status": "pong", "server_time": datetime.utcnow().isoformat()}


def _upsert_device(agent_id: str, data: dict, db: Session):
    """
    Upsert device keyed by HOSTNAME — not agent_id.
    This means restarting the agent (new PID = new agent_id)
    won't create a duplicate device entry.
    """
    os_data      = data.get("os", {})
    hostname     = os_data.get("hostname") or agent_id
    platform     = os_data.get("platform", "unknown")
    architecture = os_data.get("architecture", "unknown")

    # Look up by hostname first
    device = db.query(Device).filter(Device.hostname == hostname).first()

    if not device:
        # Also try by agent_id for backward compatibility
        device = db.query(Device).filter(Device.id == agent_id).first()

    if not device:
        device = Device(
            id=agent_id,
            hostname=hostname,
            platform=platform,
            architecture=architecture,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            is_active=True,
        )
        db.add(device)
    else:
        # Update the existing device record with the new agent_id
        device.id           = agent_id
        device.last_seen    = datetime.utcnow()
        device.hostname     = hostname
        device.is_active    = True
        device.platform     = platform or device.platform
        device.architecture = architecture or device.architecture


def _store_system_report(agent_id: str, data: dict, db: Session):
    cpu  = data.get("cpu", {})
    mem  = data.get("memory", {}).get("ram", {})
    os_i = data.get("os", {})
    db.add(SystemReport(
        device_id     = agent_id,
        cpu_cores     = cpu.get("logical_cores"),
        cpu_usage     = cpu.get("usage_percent"),
        ram_total_gb  = mem.get("total_gb"),
        ram_used_gb   = mem.get("used_gb"),
        ram_percent   = mem.get("percent_used"),
        os_platform   = os_i.get("platform"),
        os_release    = os_i.get("platform_release"),
        hostname      = os_i.get("hostname"),
        uptime_seconds= os_i.get("uptime_seconds"),
        raw_data      = data,
    ))


def _store_port_scan(agent_id: str, data: dict, db: Session):
    db.add(PortScanReport(
        device_id         = agent_id,
        target            = data.get("target"),
        ports_scanned     = data.get("ports_scanned"),
        total_open        = data.get("total_open"),
        risk_score        = data.get("risk_score"),
        critical_exposures= data.get("critical_exposures"),
        status            = data.get("status"),
        open_ports        = data.get("open_ports", []),
        scan_duration     = data.get("scan_duration_seconds"),
    ))
    device = db.query(Device).filter(Device.id == agent_id).first()
    if device:
        device.risk_score = min(data.get("risk_score", 0), 100)


def _store_file_events(agent_id: str, data: dict, db: Session):
    for f in data.get("modified", []):
        db.add(FileEvent(device_id=agent_id, event_type="modified",
            file_path=f.get("path"), severity=f.get("severity","MEDIUM"),
            original_hash=f.get("original_hash"), current_hash=f.get("current_hash")))

    for f in data.get("deleted", []):
        path = f.get("path")
        if not path:
            continue
        # Only insert deleted event if this file isn't already tracked as unresolved deleted
        existing = db.query(FileEvent).filter(
            FileEvent.device_id  == agent_id,
            FileEvent.file_path  == path,
            FileEvent.event_type == "deleted",
            FileEvent.resolved   == False,
        ).first()
        if not existing:
            db.add(FileEvent(device_id=agent_id, event_type="deleted",
                file_path=path, severity=f.get("severity","HIGH"),
                original_hash=f.get("original_hash")))

    for f in data.get("new_files", []):
        path = f.get("path")
        if not path:
            continue
        # If this file was previously tracked as deleted and now exists again, resolve it
        old_del = db.query(FileEvent).filter(
            FileEvent.device_id  == agent_id,
            FileEvent.file_path  == path,
            FileEvent.event_type == "deleted",
            FileEvent.resolved   == False,
        ).first()
        if old_del:
            old_del.resolved = True  # File came back (manually restored)
        db.add(FileEvent(device_id=agent_id, event_type="new",
            file_path=path, severity="LOW"))


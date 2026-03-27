"""
Devices API
-----------
GET  /api/devices/             — list all devices
GET  /api/devices/{id}/summary — full device summary
DELETE /api/devices/{id}       — remove a device
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime

from db.database import get_db, Device, SystemReport, PortScanReport, FileEvent, Alert

router = APIRouter()


@router.get("/")
def list_devices(db: Session = Depends(get_db)):
    devices = db.query(Device).order_by(Device.last_seen.desc()).all()
    now = datetime.utcnow()
    result = []
    for d in devices:
        last_seen = d.last_seen or d.first_seen
        online = (now - last_seen).seconds < 300 if last_seen else False
        # Count indexed files for this device
        indexed_files = db.query(FileEvent).filter(
            FileEvent.device_id == d.id,
            FileEvent.event_type == "new"
        ).count()
        # Also check initial index report
        total_indexed = db.query(FileEvent).filter(
            FileEvent.device_id == d.id
        ).count()
        result.append({
            "id": d.id, "hostname": d.hostname, "platform": d.platform,
            "architecture": d.architecture, "risk_score": d.risk_score,
            "online": online,
            "indexed_files": d.indexed_files or 0,
            "first_seen": d.first_seen.isoformat() if d.first_seen else None,
            "last_seen": d.last_seen.isoformat() if d.last_seen else None,
        })
    return {"total": len(result), "devices": result}


@router.get("/{device_id}/summary")
def get_device_summary(device_id: str, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    latest_system = db.query(SystemReport).filter(
        SystemReport.device_id == device_id).order_by(
        SystemReport.reported_at.desc()).first()

    latest_ports = db.query(PortScanReport).filter(
        PortScanReport.device_id == device_id).order_by(
        PortScanReport.scanned_at.desc()).first()

    alerts = db.query(Alert).filter(
        Alert.device_id == device_id, Alert.resolved == False).order_by(
        Alert.created_at.desc()).limit(10).all()

    file_events = db.query(FileEvent).filter(
        FileEvent.device_id == device_id).order_by(
        FileEvent.detected_at.desc()).limit(10).all()

    return {
        "device": {
            "id": device.id, "hostname": device.hostname,
            "platform": device.platform, "architecture": device.architecture,
            "risk_score": device.risk_score,
            "first_seen": device.first_seen.isoformat() if device.first_seen else None,
            "last_seen": device.last_seen.isoformat() if device.last_seen else None,
        },
        "system": {
            "cpu_usage": latest_system.cpu_usage if latest_system else None,
            "ram_percent": latest_system.ram_percent if latest_system else None,
            "ram_total_gb": latest_system.ram_total_gb if latest_system else None,
            "os": f"{latest_system.os_platform} {latest_system.os_release}" if latest_system else None,
            "uptime_seconds": latest_system.uptime_seconds if latest_system else None,
        },
        "ports": {
            "total_open": latest_ports.total_open if latest_ports else 0,
            "critical_exposures": latest_ports.critical_exposures if latest_ports else 0,
            "risk_score": latest_ports.risk_score if latest_ports else 0,
            "status": latest_ports.status if latest_ports else "UNKNOWN",
            "open_ports": latest_ports.open_ports if latest_ports else [],
        },
        "alerts": [{"id": a.id, "type": a.alert_type, "severity": a.severity,
            "title": a.title, "description": a.description,
            "created_at": a.created_at.isoformat()} for a in alerts],
        "file_events": [{"id": f.id, "type": f.event_type, "path": f.file_path,
            "severity": f.severity, "detected_at": f.detected_at.isoformat()} for f in file_events],
    }


@router.delete("/{device_id}")
def remove_device(device_id: str, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    db.delete(device)
    db.commit()
    return {"status": "removed", "device_id": device_id}

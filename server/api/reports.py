"""Reports API"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from db.database import get_db, SystemReport, PortScanReport, FileEvent

router = APIRouter()

@router.get("/system/{device_id}")
def get_system_history(device_id: str, limit: int = Query(default=24, le=100), db: Session = Depends(get_db)):
    reports = db.query(SystemReport).filter(SystemReport.device_id == device_id).order_by(SystemReport.reported_at.desc()).limit(limit).all()
    return {"device_id": device_id, "count": len(reports),
        "reports": [{"reported_at": r.reported_at.isoformat(), "cpu_usage": r.cpu_usage,
            "ram_percent": r.ram_percent, "ram_total_gb": r.ram_total_gb} for r in reports]}

@router.get("/ports/{device_id}")
def get_port_history(device_id: str, limit: int = Query(default=10, le=50), db: Session = Depends(get_db)):
    reports = db.query(PortScanReport).filter(PortScanReport.device_id == device_id).order_by(PortScanReport.scanned_at.desc()).limit(limit).all()
    return {"device_id": device_id, "count": len(reports),
        "scans": [{"scanned_at": r.scanned_at.isoformat(), "total_open": r.total_open,
            "critical_exposures": r.critical_exposures, "risk_score": r.risk_score,
            "status": r.status, "open_ports": r.open_ports} for r in reports]}

@router.get("/files/{device_id}")
def get_file_events(device_id: str, event_type: str = Query(default=None), limit: int = Query(default=50, le=200), db: Session = Depends(get_db)):
    query = db.query(FileEvent).filter(FileEvent.device_id == device_id)
    if event_type:
        query = query.filter(FileEvent.event_type == event_type)
    events = query.order_by(FileEvent.detected_at.desc()).limit(limit).all()
    return {"device_id": device_id, "count": len(events),
        "events": [{"id": e.id, "type": e.event_type, "path": e.file_path,
            "severity": e.severity, "detected_at": e.detected_at.isoformat()} for e in events]}
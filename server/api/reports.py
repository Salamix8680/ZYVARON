"""
Reports API
-----------
GET /api/reports/system/{device_id}    — system history
GET /api/reports/ports/{device_id}     — port scan history
GET /api/reports/files/{device_id}     — file events
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from db.database import get_db, SystemReport, PortScanReport, FileEvent

router = APIRouter()


@router.get("/system/{device_id}")
async def get_system_history(
    device_id: str,
    limit: int = Query(default=24, le=100),
    db: AsyncSession = Depends(get_db)
):
    """Get system metric history for a device — good for charts."""
    result = db.execute(
        select(SystemReport)
        .where(SystemReport.device_id == device_id)
        .order_by(desc(SystemReport.reported_at))
        .limit(limit)
    )
    reports = result.scalars().all()
    return {
        "device_id": device_id,
        "count": len(reports),
        "reports": [
            {
                "reported_at": r.reported_at.isoformat(),
                "cpu_usage": r.cpu_usage,
                "ram_percent": r.ram_percent,
                "ram_total_gb": r.ram_total_gb,
                "uptime_seconds": r.uptime_seconds,
            }
            for r in reports
        ]
    }


@router.get("/ports/{device_id}")
async def get_port_history(
    device_id: str,
    limit: int = Query(default=10, le=50),
    db: AsyncSession = Depends(get_db)
):
    """Get port scan history for a device."""
    result = db.execute(
        select(PortScanReport)
        .where(PortScanReport.device_id == device_id)
        .order_by(desc(PortScanReport.scanned_at))
        .limit(limit)
    )
    reports = result.scalars().all()
    return {
        "device_id": device_id,
        "count": len(reports),
        "scans": [
            {
                "scanned_at": r.scanned_at.isoformat(),
                "total_open": r.total_open,
                "critical_exposures": r.critical_exposures,
                "risk_score": r.risk_score,
                "status": r.status,
                "open_ports": r.open_ports,
            }
            for r in reports
        ]
    }


@router.get("/files/{device_id}")
async def get_file_events(
    device_id: str,
    event_type: str = Query(default=None),
    limit: int = Query(default=50, le=200),
    db: AsyncSession = Depends(get_db)
):
    """Get file change events for a device."""
    query = select(FileEvent).where(FileEvent.device_id == device_id)
    if event_type:
        query = query.where(FileEvent.event_type == event_type)
    query = query.order_by(desc(FileEvent.detected_at)).limit(limit)

    result = db.execute(query)
    events = result.scalars().all()
    return {
        "device_id": device_id,
        "count": len(events),
        "events": [
            {
                "id": e.id,
                "type": e.event_type,
                "path": e.file_path,
                "severity": e.severity,
                "detected_at": e.detected_at.isoformat(),
                "resolved": e.resolved,
            }
            for e in events
        ]
    }

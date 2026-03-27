"""
File Vault API — ZYVARON v0.3.0
- Exposes file events, deleted files list, and recovery endpoint
- Auto-cleans malformed/stale recovery requests on startup
- Returns correct timestamps
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from db.database import get_db, FileEvent, Device

router = APIRouter()


@router.get("/events")
def get_file_events(device_id: str = None, event_type: str = None,
                    limit: int = 100, db: Session = Depends(get_db)):
    q = db.query(FileEvent)
    if device_id:
        q = q.filter(FileEvent.device_id == device_id)
    if event_type:
        q = q.filter(FileEvent.event_type == event_type)
    # Only return unresolved recovery requests
    if event_type == "recovery_requested":
        q = q.filter(FileEvent.resolved == False)
    events = q.order_by(FileEvent.detected_at.desc()).limit(limit).all()
    return {"total": len(events), "events": [_s(e) for e in events]}


@router.get("/deleted")
def get_deleted_files(device_id: str = None, db: Session = Depends(get_db)):
    """Get deleted files that haven't been recovered. Auto-purges malformed paths."""
    q = db.query(FileEvent).filter(
        FileEvent.event_type == "deleted",
        FileEvent.resolved == False,
    )
    if device_id:
        q = q.filter(FileEvent.device_id == device_id)
    events = q.order_by(FileEvent.detected_at.desc()).all()

    # Filter out malformed paths (missing backslash after drive letter)
    valid = []
    for e in events:
        path = e.file_path or ""
        # Valid Windows path: C:\... — invalid: C:Users... (missing backslash)
        if "\\" in path and (len(path) > 3 and path[1] == ":" and path[2] == "\\"):
            valid.append(e)
        else:
            # Auto-resolve malformed entries
            e.resolved = True
    db.commit()

    return {"total": len(valid), "deleted_files": [_s(e) for e in valid]}


@router.get("/stats")
def get_file_stats(db: Session = Depends(get_db)):
    total     = db.query(FileEvent).count()
    deleted   = db.query(FileEvent).filter(FileEvent.event_type == "deleted",            FileEvent.resolved == False).count()
    modified  = db.query(FileEvent).filter(FileEvent.event_type == "modified").count()
    recovered = db.query(FileEvent).filter(FileEvent.event_type == "recovered").count()
    new_files = db.query(FileEvent).filter(FileEvent.event_type == "new").count()
    # Snapshot count = number of "snapshot" events logged by agent
    snapshots = db.query(FileEvent).filter(FileEvent.event_type == "snapshot").order_by(FileEvent.detected_at.desc()).all()
    last_snap = snapshots[0].detected_at.isoformat() if snapshots else None
    # Count total unique files being monitored (from new + modified events)
    total_indexed = db.query(FileEvent.file_path).distinct().count()
    return {
        "total_events": total,
        "total_indexed": total_indexed,
        "deleted_unrecovered": deleted,
        "modified": modified,
        "recovered": recovered,
        "new_files": new_files,
        "snapshots_count": len(snapshots),
        "last_snapshot": last_snap,
    }


@router.post("/recover")
def recover_file(payload: dict, db: Session = Depends(get_db)):
    file_path = payload.get("file_path")
    device_id = payload.get("device_id")
    snapshot_id = payload.get("snapshot_id")

    if not file_path or not device_id:
        return {"success": False, "error": "file_path and device_id required"}

    # Validate path format
    if "\\" not in file_path:
        return {"success": False, "error": f"Invalid path format: {file_path}"}

    # Mark the deleted event as being actioned
    event = db.query(FileEvent).filter(
        FileEvent.device_id == device_id,
        FileEvent.file_path == file_path,
        FileEvent.event_type == "deleted",
        FileEvent.resolved == False,
    ).first()
    if event:
        event.resolved = True
        db.commit()

    # Check if recovery already requested (prevent duplicates)
    existing = db.query(FileEvent).filter(
        FileEvent.device_id == device_id,
        FileEvent.file_path == file_path,
        FileEvent.event_type == "recovery_requested",
        FileEvent.resolved == False,
    ).first()
    if existing:
        return {
            "success": True,
            "file_path": file_path,
            "message": "Recovery already queued — agent will restore file within 30 seconds",
        }

    recovery_event = FileEvent(
        device_id=device_id,
        event_type="recovery_requested",
        file_path=file_path,
        severity="LOW",
        resolved=False,
    )
    db.add(recovery_event)
    db.commit()

    return {
        "success": True,
        "file_path": file_path,
        "device_id": device_id,
        "snapshot_id": snapshot_id,
        "message": "Recovery queued — agent will restore file within 30 seconds",
        "queued_at": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/recover/confirm")
def confirm_recovery(payload: dict, db: Session = Depends(get_db)):
    file_path = payload.get("file_path")
    device_id = payload.get("device_id") or payload.get("agent_id")
    success   = payload.get("success", False)

    # Mark ALL pending recovery requests for this file as resolved
    events = db.query(FileEvent).filter(
        FileEvent.file_path == file_path,
        FileEvent.event_type == "recovery_requested",
        FileEvent.resolved == False,
    ).all()

    for event in events:
        event.resolved = True
        event.event_type = "recovered" if success else "recovery_failed"
    db.commit()

    return {"status": "confirmed", "success": success, "cleared": len(events)}


@router.delete("/cleanup")
def cleanup_stale(db: Session = Depends(get_db)):
    """Remove all malformed or stale recovery requests."""
    stale = db.query(FileEvent).filter(
        FileEvent.event_type == "recovery_requested",
        FileEvent.resolved == False,
    ).all()
    count = 0
    for e in stale:
        path = e.file_path or ""
        if "\\" not in path or not (len(path) > 3 and path[1] == ":" and path[2] == "\\"):
            e.resolved = True
            count += 1
    db.commit()
    return {"cleaned": count}


def _s(e):
    return {
        "id": e.id,
        "device_id": e.device_id,
        "event_type": e.event_type,
        "file_path": e.file_path,
        "severity": e.severity,
        "original_hash": e.original_hash,
        "detected_at": e.detected_at.isoformat() if e.detected_at else None,
        "resolved": e.resolved,
    }


@router.post("/cleanup-stale")
def cleanup_stale_deleted(db: Session = Depends(get_db)):
    """
    Resolve duplicate deleted FileEvents — keep only the most recent per file path.
    Call this once after upgrading to clear old duplicate entries.
    """
    from sqlalchemy import func

    # Get all unresolved deleted events grouped by file_path
    deleted_events = db.query(FileEvent).filter(
        FileEvent.event_type == "deleted",
        FileEvent.resolved == False,
    ).order_by(FileEvent.file_path, FileEvent.detected_at.desc()).all()

    # Keep only the newest per path, resolve the rest
    seen = {}
    resolved_count = 0
    for event in deleted_events:
        path = event.file_path
        if path not in seen:
            seen[path] = event  # keep this one
        else:
            event.resolved = True  # resolve the duplicate
            resolved_count += 1

    db.commit()
    return {"cleaned": resolved_count, "unique_paths": len(seen)}

"""Alerts API"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from datetime import datetime
from db.database import get_db, Alert

router = APIRouter()


@router.get("/")
def get_alerts(resolved: bool = Query(default=False), limit: int = Query(default=100), db: Session = Depends(get_db)):
    alerts = db.query(Alert).filter(Alert.resolved == resolved, Alert.alert_type != "cve_vulnerability").order_by(Alert.created_at.desc()).limit(limit).all()
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        counts[a.severity] = counts.get(a.severity, 0) + 1
    return {"total": len(alerts), "severity_counts": counts, "alerts": [_s(a) for a in alerts]}


@router.get("/all")
def get_all_alerts(limit: int = Query(default=200), db: Session = Depends(get_db)):
    all_alerts = db.query(Alert).filter(Alert.alert_type != "cve_vulnerability").order_by(Alert.created_at.desc()).limit(limit).all()
    active = [a for a in all_alerts if not a.resolved]
    resolved = [a for a in all_alerts if a.resolved]
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in active:
        counts[a.severity] = counts.get(a.severity, 0) + 1
    return {
        "total_active": len(active),
        "total_resolved": len(resolved),
        "severity_counts": counts,
        "active_alerts": [_s(a) for a in active],
        "resolved_alerts": [_s(a) for a in resolved],
    }


@router.get("/stats")
def get_alert_stats(db: Session = Depends(get_db)):
    total    = db.query(Alert).filter(Alert.alert_type != "cve_vulnerability").count()
    active   = db.query(Alert).filter(Alert.alert_type != "cve_vulnerability", Alert.resolved == False).count()
    resolved = db.query(Alert).filter(Alert.alert_type != "cve_vulnerability", Alert.resolved == True).count()
    return {"total": total, "active": active, "resolved": resolved}


@router.get("/device/{device_id}")
def get_device_alerts(device_id: str, resolved: bool = Query(default=False), db: Session = Depends(get_db)):
    alerts = db.query(Alert).filter(Alert.device_id == device_id, Alert.resolved == resolved).order_by(Alert.created_at.desc()).all()
    return {"device_id": device_id, "total": len(alerts), "alerts": [_s(a) for a in alerts]}


@router.post("/resolve-by-type")
def resolve_by_type(payload: dict, db: Session = Depends(get_db)):
    agent_id    = payload.get("agent_id")
    action_type = payload.get("action_type", "")
    target      = payload.get("target", "")

    # Map remediation action types to alert types they resolve
    ACTION_TO_ALERT = {
        "PORT_BLOCKED":   ["port_exposure", "critical_exposure"],
        "FILE_MONITORED": ["file_deleted"],
        "FILE_RECOVERED": ["file_deleted"],
        "RANSOMWARE_RESPONSE": ["mass_deletion", "mass_modification"],
        "PROCESS_KILLED": ["suspicious_process"],
    }
    # Resolve only the specific alert types this action fixes
    resolvable_types = ACTION_TO_ALERT.get(action_type, [])

    if resolvable_types:
        # Resolve matching unresolved alerts for this agent
        q = db.query(Alert).filter(
            Alert.device_id == agent_id,
            Alert.resolved  == False,
            Alert.alert_type.in_(resolvable_types),
        )
        # If target specified, try to match by title/description
        alerts = q.all()
        resolved_count = 0
        for alert in alerts:
            # For port alerts, match specific port number
            if action_type == "PORT_BLOCKED" and target and str(target) not in alert.title:
                continue
            alert.resolved    = True
            alert.resolved_at = datetime.utcnow()
            resolved_count   += 1
        db.commit()
    else:
        # Fallback: resolve all unresolved for backward compat
        alerts = db.query(Alert).filter(
            Alert.device_id == agent_id, Alert.resolved == False
        ).all()
        resolved_count = 0
        for alert in alerts:
            alert.resolved    = True
            alert.resolved_at = datetime.utcnow()
            resolved_count   += 1
        db.commit()

    return {"status": "ok", "resolved": resolved_count, "action_type": action_type}


@router.post("/{alert_id}/resolve")
def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert:
        alert.resolved = True
        alert.resolved_at = datetime.utcnow()
        db.commit()
    return {"status": "resolved", "alert_id": alert_id}


def _s(a):
    return {
        "id": a.id, "device_id": a.device_id, "type": a.alert_type,
        "severity": a.severity, "title": a.title, "description": a.description,
        "created_at": a.created_at.isoformat(), "resolved": a.resolved,
        "resolved_at": a.resolved_at.isoformat() if getattr(a, "resolved_at", None) else None,
    }


# ── Remediation Mode API ──────────────────────────────────────────────────────
_remediation_mode = {"mode": "smart"}  # in-memory store (resets on server restart)

@router.get("/remediation-mode")
def get_remediation_mode():
    return _remediation_mode

@router.post("/remediation-mode")
def set_remediation_mode(payload: dict):
    mode = payload.get("mode", "smart").lower()
    if mode not in ("smart", "auto", "manual"):
        return {"error": "Mode must be smart, auto, or manual"}
    _remediation_mode["mode"] = mode
    return {"status": "ok", "mode": mode}

"""
CVE API — ZYVARON Layer 6
CVEs are stored ONLY in cve_scans/cve_entries tables.
They do NOT create Alert records and do NOT affect the security overview.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional
from db.database import get_db, CVEScan, CVEEntry

router = APIRouter()


# ── Receive CVE scan from agent ───────────────────────────────────────────────
@router.post("/scan")
def receive_cve_scan(payload: dict, db: Session = Depends(get_db)):
    agent_id = payload.get("agent_id")
    data     = payload.get("data", {})
    if not agent_id or not data:
        return {"error": "missing agent_id or data"}

    scan = CVEScan(
        device_id      = agent_id,
        scanned_at     = datetime.utcnow(),
        apps_scanned   = data.get("apps_scanned", 0),
        apps_total     = data.get("apps_total", 0),
        total_cves     = data.get("total_cves", 0),
        critical_count = data.get("critical_count", 0),
        high_count     = data.get("high_count", 0),
        medium_count   = data.get("medium_count", 0),
        cves           = data.get("cves", []),
        software_list  = data.get("software_list", []),
    )
    db.add(scan)
    db.flush()

    new_cves = 0
    for cve in data.get("cves", []):
        cve_id = cve.get("cve_id")
        if not cve_id:
            continue
        existing = db.query(CVEEntry).filter(
            CVEEntry.device_id == agent_id,
            CVEEntry.cve_id    == cve_id,
            CVEEntry.resolved  == False,
        ).first()
        if not existing:
            db.add(CVEEntry(
                device_id   = agent_id,
                scan_id     = scan.id,
                cve_id      = cve_id,
                software    = cve.get("software", ""),
                version     = cve.get("version", ""),
                score       = cve.get("score", 0.0),
                severity    = cve.get("severity", "MEDIUM"),
                description = cve.get("description", ""),
                published   = cve.get("published", ""),
                url         = cve.get("url", ""),
            ))
            new_cves += 1

    db.commit()
    return {"status": "received", "scan_id": scan.id, "new_cves": new_cves}


# ── Latest scan ───────────────────────────────────────────────────────────────
@router.get("/latest")
def get_latest_scan(
    device_id: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    q = db.query(CVEScan).order_by(CVEScan.scanned_at.desc())
    if device_id:
        q = q.filter(CVEScan.device_id == device_id)
    scan = q.first()
    if not scan:
        return {"scan": None, "cves": [], "software": []}
    return {
        "scan":     _scan_dict(scan),
        "cves":     scan.cves or [],
        "software": scan.software_list or [],
    }


# ── CVE entries ───────────────────────────────────────────────────────────────
@router.get("/entries")
def get_cve_entries(
    device_id: Optional[str] = Query(None),
    severity:  Optional[str] = Query(None),
    resolved:  bool          = Query(default=False),
    limit:     int           = Query(default=100),
    db: Session = Depends(get_db)
):
    q = db.query(CVEEntry).filter(CVEEntry.resolved == resolved)
    if device_id:
        q = q.filter(CVEEntry.device_id == device_id)
    if severity:
        q = q.filter(CVEEntry.severity == severity.upper())
    entries = q.order_by(CVEEntry.score.desc()).limit(limit).all()
    return {"entries": [_entry_dict(e) for e in entries], "total": len(entries)}


# ── Scan history ──────────────────────────────────────────────────────────────
@router.get("/history")
def get_scan_history(
    device_id: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    q = db.query(CVEScan).order_by(CVEScan.scanned_at.desc()).limit(10)
    if device_id:
        q = q.filter(CVEScan.device_id == device_id)
    return {"scans": [_scan_dict(s) for s in q.all()]}


# ── Mark CVE as patched ───────────────────────────────────────────────────────
@router.post("/resolve/{cve_id}")
def resolve_cve(
    cve_id:    str,
    device_id: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    q = db.query(CVEEntry).filter(
        CVEEntry.cve_id   == cve_id,
        CVEEntry.resolved == False,
    )
    if device_id:
        q = q.filter(CVEEntry.device_id == device_id)
    entries = q.all()
    for e in entries:
        e.resolved = True
    db.commit()
    return {"status": "resolved", "cve_id": cve_id, "resolved": len(entries)}


# ── Summary stats ─────────────────────────────────────────────────────────────
@router.get("/summary")
def get_cve_summary(
    device_id: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    q = db.query(CVEEntry).filter(CVEEntry.resolved == False)
    if device_id:
        q = q.filter(CVEEntry.device_id == device_id)
    entries = q.all()

    sq = db.query(CVEScan).order_by(CVEScan.scanned_at.desc())
    if device_id:
        sq = sq.filter(CVEScan.device_id == device_id)
    last_scan = sq.first()

    return {
        "total":        len(entries),
        "critical":     sum(1 for e in entries if e.severity == "CRITICAL"),
        "high":         sum(1 for e in entries if e.severity == "HIGH"),
        "medium":       sum(1 for e in entries if e.severity == "MEDIUM"),
        "low":          sum(1 for e in entries if e.severity == "LOW"),
        "last_scan":    last_scan.scanned_at.isoformat() if last_scan else None,
        "apps_scanned": last_scan.apps_scanned if last_scan else 0,
    }


# ── Serialisers ───────────────────────────────────────────────────────────────
def _scan_dict(s):
    return {
        "id":             s.id,
        "device_id":      s.device_id,
        "scanned_at":     s.scanned_at.isoformat() if s.scanned_at else None,
        "apps_scanned":   s.apps_scanned,
        "apps_total":     s.apps_total,
        "total_cves":     s.total_cves,
        "critical_count": s.critical_count,
        "high_count":     s.high_count,
        "medium_count":   s.medium_count,
    }

def _entry_dict(e):
    return {
        "id":          e.id,
        "device_id":   e.device_id,
        "scan_id":     e.scan_id,
        "cve_id":      e.cve_id,
        "software":    e.software,
        "version":     e.version,
        "score":       e.score,
        "severity":    e.severity,
        "description": e.description,
        "published":   e.published,
        "url":         e.url,
        "resolved":    e.resolved,
        "detected_at": e.detected_at.isoformat() if e.detected_at else None,
    }
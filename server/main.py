"""
ZYVARON Central Server v0.2.0
"""

import sys
if sys.platform == "win32":
    import asyncio
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from db.database import init_db, Alert, get_db
from api.agents  import router as agents_router
from api.reports import router as reports_router
from api.alerts  import router as alerts_router
from api.devices import router as devices_router
from api.files   import router as files_router
from api.cve     import router as cve_router


def _cleanup_stale_alerts():
    """
    On server startup, resolve any stale duplicate port alerts.
    Ports 3389 and 445 are permanently blocked by ZYVARON firewall rules —
    if alerts exist for them they should be resolved, not repeat forever.
    """
    try:
        from db.database import SessionLocal, Alert
        from datetime import datetime
        db = SessionLocal()
        # Resolve duplicate port alerts — keep only the most recent per title
        port_alerts = db.query(Alert).filter(
            Alert.alert_type.in_(["port_exposure", "critical_exposure"]),
            Alert.resolved == False,
        ).order_by(Alert.title, Alert.created_at.desc()).all()

        seen_titles = {}
        resolved = 0
        for alert in port_alerts:
            if alert.title not in seen_titles:
                seen_titles[alert.title] = alert
            else:
                # Resolve the duplicate (keep newest)
                alert.resolved    = True
                alert.resolved_at = datetime.utcnow()
                resolved += 1
        db.commit()
        db.close()
        if resolved:
            print(f"Startup cleanup: resolved {resolved} duplicate stale alerts")
    except Exception as e:
        print(f"Startup cleanup skipped: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("ZYVARON Server starting...")
    init_db()
    _cleanup_stale_alerts()
    print("Database ready [OK]")
    print("Server live at http://localhost:8000")
    print("API docs at   http://localhost:8000/docs")
    yield
    print("ZYVARON Server shutting down...")


app = FastAPI(
    title="ZYVARON Central Server",
    description="Autonomous Cybersecurity Platform",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(agents_router,  prefix="/api/agent",   tags=["Agent"])
app.include_router(reports_router, prefix="/api/reports", tags=["Reports"])
app.include_router(alerts_router,  prefix="/api/alerts",  tags=["Alerts"])
app.include_router(devices_router, prefix="/api/devices", tags=["Devices"])
app.include_router(files_router,   prefix="/api/files",   tags=["Files"])
app.include_router(cve_router,     prefix="/api/cve",     tags=["CVE"])


@app.get("/")
async def root():
    return {"name": "ZYVARON Central Server", "version": "0.2.0", "status": "running"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

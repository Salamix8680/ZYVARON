from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey
from datetime import datetime
from sqlalchemy.orm import relationship

DATABASE_URL = "sqlite:///./zyvaron.db"
engine = create_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

class Device(Base):
    __tablename__ = "devices"
    id = Column(String, primary_key=True)
    hostname = Column(String, index=True)
    platform = Column(String)
    architecture = Column(String)
    ip_address = Column(String)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    agent_version = Column(String)
    risk_score = Column(Integer, default=0)

class SystemReport(Base):
    __tablename__ = "system_reports"
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String, ForeignKey("devices.id"), index=True)
    reported_at = Column(DateTime, default=datetime.utcnow)
    cpu_cores = Column(Integer)
    cpu_usage = Column(Float)
    ram_total_gb = Column(Float)
    ram_used_gb = Column(Float)
    ram_percent = Column(Float)
    os_platform = Column(String)
    os_release = Column(String)
    hostname = Column(String)
    uptime_seconds = Column(Integer)
    raw_data = Column(JSON)

class PortScanReport(Base):
    __tablename__ = "port_scan_reports"
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String, ForeignKey("devices.id"), index=True)
    scanned_at = Column(DateTime, default=datetime.utcnow)
    target = Column(String)
    ports_scanned = Column(Integer)
    total_open = Column(Integer)
    risk_score = Column(Integer)
    critical_exposures = Column(Integer)
    status = Column(String)
    open_ports = Column(JSON)
    scan_duration = Column(Float)

class FileEvent(Base):
    __tablename__ = "file_events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String, ForeignKey("devices.id"), index=True)
    detected_at = Column(DateTime, default=datetime.utcnow)
    event_type = Column(String)
    file_path = Column(String)
    severity = Column(String)
    original_hash = Column(String, nullable=True)
    current_hash = Column(String, nullable=True)
    resolved = Column(Boolean, default=False)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String, ForeignKey("devices.id"), index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    alert_type = Column(String)
    severity = Column(String)
    title = Column(String)
    description = Column(Text)
    data = Column(JSON)
    resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime, nullable=True)

class SnapshotRecord(Base):
    __tablename__ = "snapshots"
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String, ForeignKey("devices.id"), index=True)
    snapshot_id = Column(String, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    total_files = Column(Integer)
    label = Column(String, nullable=True)

class CVEScan(Base):
    __tablename__ = "cve_scans"
    id             = Column(Integer, primary_key=True, autoincrement=True)
    device_id      = Column(String, ForeignKey("devices.id"), index=True)
    scanned_at     = Column(DateTime, default=datetime.utcnow)
    apps_scanned   = Column(Integer, default=0)
    apps_total     = Column(Integer, default=0)
    total_cves     = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count     = Column(Integer, default=0)
    medium_count   = Column(Integer, default=0)
    cves           = Column(JSON, default=list)
    software_list  = Column(JSON, default=list)
    entries        = relationship("CVEEntry", back_populates="scan")

class CVEEntry(Base):

    __tablename__ = "cve_entries"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    device_id   = Column(String, ForeignKey("devices.id"), index=True)
    scan_id     = Column(Integer, ForeignKey("cve_scans.id"), index=True)
    cve_id      = Column(String, index=True)
    software    = Column(String)
    version     = Column(String)
    score       = Column(Float)
    severity    = Column(String)
    description = Column(String)
    published   = Column(String)
    url         = Column(String)
    resolved    = Column(Boolean, default=False)
    detected_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("CVEScan", back_populates="entries")

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
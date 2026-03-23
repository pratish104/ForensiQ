from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
import enum
from app.core.database import Base


def gen_uuid():
    return str(uuid.uuid4())


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    complete = "complete"
    failed = "failed"


class SeverityLevel(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=gen_uuid)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    scans = relationship("Scan", back_populates="user")


class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True, default=gen_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    tool = Column(String, nullable=False)       # owasp | metadata | logs | pcap
    target = Column(String)                     # URL or filename
    status = Column(Enum(ScanStatus), default=ScanStatus.pending)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True))
    user = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete")


class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text)
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.info)
    category = Column(String)        # e.g. A01, A04, EXIF, AUTH
    remediation = Column(Text)
    raw_evidence = Column(Text)
    scan = relationship("Scan", back_populates="findings")

from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime


# ── Auth ──────────────────────────────────────────────────────────────────────
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None


class UserOut(BaseModel):
    id: str
    email: str
    full_name: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


# ── Findings ──────────────────────────────────────────────────────────────────
class FindingOut(BaseModel):
    id: str
    title: str
    description: Optional[str]
    severity: str
    category: Optional[str]
    remediation: Optional[str]

    class Config:
        from_attributes = True


# ── Scans ─────────────────────────────────────────────────────────────────────
class ScanOut(BaseModel):
    id: str
    tool: str
    target: Optional[str]
    status: str
    created_at: datetime
    completed_at: Optional[datetime]
    findings: List[FindingOut] = []

    class Config:
        from_attributes = True


# ── Tool-specific request schemas ─────────────────────────────────────────────
class OWASPScanRequest(BaseModel):
    url: str
    checks: Optional[List[str]] = None    # e.g. ["sqli","xss","headers"]


class LogAnalyzeRequest(BaseModel):
    content: str                           # raw log text pasted by user
    log_type: Optional[str] = "auto"      # auth | apache | nginx | auto


# ── Dashboard ─────────────────────────────────────────────────────────────────
class DashboardStats(BaseModel):
    total_scans: int
    total_findings: int
    high_severity: int
    labs_completed: int

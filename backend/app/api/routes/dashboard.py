from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import Scan, Finding, SeverityLevel
from app.schemas.schemas import DashboardStats

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStats)
def get_stats(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    uid = current_user["id"]
    total_scans = db.query(func.count(Scan.id)).filter(Scan.user_id == uid).scalar() or 0
    total_findings = (
        db.query(func.count(Finding.id)).join(Scan).filter(Scan.user_id == uid).scalar() or 0
    )
    high_severity = (
        db.query(func.count(Finding.id))
        .join(Scan)
        .filter(Scan.user_id == uid, Finding.severity == SeverityLevel.high)
        .scalar() or 0
    )
    return DashboardStats(
        total_scans=total_scans,
        total_findings=total_findings,
        high_severity=high_severity,
        labs_completed=0,
    )


@router.get("/recent-findings")
def recent_findings(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    rows = (
        db.query(Finding, Scan.tool, Scan.target)
        .join(Scan)
        .filter(Scan.user_id == current_user["id"])
        .order_by(Scan.created_at.desc())
        .limit(10).all()
    )
    return [
        {"id": f.id, "title": f.title, "severity": f.severity,
         "category": f.category, "tool": tool, "target": target}
        for f, tool, target in rows
    ]

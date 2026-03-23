from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import Scan, Finding, ScanStatus, SeverityLevel
from app.schemas.schemas import ScanOut, OWASPScanRequest
from app.services import owasp_scanner, metadata_analyzer, log_analyzer, pcap_analyzer

router = APIRouter(prefix="/scan", tags=["scans"])


def _save_findings(db: Session, scan_id: str, raw: list):
    for f in raw:
        try:
            sev = SeverityLevel(f.get("severity", "info"))
        except ValueError:
            sev = SeverityLevel.info
        db.add(Finding(
            scan_id=scan_id,
            title=f.get("title", ""),
            description=f.get("description"),
            severity=sev,
            category=f.get("category"),
            remediation=f.get("remediation"),
            raw_evidence=f.get("raw_evidence"),
        ))


@router.post("/owasp", response_model=ScanOut)
async def owasp_scan(
    payload: OWASPScanRequest,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = Scan(user_id=current_user["id"], tool="owasp", target=payload.url, status=ScanStatus.running)
    db.add(scan); db.commit(); db.refresh(scan)
    try:
        findings = await owasp_scanner.run_owasp_scan(payload.url, payload.checks)
        _save_findings(db, scan.id, findings)
        scan.status = ScanStatus.complete
        scan.completed_at = datetime.utcnow()
    except Exception:
        scan.status = ScanStatus.failed
    db.commit(); db.refresh(scan)
    return scan


@router.post("/metadata")
async def metadata_scan(
    file: UploadFile = File(...),
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    contents = await file.read()
    if len(contents) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 50 MB)")
    scan = Scan(user_id=current_user["id"], tool="metadata", target=file.filename, status=ScanStatus.running)
    db.add(scan); db.commit(); db.refresh(scan)
    result = metadata_analyzer.analyze_file(contents, file.filename)
    _save_findings(db, scan.id, result.get("risks", []))
    scan.status = ScanStatus.complete
    scan.completed_at = datetime.utcnow()
    db.commit()
    return {"scan_id": scan.id, **result}


@router.post("/logs")
async def logs_scan(
    file: Optional[UploadFile] = File(None),
    content: Optional[str] = Form(None),
    log_type: str = Form("auto"),
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if file:
        raw = (await file.read()).decode("utf-8", errors="ignore")
        target = file.filename
    elif content:
        raw, target = content, "pasted_log"
    else:
        raise HTTPException(status_code=400, detail="Provide a file upload or raw log content")
    scan = Scan(user_id=current_user["id"], tool="logs", target=target, status=ScanStatus.running)
    db.add(scan); db.commit(); db.refresh(scan)
    result = log_analyzer.analyze_logs(raw, log_type)
    _save_findings(db, scan.id, result.get("findings", []))
    scan.status = ScanStatus.complete
    scan.completed_at = datetime.utcnow()
    db.commit()
    return {"scan_id": scan.id, **result}


@router.post("/pcap")
async def pcap_scan(
    file: UploadFile = File(...),
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    contents = await file.read()
    scan = Scan(user_id=current_user["id"], tool="pcap", target=file.filename, status=ScanStatus.running)
    db.add(scan); db.commit(); db.refresh(scan)
    result = pcap_analyzer.analyze_pcap(contents, file.filename)
    _save_findings(db, scan.id, result.get("findings", []))
    scan.status = ScanStatus.complete
    scan.completed_at = datetime.utcnow()
    db.commit()
    return {"scan_id": scan.id, **result}


@router.get("/history")
def scan_history(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    return (
        db.query(Scan)
        .filter(Scan.user_id == current_user["id"])
        .order_by(Scan.created_at.desc())
        .limit(50).all()
    )


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str, current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user["id"]).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

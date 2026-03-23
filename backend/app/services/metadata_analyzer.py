"""
File metadata extraction service.
Supports: JPEG/PNG/TIFF (EXIF), PDF (document info), DOCX (core properties).
"""
import io
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List

from PIL import Image
import exifread
import PyPDF2


def analyze_file(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    ext = Path(filename).suffix.lower()
    if ext in (".jpg", ".jpeg", ".png", ".tiff", ".heic"):
        return _analyze_image(file_bytes, filename)
    elif ext == ".pdf":
        return _analyze_pdf(file_bytes, filename)
    elif ext in (".docx", ".doc"):
        return _analyze_docx(file_bytes, filename)
    else:
        return {
            "filename": filename,
            "error": f"Unsupported file type: {ext}",
            "metadata": {},
            "risks": [],
            "summary": {"total_tags": 0, "has_gps": False, "risk_count": 0},
        }


# ── Image (EXIF) ──────────────────────────────────────────────────────────────
def _analyze_image(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {}
    risks: List[Dict] = []

    # exifread — full EXIF tag extraction
    stream = io.BytesIO(file_bytes)
    tags = exifread.process_file(stream, details=True)
    for tag, val in tags.items():
        clean = tag.replace("EXIF ", "").replace("Image ", "")
        metadata[clean] = str(val)

    # Pillow — image dimensions + format
    try:
        img = Image.open(io.BytesIO(file_bytes))
        metadata["Image Width"] = img.width
        metadata["Image Height"] = img.height
        metadata["Color Mode"] = img.mode
        metadata["Format"] = img.format or "unknown"
    except Exception:
        pass

    has_gps = any("GPS" in k for k in metadata)

    # GPS risk
    if has_gps:
        lat = metadata.get("GPS GPSLatitude", "unknown")
        lon = metadata.get("GPS GPSLongitude", "unknown")
        risks.append({
            "type": "privacy",
            "severity": "high",
            "title": "GPS coordinates embedded in image",
            "description": f"Exact location data found — Lat: {lat}, Lon: {lon}. Sharing this file reveals the photo location.",
            "remediation": "Strip GPS before publishing: exiftool -gps:all= file.jpg  OR  use Pillow to save without EXIF.",
        })

    # Device info
    device_fields = {k: metadata[k] for k in ["Image Make", "Image Model"] if k in metadata}
    if device_fields:
        risks.append({
            "type": "privacy",
            "severity": "medium",
            "title": "Device information embedded",
            "description": f"Camera/device details: {device_fields}. Identifies the hardware used.",
            "remediation": "Remove device metadata: exiftool -Make= -Model= file.jpg",
        })

    # Software disclosure
    if "Image Software" in metadata:
        risks.append({
            "type": "info_disclosure",
            "severity": "low",
            "title": "Software version disclosed",
            "description": f"Software tag: {metadata['Image Software']}",
            "remediation": "Strip software metadata: exiftool -Software= file.jpg",
        })

    return {
        "filename": filename,
        "file_type": "image",
        "metadata": metadata,
        "risks": risks,
        "summary": {
            "total_tags": len(metadata),
            "has_gps": has_gps,
            "risk_count": len(risks),
        },
    }


# ── PDF ───────────────────────────────────────────────────────────────────────
def _analyze_pdf(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {}
    risks: List[Dict] = []
    try:
        reader = PyPDF2.PdfReader(io.BytesIO(file_bytes))
        info = reader.metadata or {}
        for key, val in info.items():
            metadata[key.lstrip("/")] = str(val)
        metadata["Page Count"] = len(reader.pages)
    except Exception as e:
        metadata["parse_error"] = str(e)

    for field in ["Author", "Creator", "Producer", "LastModifiedBy"]:
        if field in metadata and metadata[field]:
            risks.append({
                "type": "privacy",
                "severity": "medium",
                "title": f"Identity disclosed in PDF ({field})",
                "description": f"{field}: {metadata[field]}",
                "remediation": "Remove metadata before sharing: File → Properties → Remove Personal Info in Acrobat, or: exiftool -all= file.pdf",
            })

    return {
        "filename": filename,
        "file_type": "pdf",
        "metadata": metadata,
        "risks": risks,
        "summary": {"total_tags": len(metadata), "has_gps": False, "risk_count": len(risks)},
    }


# ── DOCX ──────────────────────────────────────────────────────────────────────
def _analyze_docx(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {}
    risks: List[Dict] = []

    NS = {
        "dc":      "http://purl.org/dc/elements/1.1/",
        "cp":      "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
        "dcterms": "http://purl.org/dc/terms/",
    }
    FIELDS = [
        "title", "subject", "creator", "keywords",
        "description", "lastModifiedBy", "revision", "created", "modified",
    ]

    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
            if "docProps/core.xml" in z.namelist():
                root = ET.parse(z.open("docProps/core.xml")).getroot()
                for field in FIELDS:
                    for prefix, uri in NS.items():
                        el = root.find(f"{{{uri}}}{field}")
                        if el is not None and el.text:
                            metadata[field] = el.text
    except Exception as e:
        metadata["parse_error"] = str(e)

    for field in ["creator", "lastModifiedBy"]:
        if field in metadata:
            risks.append({
                "type": "privacy",
                "severity": "medium",
                "title": f"Author identity in DOCX ({field})",
                "description": f"{field}: {metadata[field]}",
                "remediation": "Use Inspect Document in Word (File → Info → Check for Issues) to remove personal info before sharing.",
            })

    return {
        "filename": filename,
        "file_type": "docx",
        "metadata": metadata,
        "risks": risks,
        "summary": {"total_tags": len(metadata), "has_gps": False, "risk_count": len(risks)},
    }

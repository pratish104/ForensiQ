"""
OWASP Top 10 passive scanner.
Checks: security headers, cookie flags, form CSRF, info disclosure, basic SQLi detection.
For full active scanning integrate OWASP ZAP REST API.
"""
import re
import httpx
from bs4 import BeautifulSoup
from typing import List, Dict, Any
from urllib.parse import urlparse


SECURITY_HEADERS = {
    "Content-Security-Policy":   ("A02", "Missing Content-Security-Policy header — XSS risk", "medium"),
    "X-Frame-Options":           ("A02", "Missing X-Frame-Options — clickjacking risk", "medium"),
    "X-Content-Type-Options":    ("A02", "Missing X-Content-Type-Options header", "low"),
    "Strict-Transport-Security": ("A02", "Missing HSTS header — downgrade attack risk", "medium"),
    "Referrer-Policy":           ("A02", "Missing Referrer-Policy header", "low"),
    "Permissions-Policy":        ("A02", "Missing Permissions-Policy header", "low"),
}

SENSITIVE_HEADERS = ["X-Powered-By", "Server", "X-AspNet-Version"]

SQL_ERROR_STRINGS = [
    "sql syntax", "mysql_fetch", "unclosed quotation", "odbc driver",
    "ora-", "sqlite_", "pg_query", "syntax error near",
]


async def run_owasp_scan(url: str, checks: List[str] = None) -> List[Dict[str, Any]]:
    findings = []
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            resp = await client.get(url)
            findings += _check_security_headers(resp)
            findings += _check_info_disclosure(resp)
            findings += _check_cookies(resp)
            soup = BeautifulSoup(resp.text, "html.parser")
            findings += _check_forms(soup)
            findings += await _check_sqli(client, url, resp)
    except httpx.RequestError as e:
        findings.append({
            "title": "Connection error",
            "description": str(e),
            "severity": "info",
            "category": "RECON",
            "remediation": "Ensure the target URL is reachable and accessible.",
        })
    return findings


def _check_security_headers(resp: httpx.Response) -> List[Dict]:
    findings = []
    present = {k.lower() for k in resp.headers}
    for header, (category, message, severity) in SECURITY_HEADERS.items():
        if header.lower() not in present:
            findings.append({
                "title": message,
                "description": f"The response does not include the '{header}' HTTP security header.",
                "severity": severity,
                "category": category,
                "remediation": f"Add '{header}' to all HTTP responses in your server or application config.",
            })
    return findings


def _check_info_disclosure(resp: httpx.Response) -> List[Dict]:
    findings = []
    for header in SENSITIVE_HEADERS:
        if header.lower() in {k.lower() for k in resp.headers}:
            val = resp.headers.get(header, "")
            findings.append({
                "title": f"Server version disclosure via {header}",
                "description": f"Header value: '{val}'. Exposes your tech stack to attackers.",
                "severity": "low",
                "category": "A02",
                "remediation": f"Remove or suppress the '{header}' header in your server configuration.",
            })
    return findings


def _check_cookies(resp: httpx.Response) -> List[Dict]:
    findings = []
    cookie = resp.headers.get("set-cookie", "").lower()
    if not cookie:
        return findings
    if "httponly" not in cookie:
        findings.append({
            "title": "Cookie missing HttpOnly flag",
            "description": "Session cookies without HttpOnly are accessible via JavaScript — XSS can steal them.",
            "severity": "high",
            "category": "A07",
            "remediation": "Add the HttpOnly attribute to all session cookies.",
        })
    if "secure" not in cookie:
        findings.append({
            "title": "Cookie missing Secure flag",
            "description": "Cookies without Secure can be transmitted over plain HTTP connections.",
            "severity": "medium",
            "category": "A02",
            "remediation": "Add the Secure attribute to all cookies.",
        })
    if "samesite" not in cookie:
        findings.append({
            "title": "Cookie missing SameSite attribute",
            "description": "Cookies without SameSite=Strict/Lax are vulnerable to CSRF attacks.",
            "severity": "medium",
            "category": "A01",
            "remediation": "Set SameSite=Strict or SameSite=Lax on all session cookies.",
        })
    return findings


def _check_forms(soup: BeautifulSoup) -> List[Dict]:
    findings = []
    for form in soup.find_all("form"):
        method = form.get("method", "get").upper()
        action = form.get("action", "(same page)")
        inputs = form.find_all("input")
        has_csrf = any(
            "csrf" in (i.get("name", "") + i.get("id", "")).lower()
            for i in inputs
        )
        if method == "POST" and not has_csrf:
            findings.append({
                "title": "POST form lacks CSRF token",
                "description": f"Form (action='{action}') submits via POST with no visible CSRF protection.",
                "severity": "high",
                "category": "A01",
                "remediation": "Add a per-session CSRF token as a hidden input to all state-changing forms.",
            })
        for inp in inputs:
            if inp.get("type") == "password" and inp.get("autocomplete") != "off":
                findings.append({
                    "title": "Password field with autocomplete enabled",
                    "description": "Browser may cache the password locally.",
                    "severity": "low",
                    "category": "A02",
                    "remediation": "Set autocomplete='off' on all password input fields.",
                })
                break
    return findings


async def _check_sqli(
    client: httpx.AsyncClient, url: str, original: httpx.Response
) -> List[Dict]:
    findings = []
    parsed = urlparse(url)
    if not parsed.query:
        return findings
    for payload in ["'", "''", "1 AND 1=2"]:
        try:
            resp = await client.get(url + payload, timeout=8)
            body = resp.text.lower()
            original_body = original.text.lower()
            for err in SQL_ERROR_STRINGS:
                if err in body and err not in original_body:
                    findings.append({
                        "title": "Possible SQL injection (error-based)",
                        "description": f"SQL error '{err}' appeared after injecting payload: {payload}",
                        "severity": "high",
                        "category": "A04",
                        "remediation": "Use parameterised queries / prepared statements. Never concatenate user input into SQL strings.",
                        "raw_evidence": f"Payload: {payload} | Pattern: {err}",
                    })
                    return findings
        except Exception:
            pass
    return findings

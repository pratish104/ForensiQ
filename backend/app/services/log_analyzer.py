"""
Log analyzer service.
Detects: brute force attacks, off-hours logins, privilege escalation,
         scanner user-agents, sensitive path access, data exfiltration.
"""
import re
from collections import defaultdict, Counter
from typing import List, Dict, Any, Optional


PATTERNS = {
    "ssh_failed":  re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)", re.I),
    "ssh_success": re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)", re.I),
    "sudo":        re.compile(r"sudo:\s+(\S+) :.*COMMAND=(.*)", re.I),
    "apache":      re.compile(r'([\d.]+) .+\[(.+)\] "(\w+) ([^\s"]+)[^"]*" (\d+) (\d+|-)', re.I),
    "nginx":       re.compile(r'([\d.]+) - .+\[(.+)\] "(\w+) ([^\s"]+)[^"]*" (\d+) (\d+)', re.I),
}

SENSITIVE_PATHS  = ["/admin", "/wp-admin", "/.env", "/config", "/backup",
                    "/phpmyadmin", "/.git", "/api/v1/users", "/etc/passwd"]
SCANNER_UA       = ["sqlmap", "nikto", "nmap", "masscan", "zgrab",
                    "nuclei", "dirbuster", "gobuster", "hydra", "medusa"]
PRIV_ESC_CMDS    = ["/bin/sh", "/bin/bash", "passwd", "visudo", "chmod 777"]
BRUTE_THRESHOLD  = 10       # failed attempts from same IP
OFF_HOURS        = (0, 5)   # midnight – 5 am
LARGE_RESP_BYTES = 10_000_000  # 10 MB


def analyze_logs(content: str, log_type: str = "auto") -> Dict[str, Any]:
    lines = content.strip().splitlines()
    detected = log_type if log_type != "auto" else _detect_type(lines)
    findings: List[Dict] = []

    if detected in ("auth", "syslog"):
        findings += _auth_log(lines)
    elif detected in ("apache", "nginx", "access"):
        findings += _access_log(lines)
    else:
        findings += _auth_log(lines)
        findings += _access_log(lines)

    return {
        "log_type": detected,
        "stats": {
            "total_lines":    len(lines),
            "total_findings": len(findings),
            "high_count":     sum(1 for f in findings if f["severity"] == "high"),
            "medium_count":   sum(1 for f in findings if f["severity"] == "medium"),
        },
        "findings": findings,
    }


def _detect_type(lines: List[str]) -> str:
    sample = "\n".join(lines[:20]).lower()
    if "failed password" in sample or "accepted password" in sample:
        return "auth"
    if re.search(r'"\w+ /[^\s]+ http/', sample):
        return "access"
    if "sudo" in sample:
        return "syslog"
    return "unknown"


def _auth_log(lines: List[str]) -> List[Dict]:
    findings: List[Dict] = []
    failed_by_ip: Dict[str, List[str]] = defaultdict(list)
    successes: List[Dict] = []

    for line in lines:
        m = PATTERNS["ssh_failed"].search(line)
        if m:
            failed_by_ip[m.group(2)].append(m.group(1))
            continue

        m = PATTERNS["ssh_success"].search(line)
        if m:
            hour = _hour(line)
            successes.append({"user": m.group(1), "ip": m.group(2), "hour": hour, "line": line})
            continue

        m = PATTERNS["sudo"].search(line)
        if m:
            user, cmd = m.group(1), m.group(2)
            if any(s in cmd.lower() for s in PRIV_ESC_CMDS):
                findings.append({
                    "title": f"Suspicious sudo command by {user}",
                    "description": f"Command: {cmd.strip()}",
                    "severity": "high",
                    "category": "PRIV_ESC",
                    "remediation": "Review sudoers rules. Restrict shell access granted via sudo.",
                    "raw_evidence": line.strip(),
                })

    # Brute force
    for ip, users in failed_by_ip.items():
        if len(users) >= BRUTE_THRESHOLD:
            findings.append({
                "title": f"Brute force attack from {ip} ({len(users)} attempts)",
                "description": f"Targeted users: {', '.join(sorted(set(users))[:5])}",
                "severity": "high",
                "category": "A07",
                "remediation": "Block IP with fail2ban. Enable account lockout policy.",
                "raw_evidence": f"IP: {ip}, attempts: {len(users)}",
            })

    # Off-hours logins
    for s in successes:
        h = s["hour"]
        if h is not None and OFF_HOURS[0] <= h <= OFF_HOURS[1]:
            findings.append({
                "title": f"Off-hours login — {s['user']} at {h:02d}:xx from {s['ip']}",
                "description": "Successful login between midnight and 5am — investigate if authorised.",
                "severity": "medium",
                "category": "A07",
                "remediation": "Verify with the user. Consider time-based access restrictions.",
                "raw_evidence": s["line"].strip(),
            })

    return findings


def _access_log(lines: List[str]) -> List[Dict]:
    findings: List[Dict] = []
    ip_counts: Counter = Counter()
    scanner_hits: List[tuple] = []
    sensitive_hits: List[tuple] = []
    large_resps: List[tuple] = []

    for line in lines:
        m = PATTERNS["apache"].search(line) or PATTERNS["nginx"].search(line)
        if not m:
            continue
        ip, method, path, status, size = m.group(1), m.group(3), m.group(4), m.group(5), m.group(6)
        ip_counts[ip] += 1

        for ua in SCANNER_UA:
            if ua in line.lower():
                scanner_hits.append((ua, ip, line.strip()))
                break

        for sp in SENSITIVE_PATHS:
            if path.startswith(sp):
                sensitive_hits.append((sp, ip, status, line.strip()))
                break

        try:
            if int(size) > LARGE_RESP_BYTES:
                large_resps.append((ip, path, int(size), line.strip()))
        except (ValueError, TypeError):
            pass

    # High request volume
    for ip, count in ip_counts.most_common(3):
        if count > 500:
            findings.append({
                "title": f"High request volume from {ip} ({count} requests)",
                "description": "Possible scraping, DDoS, or automated scanning.",
                "severity": "medium",
                "category": "A02",
                "remediation": "Enable rate limiting (nginx limit_req or WAF rule). Consider IP blocking.",
                "raw_evidence": f"IP: {ip}, count: {count}",
            })

    for ua, ip, raw in scanner_hits[:3]:
        findings.append({
            "title": f"Security scanner detected: {ua}",
            "description": f"Requests from {ip} contain the '{ua}' user-agent.",
            "severity": "high",
            "category": "RECON",
            "remediation": "Block known scanner UAs at WAF level. Review what paths were accessed.",
            "raw_evidence": raw,
        })

    for sp, ip, status, raw in sensitive_hits[:5]:
        findings.append({
            "title": f"Sensitive path accessed: {sp} (HTTP {status})",
            "description": f"IP {ip} requested {sp} — status {status}.",
            "severity": "high" if status == "200" else "medium",
            "category": "A01",
            "remediation": "Restrict access. Return 404 instead of 403 to avoid path disclosure.",
            "raw_evidence": raw,
        })

    for ip, path, size, raw in large_resps[:3]:
        findings.append({
            "title": f"Large response ({size // 1_000_000} MB) from {path}",
            "description": f"IP {ip} received {size:,} bytes — possible data exfiltration.",
            "severity": "high",
            "category": "A01",
            "remediation": "Verify the transfer was authorised. Implement download rate limits.",
            "raw_evidence": raw,
        })

    return findings


def _hour(line: str) -> Optional[int]:
    m = re.search(r"(\d{2}):\d{2}:\d{2}", line)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            pass
    return None

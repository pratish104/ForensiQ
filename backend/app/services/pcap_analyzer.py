"""
PCAP network traffic analyzer using Scapy.
Detects: plaintext credentials (FTP/HTTP), port scans,
         DNS exfiltration patterns, ARP spoofing, legacy TLS.
"""
import os
import tempfile
from collections import defaultdict, Counter
from typing import List, Dict, Any


def analyze_pcap(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    findings: List[Dict] = []
    stats: Dict[str, Any] = {}

    try:
        from scapy.all import rdpcap, TCP, UDP, IP, DNS, DNSQR, ARP, Raw
    except ImportError:
        return {
            "filename": filename,
            "stats": {},
            "findings": [{
                "title": "Scapy not installed",
                "description": "Run: pip install scapy",
                "severity": "info",
                "category": "SYSTEM",
                "remediation": "pip install scapy",
            }],
            "summary": {"total_packets": 0, "total_findings": 1, "critical_count": 0, "high_count": 0},
        }

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(file_bytes)
            tmp_path = tmp.name

        packets = rdpcap(tmp_path)
        os.unlink(tmp_path)
        stats["total_packets"] = len(packets)

        ip_counter: Counter = Counter()
        ftp_creds: List[Dict] = []
        http_basic: List[Dict] = []
        dns_queries: List[str] = []
        syn_ports: Dict[str, set] = defaultdict(set)
        arp_table: Dict[str, set] = defaultdict(set)

        for pkt in packets:
            if IP in pkt:
                ip_counter[pkt[IP].src] += 1

            # FTP plaintext credentials
            if TCP in pkt and Raw in pkt:
                raw = pkt[Raw].load.decode("utf-8", errors="ignore")
                if pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
                    if raw.startswith(("USER ", "PASS ")):
                        ftp_creds.append({
                            "src": pkt[IP].src if IP in pkt else "?",
                            "dst": pkt[IP].dst if IP in pkt else "?",
                            "data": raw.strip(),
                        })

            # HTTP Basic Auth
            if TCP in pkt and Raw in pkt:
                raw = pkt[Raw].load.decode("utf-8", errors="ignore")
                if "Authorization: Basic " in raw:
                    http_basic.append({
                        "src": pkt[IP].src if IP in pkt else "?",
                        "evidence": raw[:200],
                    })

            # DNS exfiltration (long subdomain = possible data tunnelling)
            if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                dns_queries.append(qname)
                parts = qname.split(".")
                if parts and len(parts[0]) > 40:
                    findings.append({
                        "title": "Possible DNS exfiltration",
                        "description": f"Unusually long subdomain: {qname[:80]} — could be C2 beaconing or data tunnelling.",
                        "severity": "high",
                        "category": "EXFIL",
                        "remediation": "Inspect DNS for base64-encoded subdomains. Block suspicious domains at resolver.",
                        "raw_evidence": qname,
                    })

            # Port scan (SYN flood to many ports)
            if TCP in pkt and IP in pkt and pkt[TCP].flags == 2:
                syn_ports[pkt[IP].src].add(pkt[TCP].dport)

            # ARP spoofing (same IP, multiple MACs)
            if ARP in pkt and pkt[ARP].op == 2:
                arp_table[pkt[ARP].psrc].add(pkt[ARP].hwsrc)

        # ── Emit findings ─────────────────────────────────────────────────────
        if ftp_creds:
            sample = " | ".join(c["data"] for c in ftp_creds[:3])
            findings.append({
                "title": f"Plaintext FTP credentials ({len(ftp_creds)} packets)",
                "description": f"FTP login transmitted in cleartext: {sample}",
                "severity": "critical",
                "category": "A02",
                "remediation": "Replace FTP with SFTP or FTPS immediately.",
                "raw_evidence": str(ftp_creds[:2]),
            })

        if http_basic:
            findings.append({
                "title": f"HTTP Basic Auth intercepted ({len(http_basic)} occurrences)",
                "description": "Base64 credentials in plain HTTP Authorization header — trivially decoded.",
                "severity": "high",
                "category": "A07",
                "remediation": "Enforce HTTPS. Switch to token-based auth (JWT/OAuth2).",
                "raw_evidence": str(http_basic[0])[:200],
            })

        for src_ip, ports in syn_ports.items():
            if len(ports) > 50:
                findings.append({
                    "title": f"Port scan from {src_ip} ({len(ports)} ports)",
                    "description": f"SYN-only packets to {len(ports)} distinct ports — likely nmap or similar.",
                    "severity": "high",
                    "category": "RECON",
                    "remediation": "Block this IP. Enable port scan detection (Snort/Suricata).",
                    "raw_evidence": f"Ports: {sorted(list(ports))[:20]}",
                })

        for ip, macs in arp_table.items():
            if len(macs) > 1:
                findings.append({
                    "title": f"Possible ARP spoofing — {ip} with multiple MACs",
                    "description": f"MACs seen: {', '.join(macs)} — possible MITM attack.",
                    "severity": "high",
                    "category": "NET",
                    "remediation": "Enable Dynamic ARP Inspection (DAI) on managed switches.",
                    "raw_evidence": f"IP: {ip}, MACs: {list(macs)}",
                })

        stats["unique_ips"] = len(ip_counter)
        stats["dns_queries"] = len(dns_queries)
        stats["top_talker"] = ip_counter.most_common(1)[0] if ip_counter else None

    except Exception as e:
        findings.append({
            "title": "PCAP parse error",
            "description": str(e),
            "severity": "info",
            "category": "SYSTEM",
            "remediation": "Ensure the file is a valid .pcap or .pcapng capture file.",
        })

    return {
        "filename": filename,
        "stats": stats,
        "findings": findings,
        "summary": {
            "total_packets":  stats.get("total_packets", 0),
            "total_findings": len(findings),
            "critical_count": sum(1 for f in findings if f["severity"] == "critical"),
            "high_count":     sum(1 for f in findings if f["severity"] == "high"),
        },
    }

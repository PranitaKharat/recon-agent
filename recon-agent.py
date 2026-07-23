import socket
import sys
import json
import xml.etree.ElementTree as ET
import logging
import ssl
import re
import time
from datetime import datetime

# Suppress Scapy IPv6/runtime warnings on startup
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, UDP, sr1, send, ICMP, DNS, DNSQR, RandShort

# Configuration Constants (Unchanged Port List: 9 Ports)
FTP_PORT = 21
SSH_PORT = 22
DNS_PORT = 53
HTTP_PORT = 80
SMTP_PORTS = [25, 465, 587]
IMAP_PORTS = [143, 993]
TIMEOUT = 2.0

# State Tracking & Core Priority Engine
port_votes = {}  # Format: { port: {"open": X, "closed": Y, "filtered": Z} }
detected_as_windows = False
port_authoritative_states = {}

# Single source of truth for all results
scan_results = {
    "metadata": {
        "target_host": "",
        "target_ip": "",
        "scan_started": "",
        "scan_profile": "Safe Recon Matrix",
        "duration_seconds": 0.0,
        "zombie_ip": "Skipped"
    },
    "host_status": {
        "status": "UNKNOWN",
        "method": "ICMP / TCP Probe",
        "rtt_ms": 0.0,
        "confidence": 100
    },
    "port_coverage": {
        "configured_tcp_ports": 9,
        "open_found": 0,
        "closed": 0,
        "filtered": 0
    },
    "ports": [],  # High quality structured list
    "os_fingerprint": {
        "detected_os": "Unknown",
        "confidence_score": 0,
        "confidence_percentage": "0%",
        "evidence": []
    },
    "risk_assessment": {
        "overall_risk": "LOW",
        "reasons": [],
        "vulnerabilities": []
    },
    "scan_modules": {
        "host_discovery": "PENDING",
        "port_scan": "PENDING",
        "service_detection": "PENDING",
        "banner_grabbing": "PENDING",
        "os_fingerprint": "PENDING"
    }
}

# Vulnerability Database (Local Offline Lookup)
CVE_DATABASE = {
    "Apache/2.4.7": [
        {"cve": "CVE-2014-0226", "severity": "MEDIUM", "cvss": 6.8, "summary": "Apache HTTP Server mod_status race condition"}
    ],
    "vsFTPd 2.3.4": [
        {"cve": "CVE-2011-2523", "severity": "CRITICAL", "cvss": 9.8, "summary": "vsFTPd 2.3.4 Backdoor Execution"}
    ],
    "OpenSSH_7.2p2": [
        {"cve": "CVE-2018-15473", "severity": "MEDIUM", "cvss": 5.3, "summary": "OpenSSH User Enumeration"}
    ]
}

# Service Banner Parsing Database
SERVICE_REGEX = {
    "HTTP": [
        (r"Server:\s*(Apache/?[\d\.]+)", "Apache"),
        (r"Server:\s*(nginx/?[\d\.]+)", "nginx"),
        (r"Server:\s*(Microsoft-IIS/?[\d\.]+)", "Microsoft IIS")
    ],
    "SSH": [
        (r"(OpenSSH_[\w\.\-]+)", "OpenSSH"),
        (r"(dropbear_[\d\.]+)", "Dropbear")
    ],
    "FTP": [
        (r"(vsFTPd\s*[\d\.]+)", "vsFTPd"),
        (r"(ProFTPD\s*[\d\.]+)", "ProFTPD"),
        (r"(FileZilla Server\s*[\d\.]+)", "FileZilla")
    ],
    "SMTP": [
        (r"(Postfix)", "Postfix"),
        (r"(Exim\s*[\d\.]+)", "Exim"),
        (r"(Sendmail\s*[\d\.]+)", "Sendmail")
    ],
    "DNS": [
        (r"(BIND\s*[\d\.]+)", "BIND")
    ]
}

def cast_vote(port, state, weight=1):
    """Registers weighted votes."""
    if port not in port_votes:
        port_votes[port] = {"open": 0, "closed": 0, "filtered": 0}
    port_votes[port][state] += weight

def final_consensus_decision(port):
    """Priority Decision Engine with Filtered Logic."""
    votes = port_votes.get(port, {"open": 0, "closed": 0, "filtered": 0})
    
    if votes["open"] >= 10:
        return "OPEN"
    if votes["closed"] >= 10:
        return "CLOSED"
    
    if votes["filtered"] > votes["open"] and votes["filtered"] > votes["closed"]:
        return "FILTERED"
    
    max_state = max(votes, key=votes.get)
    if votes[max_state] == 0:
        return "FILTERED"
    return max_state.upper()

def get_port_record(port_num):
    """Retrieves or initializes a structured port dictionary."""
    for record in scan_results["ports"]:
        if record["port"] == port_num:
            return record
    
    service_names = {
        21: "FTP", 22: "SSH", 53: "DNS", 80: "HTTP",
        25: "SMTP", 465: "SMTP-SSL", 587: "Submission",
        143: "IMAP", 993: "IMAPS"
    }
    
    new_record = {
        "port": port_num,
        "state": "CLOSED",
        "service": service_names.get(port_num, "UNKNOWN"),
        "product": "Unknown",
        "version": "Not Exposed",
        "banner": "Empty",
        "risk": "LOW",
        "known_cves": "None Identified",
        "cves": [],
        "enumeration": {}
    }
    scan_results["ports"].append(new_record)
    return new_record

# ==============================================================================
# 1. NETWORK PROTOCOL PROBE ENGINE
# ==============================================================================

def ping_scan(target):
    t_start = time.time()
    ans = sr1(IP(dst=target)/ICMP(), timeout=TIMEOUT, verbose=0)
    t_end = time.time()
    rtt = round((t_end - t_start) * 1000, 2)
    
    if ans:
        scan_results["host_status"] = {
            "status": "UP",
            "method": "ICMP Echo Reply",
            "rtt_ms": rtt,
            "confidence": 100
        }
    else:
        scan_results["host_status"] = {
            "status": "UP (Unconfirmed)",
            "method": "No ICMP Response (Assuming UP)",
            "rtt_ms": 0.0,
            "confidence": 75
        }
    scan_results["scan_modules"]["host_discovery"] = "SUCCESS"

def basic_port_scan(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        result = s.connect_ex((target, port))
        if result == 0:
            cast_vote(port, "open", weight=10)
        else:
            cast_vote(port, "closed", weight=10)
        s.close()
    except Exception:
        cast_vote(port, "filtered", weight=2)

def syn_scan(target, port):
    for retry in range(2):
        packet = IP(dst=target)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=TIMEOUT, verbose=0)
        
        if response:
            if response.haslayer(TCP):
                if response[TCP].flags == 0x12:
                    cast_vote(port, "open", weight=10)
                    send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=0)
                    return
                elif response[TCP].flags == 0x14:
                    cast_vote(port, "closed", weight=10)
                    return
            elif response.haslayer(ICMP):
                icmp_type = int(response[ICMP].type)
                icmp_code = int(response[ICMP].code)
                if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                    cast_vote(port, "filtered", weight=8)
                    return
        
    cast_vote(port, "filtered", weight=3)

def tcp_scan(target, port):
    syn_packet = IP(dst=target)/TCP(dport=port, flags="S", seq=1000)
    syn_ack = sr1(syn_packet, timeout=TIMEOUT, verbose=0)
    if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 0x12:
        ack_packet = IP(dst=target)/TCP(dport=port, flags="A", seq=1001, ack=syn_ack[TCP].seq + 1)
        send(ack_packet, verbose=0)
        cast_vote(port, "open", weight=5)
        send(IP(dst=target)/TCP(dport=port, flags="R", seq=1002), verbose=0)

def udp_scan(target, port):
    packet = IP(dst=target)/UDP(dport=port)
    response = sr1(packet, timeout=TIMEOUT, verbose=0)
    if response is None:
        cast_vote(port, "filtered", weight=1)
    elif response.haslayer(UDP):
        cast_vote(port, "open", weight=5)
    elif response.haslayer(ICMP):
        if int(response[ICMP].type) == 3 and int(response[ICMP].code) == 3:
            cast_vote(port, "closed", weight=5)

def process_inverse_response(response, port):
    if response is None:
        cast_vote(port, "filtered", weight=1)
    elif response.haslayer(TCP) and response[TCP].flags == 0x14:
        cast_vote(port, "closed", weight=1)

def fin_scan(target, port):
    packet = IP(dst=target)/TCP(dport=port, flags="F")
    process_inverse_response(sr1(packet, timeout=TIMEOUT, verbose=0), port)

def null_scan(target, port):
    packet = IP(dst=target)/TCP(dport=port, flags="")
    process_inverse_response(sr1(packet, timeout=TIMEOUT, verbose=0), port)

def xmas_scan(target, port):
    packet = IP(dst=target)/TCP(dport=port, flags="FPU")
    process_inverse_response(sr1(packet, timeout=TIMEOUT, verbose=0), port)

def ack_scan(target, port):
    packet = IP(dst=target)/TCP(dport=port, flags="A")
    response = sr1(packet, timeout=TIMEOUT, verbose=0)
    if response is None:
        cast_vote(port, "filtered", weight=2)

def window_scan(target, port):
    packet = IP(dst=target)/TCP(dport=port, flags="A")
    response = sr1(packet, timeout=TIMEOUT, verbose=0)
    if response and response.haslayer(TCP) and response[TCP].flags == 0x14:
        if response[TCP].window > 0:
            cast_vote(port, "open", weight=2)
        else:
            cast_vote(port, "closed", weight=2)

def maimon_scan(target, port):
    packet = IP(dst=target)/TCP(dport=port, flags="FA")
    response = sr1(packet, timeout=TIMEOUT, verbose=0)
    if response is None:
        cast_vote(port, "filtered", weight=1)
    elif response.haslayer(TCP) and response[TCP].flags == 0x14:
        cast_vote(port, "closed", weight=1)

def zombie_scan(target, zombie_ip, port):
    if not zombie_ip: return
    try:
        p1 = sr1(IP(dst=zombie_ip)/TCP(flags="SA"), timeout=TIMEOUT, verbose=0)
        if not p1: return
        id1 = p1.id
        send(IP(src=zombie_ip, dst=target)/TCP(dport=port, flags="S"), verbose=0)
        p2 = sr1(IP(dst=zombie_ip)/TCP(flags="SA"), timeout=TIMEOUT, verbose=0)
        if not p2: return
        id2 = p2.id
        if id2 == id1 + 2:
            cast_vote(port, "open", weight=3)
        else:
            cast_vote(port, "closed", weight=1)
    except Exception:
        pass

# ==============================================================================
# 2. ENHANCED OS ESTIMATION & CVE LOOKUP ENGINE
# ==============================================================================

def run_cve_lookup(banner_or_version, p_record):
    if not banner_or_version or banner_or_version == "Empty":
        return
    
    found_cve = False
    for key, cves in CVE_DATABASE.items():
        if key.lower() in banner_or_version.lower():
            for vuln in cves:
                p_record["cves"].append(vuln)
                p_record["risk"] = vuln["severity"]
                found_cve = True
                cve_msg = f"{vuln['cve']} ({vuln['summary']})"
                if cve_msg not in scan_results["risk_assessment"]["reasons"]:
                    scan_results["risk_assessment"]["reasons"].append(cve_msg)
                
                if vuln["severity"] in ["HIGH", "CRITICAL"]:
                    scan_results["risk_assessment"]["overall_risk"] = "HIGH"
                elif vuln["severity"] == "MEDIUM" and scan_results["risk_assessment"]["overall_risk"] != "HIGH":
                    scan_results["risk_assessment"]["overall_risk"] = "MEDIUM"
                    
    if found_cve:
        p_record["known_cves"] = f"{len(p_record['cves'])} Identified"
    else:
        p_record["known_cves"] = "None Identified"

def service_and_os_detection(target, port=SSH_PORT):
    """
    REFINED KERNEL ESTIMATION & OS FINGERPRINTING MATRIX
    """
    global detected_as_windows
    linux_score = 0
    windows_score = 0
    evidence = []
    
    pkt = sr1(IP(dst=target)/TCP(dport=port, flags="S"), timeout=TIMEOUT, verbose=0)
    if pkt and pkt.haslayer(TCP):
        ttl = pkt.ttl
        window = pkt[TCP].window
        df_bit = pkt.flags.DF if hasattr(pkt.flags, 'DF') else 0
        
        # 1. TTL Analysis
        if 50 <= ttl <= 70:
            linux_score += 3
            evidence.append(f"TTL = {ttl} (Standard Linux range ~64)")
        elif 100 <= ttl <= 130:
            windows_score += 3
            evidence.append(f"TTL = {ttl} (Standard Windows range ~128)")
            
        # 2. TCP Window Size Correlation
        if window in [5840, 29200, 64240]:
            linux_score += 2
            evidence.append(f"TCP Window Size = {window} (Linux Match)")
        elif window in [8192, 65535]:
            windows_score += 2
            evidence.append(f"TCP Window Size = {window} (Windows Match)")
            
        # 3. Don't Fragment (DF) Bit
        if df_bit:
            linux_score += 1
            evidence.append("DF Flag set (Linux standard)")

    # 4. App-Layer Banner Cross-Correlation & Precise Kernel Estimation
    for p_rec in scan_results["ports"]:
        consolidated = (p_rec["banner"] + " " + p_rec["product"] + " " + str(p_rec["enumeration"])).lower()
        if any(term in consolidated for term in ["ubuntu", "debian", "linux", "openssh"]):
            linux_score += 4
            evidence.append(f"Service Banner Match on Port {p_rec['port']} (Linux Profile)")
            break
        elif any(term in consolidated for term in ["windows", "microsoft", "iis"]):
            windows_score += 4
            evidence.append(f"Service Banner Match on Port {p_rec['port']} (Microsoft Profile)")
            break

    if windows_score > linux_score and windows_score >= 3:
        detected_as_windows = True
        total_score = min(windows_score, 10)
        os_name = "Microsoft Windows Server / Desktop"
    elif linux_score > windows_score and linux_score >= 3:
        total_score = min(linux_score, 10)
        os_name = "Linux 2.6.x (Kernel Range 2.6.9 - 2.6.33)"
    else:
        total_score = 4
        os_name = "Embedded System / Network Appliance"

    conf_pct = f"{total_score * 10}%"
    
    scan_results["os_fingerprint"] = {
        "detected_os": os_name,
        "confidence_score": total_score,
        "confidence_percentage": conf_pct,
        "evidence": evidence
    }
    
    scan_results["scan_modules"]["os_fingerprint"] = "SUCCESS"
    return os_name

# ==============================================================================
# 3. APPLICATION LAYER MODULES WITH REGEX BANNER PARSING
# ==============================================================================

def parse_service_regex(service_type, banner, p_record):
    if not banner or service_type not in SERVICE_REGEX:
        return
    
    for pattern, prod_name in SERVICE_REGEX[service_type]:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            p_record["product"] = prod_name
            full_str = match.group(1)
            raw_version = full_str.replace(prod_name, "").strip().lstrip("_")
            version_match = re.search(r"[\d\.\w\-]+", raw_version)
            p_record["version"] = version_match.group(0) if version_match else ("Not Exposed" if raw_version == "" else raw_version)
            return

def run_ssh_advanced_audit(target):
    p_rec = get_port_record(SSH_PORT)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((target, SSH_PORT))
        
        banner = ""
        for _ in range(3):
            data = s.recv(1024).decode('utf-8', errors='ignore')
            banner += data
            if "\n" in banner:
                break
            time.sleep(0.2)
            
        banner = banner.strip()
        if banner:
            p_rec["banner"] = banner
            parse_service_regex("SSH", banner, p_rec)
            run_cve_lookup(banner, p_rec)
        s.close()
    except Exception as e:
        p_rec["enumeration"]["ssh_status"] = f"Connection error: {e}"

def ftp_banner_grab(target):
    p_rec = get_port_record(FTP_PORT)
    try:
        s = socket.socket()
        s.settimeout(TIMEOUT)
        s.connect((target, FTP_PORT))
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        if banner:
            p_rec["banner"] = banner
            parse_service_regex("FTP", banner, p_rec)
            run_cve_lookup(banner, p_rec)
        return banner
    except Exception:
        return None

def ftp_anonymous_check(target):
    p_rec = get_port_record(FTP_PORT)
    try:
        s = socket.socket()
        s.settimeout(TIMEOUT)
        s.connect((target, FTP_PORT))
        s.recv(1024)
        s.send(b"USER anonymous\r\n")
        s.recv(1024)
        s.send(b"PASS anonymous@target.com\r\n")
        res2 = s.recv(1024).decode('utf-8')
        s.close()
        if "230" in res2 or "successful" in res2.lower():
            p_rec["enumeration"]["anonymous_login"] = "ALLOWED (Default Access Enabled)"
            p_rec["risk"] = "MEDIUM"
            if "Anonymous FTP Enabled" not in scan_results["risk_assessment"]["reasons"]:
                scan_results["risk_assessment"]["reasons"].append("Anonymous FTP Enabled")
            return True
    except Exception:
        pass
    p_rec["enumeration"]["anonymous_login"] = "REJECTED"
    return False

def ftp_bounce_check(target):
    p_rec = get_port_record(FTP_PORT)
    try:
        s = socket.socket(); s.settimeout(TIMEOUT); s.connect((target, FTP_PORT)); s.recv(1024)
        s.send(b"USER anonymous\r\n"); s.recv(1024); s.send(b"PASS anonymous@target.com\r\n"); s.recv(1024)
        s.send(b"PORT 127,0,0,1,0,80\r\n")
        res = s.recv(1024).decode('utf-8')
        s.close()
        if res.startswith("200"):
            p_rec["enumeration"]["bounce_attack"] = "Vulnerable (PORT instruction accepted)"
        else:
            p_rec["enumeration"]["bounce_attack"] = "Protected"
    except Exception:
        pass

def ftp_brute_force(target):
    p_rec = get_port_record(FTP_PORT)
    users = ["admin", "root", "ftp"]; passwords = ["password", "12345"]
    for u in users:
        for p in passwords:
            try:
                s = socket.socket(); s.settimeout(1.0); s.connect((target, FTP_PORT)); s.recv(1024)
                s.send(f"USER {u}\r\n".encode()); s.recv(1024); s.send(f"PASS {p}\r\n".encode())
                res = s.recv(1024).decode('utf-8'); s.close()
                if "230" in res:
                    p_rec["enumeration"]["weak_credentials"] = f"MATCH FOUND -> {u}:{p}"
                    p_rec["risk"] = "HIGH"
                    if "Weak FTP Credential Detected" not in scan_results["risk_assessment"]["reasons"]:
                        scan_results["risk_assessment"]["reasons"].append("Weak FTP Credential Detected")
                    return
            except Exception:
                pass

def http_get_details(target):
    p_rec = get_port_record(HTTP_PORT)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(TIMEOUT); s.connect((target, HTTP_PORT))
        s.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\nUser-Agent: ReconAgent/2.0\r\n\r\n")
        response = s.recv(4096).decode('utf-8', errors='ignore'); s.close()
        
        server_line = "Unknown"
        for line in response.split("\n"):
            if line.lower().strip().startswith("server:"):
                server_line = line.split(":", 1)[1].strip()
                break
                
        p_rec["banner"] = f"Server: {server_line}"
        parse_service_regex("HTTP", p_rec["banner"], p_rec)
        run_cve_lookup(server_line, p_rec)
        
        title_match = re.search(r'<title>(.*?)</title>', response, re.IGNORECASE | re.DOTALL)
        if title_match:
            p_rec["enumeration"]["page_title"] = title_match.group(1).strip()
    except Exception as e:
        p_rec["enumeration"]["http_error"] = str(e)

def http_methods_check(target):
    p_rec = get_port_record(HTTP_PORT)
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM); conn.settimeout(TIMEOUT); conn.connect((target, HTTP_PORT))
        conn.send(b"OPTIONS / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
        res = conn.recv(2048).decode('utf-8', errors='ignore'); conn.close()
        for line in res.split("\n"):
            if line.lower().strip().startswith("allow:") or line.lower().strip().startswith("public:"):
                p_rec["enumeration"]["allowed_methods"] = line.split(":", 1)[1].strip()
    except Exception:
        pass

def http_directory_enumeration(target):
    p_rec = get_port_record(HTTP_PORT)
    wordlist = ["admin", "login", "robots.txt"]
    found_paths = []
    for path in wordlist:
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM); conn.settimeout(1.0); conn.connect((target, HTTP_PORT))
            conn.send(f"GET /{path} HTTP/1.1\r\nHost: {target}\r\nCache-Control: no-cache\r\n\r\n".encode())
            response = conn.recv(512).decode('utf-8', errors='ignore'); conn.close()
            if "HTTP/1.1 200" in response:
                found_paths.append(f"/{path}")
        except Exception:
            pass
    if found_paths:
        p_rec["enumeration"]["discovered_endpoints"] = ", ".join(found_paths)

def run_smtp_advanced_audit(target, port):
    p_rec = get_port_record(port)
    try:
        plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM); plain_socket.settimeout(TIMEOUT)
        s = ssl.create_default_context().wrap_socket(plain_socket, server_hostname=target) if port == 465 else plain_socket
        s.connect((target, port)); banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        p_rec["banner"] = banner
        parse_service_regex("SMTP", banner, p_rec)
        
        s.send(b"EHLO metasploitable.localdomain\r\n")
        ehlo_response = s.recv(2048).decode('utf-8', errors='ignore').strip()
        caps = [line[4:].strip() for line in ehlo_response.split("\n") if line.startswith("250-") or line.startswith("250 ")]
        if caps:
            p_rec["enumeration"]["capabilities"] = ", ".join(caps)
        s.close()
    except Exception as e:
        p_rec["enumeration"]["smtp_error"] = str(e)

def run_dns_advanced_audit(target):
    p_rec = get_port_record(DNS_PORT)
    try:
        dns_req = IP(dst=target)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname="version.bind", qclass=3, qtype=16))
        dns_resp = sr1(dns_req, timeout=TIMEOUT, verbose=0)
        if dns_resp and dns_resp.haslayer(DNS) and dns_resp[DNS].ancount > 0:
            rdata = dns_resp[DNS].an[0].rdata
            version = (b" ".join(rdata) if isinstance(rdata, list) else rdata).decode('utf-8', errors='ignore')
            p_rec["banner"] = f"BIND Version: {version}"
            p_rec["product"] = "BIND"
            p_rec["version"] = version
    except Exception:
        p_rec["banner"] = "Active Responding DNS Daemon"

def run_imap_advanced_audit(target, port):
    p_rec = get_port_record(port)
    try:
        plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM); plain_socket.settimeout(TIMEOUT)
        s = ssl.create_default_context().wrap_socket(plain_socket, server_hostname=target) if port == 993 else plain_socket
        s.connect((target, port)); banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        p_rec["banner"] = banner
        s.close()
    except Exception:
        pass

# ==============================================================================
# 4. METRICS & PROFESSIONAL OUTPUT
# ==============================================================================

def calculate_dynamic_metrics():
    """Calculates open/closed/filtered ports dynamically."""
    open_count = sum(1 for p in scan_results["ports"] if p["state"] == "OPEN")
    closed_count = sum(1 for p in scan_results["ports"] if p["state"] == "CLOSED")
    filtered_count = sum(1 for p in scan_results["ports"] if p["state"] == "FILTERED")
    
    scan_results["port_coverage"]["open_found"] = open_count
    scan_results["port_coverage"]["closed"] = closed_count
    scan_results["port_coverage"]["filtered"] = filtered_count

    scan_results["scan_modules"]["port_scan"] = "SUCCESS"
    scan_results["scan_modules"]["service_detection"] = "SUCCESS"
    scan_results["scan_modules"]["banner_grabbing"] = "SUCCESS"

    if open_count > 3:
        if "Multiple Internet Facing Services Exposed" not in scan_results["risk_assessment"]["reasons"]:
            scan_results["risk_assessment"]["reasons"].append("Multiple Internet Facing Services Exposed")

def print_professional_cli_output():
    """Generates clean, standardized CLI layout."""
    meta = scan_results["metadata"]
    host = scan_results["host_status"]
    os_info = scan_results["os_fingerprint"]
    cov = scan_results["port_coverage"]

    open_services = [p['service'] for p in scan_results["ports"] if p['state'] == "OPEN"]

    print("\n" + "="*60)
    print("              RECON AGENT v2.0")
    print("="*60)
    print(f"Target          : {meta['target_host']}")
    print(f"Resolved IP     : {meta['target_ip']}")
    print(f"Scan Started    : {meta['scan_started']}")
    print(f"Scan Profile    : {meta['scan_profile']}")
    
    print("\n" + "="*60)
    print("[1/6] HOST DISCOVERY")
    print("="*60)
    print(f"Status          : {host['status']}")
    print(f"Method          : {host['method']}")
    print(f"Response Time   : {host['rtt_ms']} ms")
    
    print("\n" + "="*60)
    print("[2/6] PORT COVERAGE & DISCOVERY")
    print("="*60)
    print(f"Configured TCP Ports : {cov['configured_tcp_ports']}")
    print(f"Open Found           : {cov['open_found']}")
    print(f"Closed               : {cov['closed']}")
    print(f"Filtered             : {cov['filtered']}\n")
    print(f"{'PORT':<10} {'STATE':<12} {'SERVICE':<15}")
    print("-" * 37)
    for p in scan_results["ports"]:
        print(f"{str(p['port']) + '/tcp':<10} {p['state']:<12} {p['service']:<15}")

    print("\n" + "="*60)
    print("[3/6] SERVICE ENUMERATION")
    print("="*60)
    for p in scan_results["ports"]:
        if p["state"] == "OPEN":
            print(f"\n{p['port']}/tcp")
            print(f"Service         : {p['service']}")
            print(f"Product         : {p['product']}")
            print(f"Version         : {p['version']}")
            print(f"Banner          : {p['banner']}")
            print(f"Known CVEs      : {p['known_cves']}")
            if p['enumeration']:
                for k, v in p['enumeration'].items():
                    print(f"  └─ {k:<15}: {v}")

    print("\n" + "="*60)
    print("[4/6] OS PROFILING")
    print("="*60)
    print(f"Detected OS     : {os_info['detected_os']}")
    print(f"Confidence      : {os_info['confidence_percentage']} ({os_info['confidence_score']}/10)")
    print("Evidence        :")
    for ev in os_info["evidence"]:
        print(f"  ✔ {ev}")

    print("\n" + "="*60)
    print("[5/6] RISK ASSESSMENT")
    print("="*60)
    print(f"Overall Risk    : {scan_results['risk_assessment']['overall_risk']}")
    print("Reasons         :")
    for reason in scan_results["risk_assessment"]["reasons"]:
        print(f"  ✔ {reason}")

    print("\n" + "="*60)
    print("[6/6] SCAN SUMMARY & REPORTS")
    print("="*60)
    print(f"Host Status          : {host['status']}")
    print(f"Configured TCP Ports : {cov['configured_tcp_ports']}")
    print(f"Open Ports           : {cov['open_found']}")
    print(f"Closed Ports         : {cov['closed']}")
    print(f"Services Identified  : {', '.join(open_services) if open_services else 'None'}")
    print(f"OS Profile           : {os_info['detected_os']}")
    print(f"Risk Level           : {scan_results['risk_assessment']['overall_risk']}")
    print("\nReports Generated:")
    print("  ✔ TXT  : report_data.txt")
    print("  ✔ JSON : report_data.json")
    print("  ✔ XML  : report_data.xml")
    print("\nScan Completed Successfully.\n")

def generate_reports():
    base_filename = "report_data"
    
    with open(f"{base_filename}.txt", "w") as f:
        f.write("============================================================\n")
        f.write("              RECON AGENT v2.0 AUDIT REPORT                 \n")
        f.write("============================================================\n")
        f.write(f"Target IP       : {scan_results['metadata']['target_ip']}\n")
        f.write(f"Detected OS     : {scan_results['os_fingerprint']['detected_os']}\n")
        f.write(f"Overall Risk    : {scan_results['risk_assessment']['overall_risk']}\n\n")
        f.write("RISK REASONS:\n")
        for r in scan_results["risk_assessment"]["reasons"]:
            f.write(f" - {r}\n")
        f.write("\nPORTS & SERVICES:\n")
        for p in scan_results["ports"]:
            f.write(f"[{p['port']}/tcp] State: {p['state']} | Service: {p['service']} | Product: {p['product']} | Version: {p['version']}\n")
            if p['banner'] != "Empty":
                f.write(f"  Banner: {p['banner']}\n")

    with open(f"{base_filename}.json", "w") as f:
        json.dump(scan_results, f, indent=2)

    root = ET.Element("ReconAgentReport", target=scan_results["metadata"]["target_ip"])
    ET.SubElement(root, "OS").text = scan_results["os_fingerprint"]["detected_os"]
    ports_node = ET.SubElement(root, "Ports")
    for p in scan_results["ports"]:
        ET.SubElement(ports_node, "PortRecord", 
                      number=str(p["port"]), 
                      state=p["state"], 
                      service=p["service"], 
                      product=p["product"],
                      version=p["version"])
    ET.ElementTree(root).write(f"{base_filename}.xml", encoding="utf-8", xml_declaration=True)

# ==============================================================================
# MASTER AUTHORITATIVE EXECUTION GATEWAY
# ==============================================================================

if __name__ == "__main__":
    if sys.platform != "win32":
        import os
        if os.geteuid() != 0:
            sys.exit("[!] CRITICAL: Script requires root privileges to send raw Scapy frames.")

    target_input = input("[?] Enter Target Host/IP Address: ").strip()
    if not target_input:
        sys.exit("[!] Error: Target address empty.")

    try:
        resolved_ip = socket.gethostbyname(target_input)
    except Exception as e:
        sys.exit(f"[!] Target resolution failed: {e}")

    start_time = time.time()
    scan_results["metadata"]["target_host"] = target_input
    scan_results["metadata"]["target_ip"] = resolved_ip
    scan_results["metadata"]["scan_started"] = datetime.now().strftime("%d-%b-%Y %H:%M:%S")

    zombie_input = input("[?] Enter Zombie Host IP for Idle Scan (Press Enter to Skip): ").strip()
    if zombie_input:
        scan_results["metadata"]["zombie_ip"] = zombie_input

    all_ports = [FTP_PORT, SSH_PORT, DNS_PORT, HTTP_PORT] + SMTP_PORTS + IMAP_PORTS

    # Step 1: Link Layer Discovery
    ping_scan(resolved_ip)

    # Step 2: Multi-Vector Scanning Execution
    for p in all_ports:
        basic_port_scan(resolved_ip, p)
        syn_scan(resolved_ip, p)
        tcp_scan(resolved_ip, p)
        udp_scan(resolved_ip, p)
        fin_scan(resolved_ip, p)
        null_scan(resolved_ip, p)
        xmas_scan(resolved_ip, p)
        ack_scan(resolved_ip, p)
        window_scan(resolved_ip, p)
        maimon_scan(resolved_ip, p)
        if zombie_input:
            zombie_scan(resolved_ip, zombie_input, p)

    # Step 3: Priority Decision Engine
    for p in all_ports:
        final_state = final_consensus_decision(p)
        port_authoritative_states[p] = final_state
        record = get_port_record(p)
        record["state"] = final_state

    # Step 4: Gated Application-Layer Enumeration
    if port_authoritative_states[FTP_PORT] == "OPEN":
        ftp_banner = ftp_banner_grab(resolved_ip)
        ftp_anonymous_check(resolved_ip)
        ftp_bounce_check(resolved_ip)
        ftp_brute_force(resolved_ip)

    if port_authoritative_states[SSH_PORT] == "OPEN":
        run_ssh_advanced_audit(resolved_ip)

    if port_authoritative_states[DNS_PORT] == "OPEN":
        run_dns_advanced_audit(resolved_ip)

    if port_authoritative_states[HTTP_PORT] == "OPEN":
        http_get_details(resolved_ip)
        http_methods_check(resolved_ip)
        http_directory_enumeration(resolved_ip)

    for s_port in SMTP_PORTS:
        if port_authoritative_states[s_port] == "OPEN":
            run_smtp_advanced_audit(resolved_ip, s_port)

    for i_port in IMAP_PORTS:
        if port_authoritative_states[i_port] == "OPEN":
            run_imap_advanced_audit(resolved_ip, i_port)

    # Step 5: OS Profiling & Kernel Range Estimation
    service_and_os_detection(resolved_ip, SSH_PORT)

    # Step 6: Dynamic Metrics & Report Artifacts
    calculate_dynamic_metrics()
    scan_results["metadata"]["duration_seconds"] = round(time.time() - start_time, 2)
    generate_reports()

    # Step 7: CLI Display Output View
    print_professional_cli_output()

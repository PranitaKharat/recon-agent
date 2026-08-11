import socket
import sys
import json
import xml.etree.ElementTree as ET
from xml.dom import minidom
import logging
import ssl
import re
import time
import struct
import os
import hashlib
import base64
import urllib.request
import urllib.parse
import urllib.error
from urllib.parse import urlparse

# Suppress Scapy IPv6/runtime warnings on startup
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, UDP, sr1, send, ICMP, DNS, DNSQR, DNSRROPT, RandShort, Raw

# Configuration Constants & Baseline Dynamic RTT Tracking
FTP_PORT = 21
TELNET_PORT = 23
SSH_PORT = 22
DNS_PORT = 53
KERBEROS_PORT = 88
HTTP_PORT = 80
HTTPS_PORT = 443
SMB_PORT = 445
RDP_PORT = 3389
ORACLE_PORT = 1521
MYSQL_PORT = 3306
POSTGRES_PORT = 5432
REDIS_PORT = 6379
MONGODB_PORT = 27017
SMTP_PORTS = [25, 465, 587]
IMAP_PORTS = [143, 993]
POP3_PORTS = [110, 995]
LDAP_PORTS = [389, 636]
DHCP_PORTS = [67, 68]
HTTPS_ALT_PORTS = [8443, 9443]
FTPS_IMPLICIT_DATA_PORT = 989
FTPS_IMPLICIT_CTRL_PORT = 990
FTPS_PORTS = [FTPS_IMPLICIT_DATA_PORT, FTPS_IMPLICIT_CTRL_PORT]
NTP_PORT = 123
TFTP_PORT = 69
SIP_PORT = 5060
SIP_TLS_PORT = 5061
SIP_PORTS = [SIP_PORT, SIP_TLS_PORT]
SNMP_PORT = 161
MSSQL_PORT = 1433
MSSQL_BROWSER_PORT = 1434
ELASTICSEARCH_PORT = 9200
DOCKER_PORT = 2375
DOCKER_TLS_PORT = 2376
K8S_API_PORT = 6443
KUBELET_PORT = 10250
WINRM_HTTP_PORT = 5985
WINRM_HTTPS_PORT = 5986
WINRM_PORTS = [WINRM_HTTP_PORT, WINRM_HTTPS_PORT]
VNC_PORTS = [5900, 5901, 5902, 5903]
MQTT_PORTS = [1883, 8883]
RABBITMQ_PORTS = [5672, 5671]
MEMCACHED_PORT = 11211
RPCBIND_PORT = 111
NFS_PORT = 2049
NFS_PORTS = [RPCBIND_PORT, NFS_PORT]
CASSANDRA_PORT = 9042
COUCHDB_PORT = 5984
NEO4J_HTTP_PORT = 7474
NEO4J_BOLT_PORT = 7687
NEO4J_PORTS = [NEO4J_HTTP_PORT, NEO4J_BOLT_PORT]
JENKINS_HTTP_PORT = 8080
JENKINS_JNLP_PORT = 50000
JENKINS_PORTS = [JENKINS_HTTP_PORT, JENKINS_JNLP_PORT]
GIT_DAEMON_PORT = 9418
IPP_CUPS_PORT = 631
GRAFANA_PORT = 3000
PROMETHEUS_PORT = 9090
KIBANA_PORT = 5601
KAFKA_PORT = 9092
ZOOKEEPER_PORT = 2181

DEFAULT_TIMEOUT = 2.0
MIN_TIMEOUT = 0.8
MAX_TIMEOUT = 6.0
MEASURED_RTT = None  # Calculated dynamically during network ping discovery

# Dynamic State Tracker & Core Priority Engine
port_votes = {}  # Format: { port: {"open": X, "closed": Y, "filtered": Z} }
detected_as_windows = False  # Track platform characteristics dynamically
port_authoritative_states = {}  # Definitive single state tracker

scan_results = {
    "target_ip": "",
    "zombie_ip": "Skipped",
    "network_discovery": {},
    "port_scans": {
        "21": {"service": "FTP/FTPS", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "22": {"service": "SSH", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "53": {"service": "DNS", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "88": {"service": "Kerberos", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "80": {"service": "HTTP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "443": {"service": "HTTPS", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "445": {"service": "SMB", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "3389": {"service": "RDP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "1521": {"service": "Oracle TNS Listener", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "3306": {"service": "MySQL", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "5432": {"service": "PostgreSQL", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "6379": {"service": "Redis", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "27017": {"service": "MongoDB", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "25": {"service": "SMTP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "465": {"service": "SMTP-SSL", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "587": {"service": "SMTP-Submission", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "143": {"service": "IMAP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "993": {"service": "IMAP-SSL", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "110": {"service": "POP3", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "995": {"service": "POP3-SSL", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "389": {"service": "LDAP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "636": {"service": "LDAP-SSL", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "67": {"service": "DHCP-Server", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "68": {"service": "DHCP-Client", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "23": {"service": "Telnet", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "989": {"service": "FTPS (Implicit-Data)", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "990": {"service": "FTPS (Implicit-Control)", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "8443": {"service": "HTTPS-Alt", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "9443": {"service": "HTTPS-Alt", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "123": {"service": "NTP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "69": {"service": "TFTP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "5060": {"service": "SIP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "5061": {"service": "SIP-TLS", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "161": {"service": "SNMP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "1433": {"service": "MSSQL", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "1434": {"service": "MSSQL-Browser", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "9200": {"service": "Elasticsearch", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "2375": {"service": "Docker-API", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "2376": {"service": "Docker-API-TLS", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "6443": {"service": "Kubernetes-API", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "10250": {"service": "Kubelet-API", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "5985": {"service": "WinRM-HTTP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "5986": {"service": "WinRM-HTTPS", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "5900": {"service": "VNC-Display-0", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "5901": {"service": "VNC-Display-1", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "5902": {"service": "VNC-Display-2", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "5903": {"service": "VNC-Display-3", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "1883": {"service": "MQTT", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "8883": {"service": "MQTT-SSL", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "5672": {"service": "RabbitMQ-AMQP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "5671": {"service": "RabbitMQ-AMQP-SSL", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "11211": {"service": "Memcached", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "111": {"service": "RPCBind", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "2049": {"service": "NFS", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        # TIER 2 NEW PORTS IN SCAN RESULTS
        "9042": {"service": "Cassandra-CQL", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "5984": {"service": "CouchDB", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "7474": {"service": "Neo4j-HTTP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "7687": {"service": "Neo4j-Bolt", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "8080": {"service": "Jenkins-HTTP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "50000": {"service": "Jenkins-JNLP", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "9418": {"service": "Git-Daemon", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "631": {"service": "IPP/CUPS", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        # TIER 3 NEW PORTS: Observability, Log Analytics, Streaming & Coordination
        "3000": {"service": "Grafana", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "9090": {"service": "Prometheus", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "5601": {"service": "Kibana", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "9092": {"service": "Apache Kafka", "version": "Not Evaluated", "scans": {}, "enumeration": {}},
        "2181": {"service": "Apache ZooKeeper", "version": "Not Evaluated", "scans": {}, "enumeration": {}}
    },
    "os_fingerprint": "Unknown",
    "risk_assessment": {}
}

def get_dynamic_timeout():
    """Calculates active operational timeout based on dynamic network baseline RTT."""
    if MEASURED_RTT is not None:
        calculated = MEASURED_RTT * 2.5
        return max(MIN_TIMEOUT, min(calculated, MAX_TIMEOUT))
    return DEFAULT_TIMEOUT

def log_silent(section, key, message, port=None):
    """Saves raw metrics strictly into background telemetry WITHOUT screen spam."""
    clean_msg = message.replace("[+]", "").replace("[-]", "").replace("[*]", "").replace("[HEURISTIC]", "").replace("[WARNING]", "").replace("[VULN]", "").strip()
    
    if port:
        port_str = str(port)
        if port_str in scan_results["port_scans"]:
            if section == "scans":
                scan_results["port_scans"][port_str]["scans"][key] = clean_msg
            elif section == "enumeration":
                scan_results["port_scans"][port_str]["enumeration"][key] = clean_msg
    else:
        if section == "discovery":
            scan_results["network_discovery"][key] = clean_msg
        elif section == "os":
            scan_results["os_fingerprint"] = clean_msg

def log_and_print(section, key, message, port=None):
    """Explicitly allowed to print ONLY during targeted application layer auditing."""
    print(message)
    log_silent(section, key, message, port)

def cast_vote(port, state, weight=1):
    """Registers weighted votes. High-trust scans get massive absolute veto weights."""
    if port not in port_votes:
        port_votes[port] = {"open": 0, "closed": 0, "filtered": 0}
    port_votes[port][state] += weight

def final_consensus_decision(port):
    """Strict Priority Decision Engine."""
    votes = port_votes.get(port, {"open": 0, "closed": 0, "filtered": 0})
    
    if votes["open"] >= 10:   return "OPEN"
    if votes["closed"] >= 10: return "CLOSED"
    
    max_state = max(votes, key=votes.get)
    if votes[max_state] == 0:
        return "FILTERED"
    if max_state == "filtered" and votes["filtered"] < 5:
        # Weight 5 only comes from an ICMP-confirmed block (destination/port
        # unreachable) - a confident "filtered" verdict. Weight 1 comes from
        # simply getting no response at all (e.g. a UDP probe nothing replied
        # to), which is genuinely ambiguous: it could be blocked, or just as
        # easily an open UDP service silently discarding a probe it didn't
        # recognize - the single most common UDP scanning outcome. Reporting
        # a bare "FILTERED" here claims certainty the evidence doesn't
        # support; nmap's own convention for exactly this evidence pattern is
        # "open|filtered", which is what was actually missing to match it
        # (e.g. on 68/udp, where a DHCP client silently drops unsolicited
        # packets exactly as an open-but-quiet service would).
        return "OPEN|FILTERED"
    return max_state.upper()

def send_http_raw_request(target, port, path="/", method="GET"):
    """Helper utility for raw HTTP probe operations."""
    timeout = get_dynamic_timeout()
    try:
        req = f"{method} {path} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: ReconScanner/2.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        s.sendall(req.encode('utf-8'))
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            resp += chunk
        s.close()
        
        resp_str = resp.decode('utf-8', errors='ignore')
        parts = resp_str.split("\r\n\r\n", 1)
        headers_raw = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""
        
        status_line = headers_raw.split("\r\n")[0] if headers_raw else ""
        headers = {}
        for line in headers_raw.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
                
        return status_line, headers, body
    except Exception as e:
        return "", {}, ""

# ==============================================================================
# 1. NETWORK PROTOCOL PROBE ENGINE WITH ADAPTIVE RTT CALCULATOR
# ==============================================================================

def ping_scan(target):
    global MEASURED_RTT
    print(f"[*] [Ping Scan] Verifying link layer context and calculating baseline RTT for {target}...")
    
    t_start = time.time()
    ans = sr1(IP(dst=target)/ICMP(), timeout=DEFAULT_TIMEOUT, verbose=0)
    t_end = time.time()
    
    if ans:
        MEASURED_RTT = t_end - t_start
        adaptive_t = get_dynamic_timeout()
        log_silent("discovery", "host_status", f"Host is up via ICMP Echo Reply. Measured RTT: {MEASURED_RTT*1000:.2f}ms. Adaptive Timeout: {adaptive_t:.2f}s")
        print(f"  [+] Host {target} is up via ICMP. Measured RTT: {MEASURED_RTT*1000:.2f}ms -> Dynamic Scan Timeout set to: {adaptive_t:.2f}s")
    else:
        log_silent("discovery", "host_status", f"No ICMP response. Reverting to default dynamic threshold {DEFAULT_TIMEOUT}s.")
        print(f"  [-] No ICMP response from {target}. Using default timeout threshold ({DEFAULT_TIMEOUT}s).")

def basic_port_scan(target, port):
    """HIGH TRUST CRITICAL SCAN (TCP CONNECT)"""
    timeout = get_dynamic_timeout()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
        if result == 0:
            log_silent("scans", "tcp_connect", "OPEN", port=port)
            cast_vote(port, "open", weight=10)
        else:
            log_silent("scans", "tcp_connect", "CLOSED", port=port)
            cast_vote(port, "closed", weight=10)
            # Deliberately NOT setting "version" here anymore: this only
            # reflects the TCP-connect probe, which is meaningless for
            # UDP-only services (bootpc/68, tftp/69, ntp/123, ...) - every
            # one of those has no TCP listener and would always land here,
            # which is exactly how port 68 ended up permanently labeled
            # "Port Closed" even when its actual (UDP) consensus state was
            # OPEN|FILTERED. The final per-port default is now set once,
            # after the full multi-vector consensus decision, from the
            # authoritative state - see execute_scan.
        s.close()
    except Exception as e:
        log_silent("scans", "tcp_connect", f"Exception: {e}", port=port)

def syn_scan(target, port):
    """HIGH TRUST CRITICAL SCAN (SYN STEALTH)"""
    timeout = get_dynamic_timeout()
    packet = IP(dst=target)/TCP(dport=port, flags="S")
    response = sr1(packet, timeout=timeout, verbose=0)
    if response and response.haslayer(TCP):
        if response[TCP].flags == 0x12: # SYN-ACK
            log_silent("scans", "syn_scan", "OPEN", port=port)
            cast_vote(port, "open", weight=10)
            send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=0) 
        elif response[TCP].flags == 0x14: # RST
            log_silent("scans", "syn_scan", "CLOSED", port=port)
            cast_vote(port, "closed", weight=10)
    else:
        log_silent("scans", "syn_scan", "FILTERED", port=port)
        cast_vote(port, "filtered", weight=2)

def tcp_scan(target, port):
    timeout = get_dynamic_timeout()
    syn_packet = IP(dst=target)/TCP(dport=port, flags="S", seq=1000)
    syn_ack = sr1(syn_packet, timeout=timeout, verbose=0)
    if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 0x12:
        ack_packet = IP(dst=target)/TCP(dport=port, flags="A", seq=1001, ack=syn_ack[TCP].seq + 1)
        send(ack_packet, verbose=0)
        log_silent("scans", "full_tcp", "OPEN", port=port)
        cast_vote(port, "open", weight=5)
        send(IP(dst=target)/TCP(dport=port, flags="R", seq=1002), verbose=0)
    else:
        log_silent("scans", "full_tcp", "Handshake Fail", port=port)

def get_udp_service_probe(port):
    """Returns specific UDP payload probes according to target port context.

    Note: port 68 (bootpc, the DHCP *client* port) deliberately has no
    dedicated probe here. A DHCP client only processes a BOOTREPLY (op=2)
    carrying the transaction ID it itself generated during a real lease
    negotiation - sending it a server-shaped DISCOVER (op=1) packet is
    protocol-nonsensical and any client implementation will just silently
    drop it, exactly as if nothing were listening. Previously this port
    reused the port-67 DHCPDISCOVER payload, which doesn't change the
    outcome (still silently dropped) but falsely implied server-style
    active probing was happening on a client port. Falls through to the
    generic empty-payload default below, so state comes from the plain
    ICMP-unreachable / no-response classification like any unprobed port -
    the same conservative treatment nmap gives 68/udp."""
    probes = {
        53:  DNS(rd=1, qd=DNSQR(qname="version.bind", qclass=3, qtype=16)),
        67:  Raw(b'\x01\x01\x06\x00' + b'\x00' * 232),
        69:  Raw(b'\x00\x01\x74\x65\x73\x74\x00\x6f\x63\x74\x65\x74\x00'),
        88:  Raw(b'\x6e\x81\x00\x00'),
        123: Raw(b'\x1b' + b'\x00' * 47),
        137: Raw(b'\x80\x90\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41'
                 b'\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41'
                 b'\x41\x41\x41\x00\x00\x21\x00\x01'),
        161: Raw(b'\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02'
                 b'\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06'
                 b'\x05\x2b\x06\x01\x02\x01\x05\x00'),
        500: Raw(b'\x00' * 28),
        11211: Raw(b'\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n'),
        5060: Raw(b'OPTIONS sip:ping@ping SIP/2.0\r\n'
                  b'Via: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bK-reconping\r\n'
                  b'Max-Forwards: 70\r\n'
                  b'To: <sip:ping@ping>\r\n'
                  b'From: <sip:recon@0.0.0.0>;tag=reconping\r\n'
                  b'Call-ID: reconping-probe\r\n'
                  b'CSeq: 1 OPTIONS\r\n'
                  b'Content-Length: 0\r\n\r\n')
    }
    return probes.get(port, Raw(b''))

def udp_scan(target, port):
    timeout = get_dynamic_timeout()
    probe_payload = get_udp_service_probe(port)
    
    packet = IP(dst=target)/UDP(sport=RandShort(), dport=port)/probe_payload
    response = sr1(packet, timeout=timeout, verbose=0)
    
    if response is None:
        log_silent("scans", "udp_scan", "OPEN|FILTERED", port=port)
        cast_vote(port, "filtered", weight=1)
    elif response.haslayer(UDP):
        log_silent("scans", "udp_scan", "UDP_OPEN", port=port)
        cast_vote(port, "open", weight=10)
    elif response.haslayer(ICMP):
        icmp_type = int(response[ICMP].type)
        icmp_code = int(response[ICMP].code)
        
        if icmp_type == 3:
            if icmp_code == 3:
                log_silent("scans", "udp_scan", "UDP_CLOSED", port=port)
                cast_vote(port, "closed", weight=10)
            elif icmp_code in [1, 2, 9, 10, 13]:
                log_silent("scans", "udp_scan", f"UDP_FILTERED (ICMP Code {icmp_code})", port=port)
                cast_vote(port, "filtered", weight=5)

def process_inverse_response(response, port, scan_type):
    global detected_as_windows
    if response is None:
        log_silent("scans", scan_type, "OPEN|FILTERED", port=port)
    elif response.haslayer(TCP) and response[TCP].flags == 0x14:
        if detected_as_windows:
            log_silent("scans", scan_type, "OPEN_RFC793_ANOMALY", port=port)
        else:
            log_silent("scans", scan_type, "CLOSED", port=port)

def fin_scan(target, port):
    timeout = get_dynamic_timeout()
    packet = IP(dst=target)/TCP(dport=port, flags="F")
    process_inverse_response(sr1(packet, timeout=timeout, verbose=0), port, "fin_scan")

def null_scan(target, port):
    timeout = get_dynamic_timeout()
    packet = IP(dst=target)/TCP(dport=port, flags="")
    process_inverse_response(sr1(packet, timeout=timeout, verbose=0), port, "null_scan")

def xmas_scan(target, port):
    timeout = get_dynamic_timeout()
    packet = IP(dst=target)/TCP(dport=port, flags="FPU")
    process_inverse_response(sr1(packet, timeout=timeout, verbose=0), port, "xmas_scan")

def ack_scan(target, port):
    timeout = get_dynamic_timeout()
    packet = IP(dst=target)/TCP(dport=port, flags="A")
    response = sr1(packet, timeout=timeout, verbose=0)
    if response is None:
        log_silent("scans", "ack_scan", "FILTERED", port=port)
    elif response.haslayer(TCP) and response[TCP].flags == 0x14:
        log_silent("scans", "ack_scan", "UNFILTERED", port=port)

def window_scan(target, port):
    timeout = get_dynamic_timeout()
    packet = IP(dst=target)/TCP(dport=port, flags="A")
    response = sr1(packet, timeout=timeout, verbose=0)
    if response and response.haslayer(TCP) and response[TCP].flags == 0x14:
        if response[TCP].window > 0:
            log_silent("scans", "window_scan", "OPEN_INDICATION", port=port)
        else:
            log_silent("scans", "window_scan", "CLOSED_INDICATION", port=port)
    else:
        log_silent("scans", "window_scan", "FILTERED", port=port)

def maimon_scan(target, port):
    timeout = get_dynamic_timeout()
    packet = IP(dst=target)/TCP(dport=port, flags="FA")
    response = sr1(packet, timeout=timeout, verbose=0)
    if response is None:
        log_silent("scans", "maimon_scan", "OPEN|FILTERED", port=port)
    elif response.haslayer(TCP) and response[TCP].flags == 0x14:
        log_silent("scans", "maimon_scan", "CLOSED", port=port)

def zombie_scan(target, zombie_ip, port):
    if not zombie_ip: return
    timeout = get_dynamic_timeout()
    try:
        p1 = sr1(IP(dst=zombie_ip)/TCP(flags="SA"), timeout=timeout, verbose=0)
        if not p1: return
        id1 = p1.id
        send(IP(src=zombie_ip, dst=target)/TCP(dport=port, flags="S"), verbose=0)
        p2 = sr1(IP(dst=zombie_ip)/TCP(flags="SA"), timeout=timeout, verbose=0)
        if not p2: return
        id2 = p2.id
        if id2 == id1 + 2:
            log_silent("scans", "zombie_scan", "OPEN_ZOMBIE", port=port)
        else:
            log_silent("scans", "zombie_scan", "CLOSED_ZOMBIE", port=port)
    except:
        pass

# ==============================================================================
# 2. HEURISTIC OS ESTIMATION ENGINE
# ==============================================================================

def _ttl_bucket(ttl):
    """Maps an observed TTL to the nearest common initial TTL (ceiling method),
    which is far more accurate than fixed ranges since routers decrement TTL by
    1 per hop and hop count varies widely between targets."""
    for initial in (32, 60, 64, 128, 255):
        if ttl <= initial:
            return initial
    return None

def _parse_tcp_options(tcp_layer):
    """Extracts MSS / Window Scale / option presence+order - a much stronger passive
    OS signal than TTL/window alone (p0f-style fingerprinting)."""
    opts = getattr(tcp_layer, "options", []) or []
    names = [o[0] for o in opts]
    mss = next((o[1] for o in opts if o[0] == "MSS"), None)
    wscale = next((o[1] for o in opts if o[0] == "WScale"), None)
    has_ts = "Timestamp" in names
    has_sack = "SAckOK" in names
    return {"names": names, "mss": mss, "wscale": wscale, "has_ts": has_ts, "has_sack": has_sack}

_TCP_IP_OS_EVIDENCE = None  # Cache: TCP/IP-layer fingerprint doesn't change between passes

def _collect_tcp_ip_os_evidence(target, port):
    """Active SYN-probe fingerprinting only (TTL/window/options). Split out
    from the banner-merge step so it can be collected once and re-used - the
    banner evidence isn't available until the application-layer audit modules
    (FTP/SSH/HTTP/SMTP/SMB/...) have actually run, which happens *after* this
    was previously being called, so the merge step below was always working
    with empty/'Not Evaluated' banner fields."""
    linux_score, windows_score, other_score = 0, 0, 0
    # Signal counts: independent checks that pointed a given direction, as
    # opposed to score (which is checks weighted by how discriminating they
    # are). Used downstream to keep confidence_percentage from overclaiming
    # on a single lucky signal - see the sample-size discount in
    # service_and_os_detection.
    linux_signals, windows_signals, other_signals = 0, 0, 0
    evidence = []
    responses_received = 0

    candidate_ports = [p for p, state in port_authoritative_states.items() if state == "OPEN"]
    if port not in candidate_ports:
        candidate_ports.insert(0, port)
    probe_ports = candidate_ports[:4] if candidate_ports else [port]

    for probe_port in probe_ports:
        pkt = sr1(
            IP(dst=target) / TCP(dport=probe_port, flags="S"),
            timeout=DEFAULT_TIMEOUT,
            verbose=0
        )
        if not (pkt and pkt.haslayer(TCP)):
            continue
        responses_received += 1

        ttl = pkt.ttl
        window = pkt[TCP].window
        df_bit = int(pkt.flags) & 0x2 if hasattr(pkt, "flags") else 0
        opt_info = _parse_tcp_options(pkt[TCP])

        bucket = _ttl_bucket(ttl)
        if bucket in (60, 64):
            linux_score += 3; linux_signals += 1
            evidence.append(f"Port {probe_port}: TTL={ttl} (initial~{bucket}, Linux/Unix-family)")
        elif bucket == 128:
            windows_score += 3; windows_signals += 1
            evidence.append(f"Port {probe_port}: TTL={ttl} (initial~128, Windows)")
        elif bucket == 255:
            other_score += 2; other_signals += 1
            evidence.append(f"Port {probe_port}: TTL={ttl} (initial~255, network device/Solaris/Cisco)")
        elif bucket == 32:
            windows_score += 1; windows_signals += 1
            evidence.append(f"Port {probe_port}: TTL={ttl} (initial~32, legacy Windows)")

        if window in (5840, 14600, 29200, 5720):
            linux_score += 2; linux_signals += 1
            evidence.append(f"Port {probe_port}: TCP Window={window} (Linux match)")
        elif window in (8192, 16384, 65535):
            windows_score += 2; windows_signals += 1
            evidence.append(f"Port {probe_port}: TCP Window={window} (Windows match)")
        elif window == 64240:
            evidence.append(f"Port {probe_port}: TCP Window=64240 (ambiguous - deferring to TCP options)")

        if opt_info["has_ts"] and opt_info["has_sack"] and opt_info["wscale"] not in (None, 0):
            linux_score += 2; linux_signals += 1
            evidence.append(f"Port {probe_port}: TCP Options include Timestamp+SACK+WScale={opt_info['wscale']} (Linux-style stack)")
        elif not opt_info["has_ts"] and opt_info["has_sack"]:
            windows_score += 2; windows_signals += 1
            evidence.append(f"Port {probe_port}: TCP Options exclude Timestamp but include SACK (Windows-style stack)")
        if opt_info["mss"] == 1460:
            evidence.append(f"Port {probe_port}: MSS=1460 (standard Ethernet, non-discriminating alone)")
        elif opt_info["mss"] == 1440:
            other_score += 1; other_signals += 1
            evidence.append(f"Port {probe_port}: MSS=1440 (common on VPN/tunneled or embedded stacks)")

        if df_bit:
            linux_score += 1
            evidence.append(f"Port {probe_port}: DF flag set")

    return {
        "linux_score": linux_score, "windows_score": windows_score, "other_score": other_score,
        "linux_signals": linux_signals, "windows_signals": windows_signals, "other_signals": other_signals,
        "evidence": evidence, "responses_received": responses_received, "probe_ports": probe_ports
    }


_LINUX_DISTRO_PATTERNS = [
    # (regex, canonical label) - ordered most-specific-first. Matched against
    # every collected banner/version string, not just SSH, since Apache/Nginx
    # Server headers and DHCP/SMB banners can also carry a distro tag.
    (r'\bubuntu\b', "Ubuntu"),
    (r'\bdebian\b', "Debian"),
    (r'\braspbian\b', "Raspbian"),
    (r'\bkali\b', "Kali Linux"),
    (r'\b(centos)\b', "CentOS"),
    (r'\b(red ?hat|rhel)\b', "Red Hat Enterprise Linux"),
    (r'\bfedora\b', "Fedora"),
    (r'\bamazon ?linux\b', "Amazon Linux"),
    (r'\balpine\b', "Alpine Linux"),
    (r'\b(opensuse|suse)\b', "SUSE"),
    (r'\barch ?linux\b', "Arch Linux"),
    (r'\bgentoo\b', "Gentoo"),
    (r'\bfreebsd\b', "FreeBSD"),
    (r'\bopenbsd\b', "OpenBSD"),
]

# Publicly documented Ubuntu release history: (release label, default kernel
# as shipped, the openssh-server and apache2 PACKAGE versions that release
# archived - sourced from Ubuntu's public package archive, not specific to
# any one target). TCP/IP fingerprinting alone (TTL/window/options) can only
# ever narrow an OS to a broad family - that's a real ceiling, not a bug, and
# is why nmap's own kernel-range answers are often wide too (its ~2,000-entry
# fingerprint DB is itself doing fuzzy matching). This table instead uses
# already-captured package versions as a release fingerprint: OpenSSH point
# releases and Apache point releases are each tied to one specific Ubuntu
# release, so an exact match on either (and agreement between both, when both
# are available) pins down a release - and therefore its known default
# kernel - far more precisely than TCP/IP heuristics can.
_UBUNTU_RELEASE_SIGNATURES = [
    ("Ubuntu 6.06 LTS (Dapper Drake)",  "2.6.15", "4.2", "2.0.55"),
    ("Ubuntu 8.04 LTS (Hardy Heron)",   "2.6.24", "4.7", "2.2.8"),
    ("Ubuntu 10.04 LTS (Lucid Lynx)",   "2.6.32", "5.3", "2.2.14"),
    ("Ubuntu 12.04 LTS (Precise Pangolin)", "3.2", "5.9", "2.2.22"),
    ("Ubuntu 14.04 LTS (Trusty Tahr)",  "3.13",  "6.6", "2.4.7"),
    ("Ubuntu 16.04 LTS (Xenial Xerus)", "4.4",   "7.2", "2.4.18"),
    ("Ubuntu 18.04 LTS (Bionic Beaver)","4.15",  "7.6", "2.4.29"),
    ("Ubuntu 20.04 LTS (Focal Fossa)",  "5.4",   "8.2", "2.4.41"),
    ("Ubuntu 22.04 LTS (Jammy Jellyfish)", "5.15", "8.9", "2.4.52"),
    ("Ubuntu 24.04 LTS (Noble Numbat)", "6.8",   "9.6", "2.4.58"),
]

def _infer_kernel_estimate(distro_label):
    """Cross-references already-captured OpenSSH/Apache package versions
    against known Ubuntu release history to narrow the OS-family verdict
    down to a specific release (and therefore a known default kernel),
    rather than leaving 'Linux' as a dead end once family is established.
    Only fires for Ubuntu (the table this tool carries); returns None
    otherwise rather than guessing outside what it actually has data for."""
    if distro_label != "Ubuntu":
        return None

    ssh_banner = scan_results["port_scans"].get("22", {}).get("version", "") or ""
    http_banner = scan_results["port_scans"].get("80", {}).get("version", "") or ""
    ssh_m = re.search(r'OpenSSH[_/](\d+\.\d+)', ssh_banner, re.IGNORECASE)
    http_m = re.search(r'Apache/(\d+\.\d+\.\d+)', http_banner, re.IGNORECASE)
    ssh_ver = ssh_m.group(1) if ssh_m else None
    http_ver = http_m.group(1) if http_m else None
    if not ssh_ver and not http_ver:
        return None

    for release, kernel, ref_ssh, ref_apache in _UBUNTU_RELEASE_SIGNATURES:
        ssh_match = ssh_ver == ref_ssh
        http_match = http_ver == ref_apache
        if ssh_match and http_match:
            return {
                "release": release, "kernel_estimate": kernel,
                "confidence": "high (OpenSSH and Apache package versions both independently match this release)",
                "basis": f"OpenSSH {ssh_ver} + Apache {http_ver}"
            }
        if ssh_match or http_match:
            matched_on = f"OpenSSH {ssh_ver}" if ssh_match else f"Apache {http_ver}"
            return {
                "release": release, "kernel_estimate": kernel,
                "confidence": f"medium (single package-version match on {matched_on} - not cross-confirmed by a second package)",
                "basis": matched_on
            }
    return None

def _infer_linux_distro(evidence_out):
    """Best-effort distro NAME extraction from already-collected banners.
    Deliberately does not attempt to guess a kernel/OS release number from
    an OpenSSH/Apache package version - that requires a distro package
    changelog database this tool doesn't have, and a wrong guess is worse
    than no guess. Distro *name* is different: it's very often stated
    verbatim in the banner (e.g. 'OpenSSH_8.9p1 Ubuntu-3ubuntu0.6',
    'Apache/2.4.41 (Ubuntu)') rather than inferred, so it's safe to surface."""
    hits = {}
    for port_key, pdata in scan_results["port_scans"].items():
        banner = pdata.get("version", "") or ""
        service = pdata.get("service", "") or ""
        text = f"{banner} {service}"
        for pattern, label in _LINUX_DISTRO_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                hits.setdefault(label, []).append(f"port {port_key}: {banner or service}")

    if not hits:
        return None, []

    if len(hits) == 1:
        label = next(iter(hits))
        for src in hits[label]:
            evidence_out.append(f"Distro Match ({label}): {src}")
        return label, hits[label]

    # Multiple distinct distro names showed up (unusual - e.g. a reverse
    # proxy fronting a differently-built backend). Report the one with the
    # most corroborating banners rather than silently picking one, and note
    # the conflict so it isn't presented as more certain than it is.
    ranked = sorted(hits.items(), key=lambda kv: -len(kv[1]))
    top_label, top_sources = ranked[0]
    for src in top_sources:
        evidence_out.append(f"Distro Match ({top_label}): {src}")
    conflicting = ", ".join(l for l, _ in ranked[1:])
    evidence_out.append(f"Note: conflicting distro banner(s) also seen ({conflicting}) - possible proxy/gateway in front of a different backend")
    return top_label, top_sources


def service_and_os_detection(target, port=SSH_PORT, refine_with_banners=False):
    """First call (before application-layer audits) does the active TCP/IP
    probe and gives a provisional verdict, and also sets detected_as_windows
    early enough for the inverse (FIN/NULL/XMAS) scan classifiers to use it.
    A second call with refine_with_banners=True, made after every service
    banner has actually been grabbed, re-merges the (cached, not re-probed)
    TCP/IP evidence with the now-populated banner text and overwrites the
    final verdict - this is what lets an OS-identifying banner (e.g.
    'Apache/2.4.41 (Ubuntu)', 'Microsoft ESMTP MAIL Service') actually move
    the needle instead of arriving too late to be counted."""
    global detected_as_windows, _TCP_IP_OS_EVIDENCE

    if _TCP_IP_OS_EVIDENCE is None or not refine_with_banners:
        _TCP_IP_OS_EVIDENCE = _collect_tcp_ip_os_evidence(target, port)

    tcp_ev = _TCP_IP_OS_EVIDENCE
    linux_score = tcp_ev["linux_score"]
    windows_score = tcp_ev["windows_score"]
    other_score = tcp_ev["other_score"]
    linux_signals = tcp_ev["linux_signals"]
    windows_signals = tcp_ev["windows_signals"]
    other_signals = tcp_ev["other_signals"]
    evidence = list(tcp_ev["evidence"])
    responses_received = tcp_ev["responses_received"]
    probe_ports = tcp_ev["probe_ports"]

    # Aggregate banner-derived evidence from every service module that ran, weighted by
    # how many distinct services agree, instead of stopping at the first match.
    linux_hits, windows_hits = 0, 0
    for port_key, pdata in scan_results["port_scans"].items():
        banner = pdata.get("version", "")
        service = pdata.get("service", "")
        text = f"{banner} {service}".lower()
        if any(x in text for x in ["ubuntu", "debian", "centos", "red hat", "linux", "openssh", "freebsd"]):
            linux_hits += 1
            evidence.append(f"Banner Match (Linux/Unix): {banner or service}")
        elif any(x in text for x in ["windows", "microsoft", "iis", " smb", "kerberos", "winrm", ".net"]):
            windows_hits += 1
            evidence.append(f"Banner Match (Windows): {banner or service}")
    linux_signals += linux_hits
    windows_signals += windows_hits
    linux_score += min(linux_hits, 3) * 3
    windows_score += min(windows_hits, 3) * 3

    if responses_received == 0 and linux_hits == 0 and windows_hits == 0:
        os_name = "Inconclusive - no TCP/IP or banner evidence collected"
        scan_results["os_fingerprint"] = {
            "detected_os": os_name,
            "confidence_score": 0,
            "confidence_percentage": "0%",
            "evidence": ["No SYN responses received on any sampled port, and no service banners yielded OS-identifying keywords."]
        }
        return os_name

    total_evidence = linux_score + windows_score + other_score
    MIN_EVIDENCE_THRESHOLD = 4  # Require a real signal before committing to a verdict

    distro_label = None
    kernel_info = None
    if windows_score > linux_score and windows_score >= MIN_EVIDENCE_THRESHOLD:
        detected_as_windows = True
        os_name = "Microsoft Windows Server / Desktop"
        winning_score = windows_score
        winning_signals = windows_signals
    elif linux_score > windows_score and linux_score >= MIN_EVIDENCE_THRESHOLD:
        detected_as_windows = False
        distro_label, _ = _infer_linux_distro(evidence)
        os_name = f"Linux / Unix-family ({distro_label})" if distro_label else "Linux / Unix-family (distro not identified from banners)"
        winning_score = linux_score
        winning_signals = linux_signals
        kernel_info = _infer_kernel_estimate(distro_label)
        if kernel_info:
            evidence.append(f"Kernel Estimate: ~{kernel_info['kernel_estimate']} via {kernel_info['release']} (matched on {kernel_info['basis']})")
    elif other_score >= MIN_EVIDENCE_THRESHOLD:
        os_name = "Non-Windows Network Appliance / Embedded Stack (e.g. Cisco, Solaris)"
        winning_score = other_score
        winning_signals = other_signals
    else:
        os_name = "Undetermined - insufficient corroborating evidence"
        winning_score = max(linux_score, windows_score, other_score)
        winning_signals = max(linux_signals, windows_signals, other_signals)

    # Raw score ratio alone overclaims on a thin sample - a single TTL match
    # (3 points) against zero counter-evidence would report "100% confidence"
    # off one data point, which is not a defensible confidence figure. Apply
    # a Laplace-style sample-size discount (winning_signals / (winning_signals+1))
    # on top of the score ratio: it climbs toward the raw ratio as independent
    # signals accumulate (1 signal -> 50% of raw ratio, 2 -> 67%, 4 -> 80%,
    # 8 -> 89%...) and stays conservative when the verdict rests on very
    # little. signal_count is reported alongside the percentage so the figure
    # is auditable rather than a black-box number.
    raw_ratio = (winning_score / total_evidence) if total_evidence else 0
    sample_discount = winning_signals / (winning_signals + 1) if winning_signals else 0
    conf_pct = f"{round(raw_ratio * sample_discount * 100)}%"

    scan_results["os_fingerprint"] = {
        "detected_os": os_name,
        "os_family": "Linux/Unix" if os_name.startswith("Linux") else ("Windows" if "Windows" in os_name else "Other/Undetermined"),
        "distro": distro_label,
        "kernel_estimate": f"~{kernel_info['kernel_estimate']} ({kernel_info['release']})" if kernel_info else None,
        "kernel_estimate_confidence": kernel_info["confidence"] if kernel_info else None,
        "confidence_score": winning_score,
        "confidence_percentage": conf_pct,
        "independent_signal_count": winning_signals,
        "sampled_ports": probe_ports,
        "responses_received": responses_received,
        "evidence": evidence,
        "note": "TCP/IP fingerprinting (TTL/window/options) alone can only establish OS family - that requires a full nmap/p0f-scale fingerprint database this tool doesn't carry, which is also why nmap's own kernel-range answers are often wide. kernel_estimate above (when present) instead comes from cross-referencing already-captured OpenSSH/Apache PACKAGE versions against known Ubuntu release history - a specific, sourced inference, not a live kernel probe. It is None whenever no such package-version match was found."
    }
    return os_name

# ==============================================================================
# 3. APPLICATION LAYER MODULES
# ==============================================================================

# 1. Cassandra Audit Module (Port 9042)
def run_cassandra_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "cassandra_init", f"[*] Auditing Apache Cassandra Database on {target}:{CASSANDRA_PORT}", port=CASSANDRA_PORT)
    
    cql_options_pkt = b"\x04\x00\x00\x00\x05\x00\x00\x00\x00"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, CASSANDRA_PORT))
        s.sendall(cql_options_pkt)
        resp = s.recv(1024)
        s.close()

        if resp and len(resp) >= 9 and (resp[0] & 0x80):
            scan_results["port_scans"][str(CASSANDRA_PORT)]["version"] = "Apache Cassandra Binary Protocol (CQL v4/v5)"
            log_and_print("enumeration", "cassandra_status", "  [+] Apache Cassandra Native Protocol active and responded to OPTIONS frame", port=CASSANDRA_PORT)
        else:
            scan_results["port_scans"][str(CASSANDRA_PORT)]["version"] = "Apache Cassandra Database Active"
            log_and_print("enumeration", "cassandra_status", "  [+] Cassandra CQL port open and responding", port=CASSANDRA_PORT)
    except Exception as e:
        log_and_print("enumeration", "cassandra_fault", f"  [-] Cassandra Audit Exception: {e}", port=CASSANDRA_PORT)

# 2. CouchDB Audit Module (Port 5984)
def run_couchdb_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "couchdb_init", f"[*] Auditing Apache CouchDB Database on {target}:{COUCHDB_PORT}", port=COUCHDB_PORT)
    try:
        status_line, headers, body = send_http_raw_request(target, COUCHDB_PORT, "/", method="GET")
        if "couchdb" in body.lower() or "welcome" in body.lower():
            ver_match = re.search(r'"version"\s*:\s*"(.*?)"', body)
            version = ver_match.group(1) if ver_match else "Detected"
            scan_results["port_scans"][str(COUCHDB_PORT)]["version"] = f"Apache CouchDB v{version}"
            log_and_print("enumeration", "couchdb_status", f"  [+] Apache CouchDB Verified | Version: {version}", port=COUCHDB_PORT)
        else:
            scan_results["port_scans"][str(COUCHDB_PORT)]["version"] = "CouchDB HTTP Interface Active"
            log_and_print("enumeration", "couchdb_status", "  [+] CouchDB REST API responding", port=COUCHDB_PORT)
    except Exception as e:
        log_and_print("enumeration", "couchdb_fault", f"  [-] CouchDB Audit Exception: {e}", port=COUCHDB_PORT)

# 3. Neo4j Audit Module (Ports 7474 / 7687)
def run_neo4j_advanced_audit(target, port):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "neo4j_init", f"[*] Auditing Neo4j Graph Database on {target}:{port}", port=port)
    try:
        if port == NEO4J_HTTP_PORT:
            status_line, headers, body = send_http_raw_request(target, port, "/", method="GET")
            if "neo4j" in body.lower() or "neo4j" in str(headers).lower():
                ver_match = re.search(r'"neo4j_version"\s*:\s*"(.*?)"', body)
                version = ver_match.group(1) if ver_match else "HTTP Web Browser Console Active"
                scan_results["port_scans"][str(port)]["version"] = f"Neo4j Server ({version})"
                log_and_print("enumeration", "neo4j_status", f"  [+] Neo4j HTTP Server Active | Details: {version}", port=port)
            else:
                scan_results["port_scans"][str(port)]["version"] = "Neo4j HTTP Service Active"
        elif port == NEO4J_BOLT_PORT:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            bolt_handshake = b"\x60\x60\xb0\x17" + b"\x00\x00\x00\x04" + b"\x00\x00\x00\x03" + b"\x00\x00\x00\x00" * 2
            s.sendall(bolt_handshake)
            resp = s.recv(4)
            s.close()
            if resp and len(resp) == 4:
                scan_results["port_scans"][str(port)]["version"] = "Neo4j Bolt Protocol Active"
                log_and_print("enumeration", "neo4j_bolt_status", "  [+] Neo4j Bolt protocol handshake accepted", port=port)
            else:
                scan_results["port_scans"][str(port)]["version"] = "Neo4j Bolt Listener Active"
    except Exception as e:
        log_and_print("enumeration", "neo4j_fault", f"  [-] Neo4j Audit Exception: {e}", port=port)

# 4. Jenkins Audit Module (Ports 8080 / 50000)
def run_jenkins_advanced_audit(target, port):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "jenkins_init", f"[*] Auditing Jenkins Automation Server on {target}:{port}", port=port)
    try:
        if port == JENKINS_HTTP_PORT:
            status_line, headers, body = send_http_raw_request(target, port, "/login", method="GET")
            jenkins_hdr = headers.get("x-jenkins") or headers.get("x-jenkins-cli-port")
            if jenkins_hdr or "jenkins" in body.lower():
                ver_str = headers.get("x-jenkins", "Active")
                scan_results["port_scans"][str(port)]["version"] = f"Jenkins Automation Server v{ver_str}"
                log_and_print("enumeration", "jenkins_status", f"  [+] Jenkins Web Interface Detected | Version Header: {ver_str}", port=port)
            else:
                scan_results["port_scans"][str(port)]["version"] = "HTTP Application Server Active"
        elif port == JENKINS_JNLP_PORT:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            s.sendall(b"Protocol:JNLP4-connect\r\n\r\n")
            resp = s.recv(512)
            s.close()
            if resp:
                scan_results["port_scans"][str(port)]["version"] = "Jenkins JNLP Slave Agent Listener"
                log_and_print("enumeration", "jenkins_jnlp_status", "  [+] Jenkins JNLP Agent port active and responding", port=port)
    except Exception as e:
        log_and_print("enumeration", "jenkins_fault", f"  [-] Jenkins Audit Exception: {e}", port=port)

# 5. Git Daemon Audit Module (Port 9418)
def run_git_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "git_init", f"[*] Auditing Git Daemon Service on {target}:{GIT_DAEMON_PORT}", port=GIT_DAEMON_PORT)
    
    git_pkt = b"0033git-upload-pack /noop\x00host=" + target.encode('utf-8') + b"\x00"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, GIT_DAEMON_PORT))
        s.sendall(git_pkt)
        resp = s.recv(1024).decode('utf-8', errors='ignore')
        s.close()

        if "ERR" in resp or "git-upload-pack" in resp or len(resp) > 0:
            scan_results["port_scans"][str(GIT_DAEMON_PORT)]["version"] = "Git Daemon Protocol Active"
            log_and_print("enumeration", "git_status", f"  [+] Git Daemon confirmed active | Response: {resp.strip()[:60]}", port=GIT_DAEMON_PORT)
        else:
            scan_results["port_scans"][str(GIT_DAEMON_PORT)]["version"] = "Git Service Listener"
    except Exception as e:
        log_and_print("enumeration", "git_fault", f"  [-] Git Audit Exception: {e}", port=GIT_DAEMON_PORT)

# 6. IPP / CUPS Audit Module (Port 631)
def run_ipp_cups_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "ipp_init", f"[*] Auditing IPP/CUPS Print Service on {target}:{IPP_CUPS_PORT}", port=IPP_CUPS_PORT)
    try:
        status_line, headers, body = send_http_raw_request(target, IPP_CUPS_PORT, "/", method="GET")
        server_hdr = headers.get("server", "")
        if "cups" in server_hdr.lower() or "cups" in body.lower() or "ipp" in status_line.lower():
            scan_results["port_scans"][str(IPP_CUPS_PORT)]["version"] = f"CUPS Print Server ({server_hdr or 'Active'})"
            log_and_print("enumeration", "ipp_status", f"  [+] CUPS Print Service Active | Server Header: {server_hdr}", port=IPP_CUPS_PORT)
        else:
            scan_results["port_scans"][str(IPP_CUPS_PORT)]["version"] = "IPP Print Listener Active"
            log_and_print("enumeration", "ipp_status", "  [+] IPP Port 631 open and responding to HTTP probes", port=IPP_CUPS_PORT)
    except Exception as e:
        log_and_print("enumeration", "ipp_fault", f"  [-] IPP/CUPS Audit Exception: {e}", port=IPP_CUPS_PORT)

# 7. Grafana Audit Module (Port 3000)
def run_grafana_advanced_audit(target, port=GRAFANA_PORT):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "grafana_init", f"[*] Auditing Grafana Observability Platform on {target}:{port}", port=port)
    try:
        confirmed = False
        version, db_status, anon_status = "Unknown", "Unknown", "Unknown"

        status_line, headers, body = send_http_raw_request(target, port, "/api/health", method="GET")
        if "200" in status_line and body:
            try:
                data = json.loads(body)
                if "version" in data:
                    confirmed = True
                    version = data.get("version", "Unknown")
                    db_status = data.get("database", "Unknown")
                    log_and_print("enumeration", "grafana_version", f"  [+] Grafana Version (via /api/health): {version}", port=port)
                    log_and_print("enumeration", "grafana_db_status", f"  [+] Internal Database Status: {db_status}", port=port)
            except (json.JSONDecodeError, ValueError):
                pass
        if not confirmed:
            log_and_print("enumeration", "grafana_health_fail", f"  [-] /api/health did not return the expected Grafana JSON schema (status: {status_line or 'no response'})", port=port)

        status_line2, headers2, body2 = send_http_raw_request(target, port, "/api/dashboards/home", method="GET")
        if "200" in status_line2:
            confirmed = True
            anon_status = "Anonymous Access ENABLED"
            log_and_print("enumeration", "grafana_anon_access", "  [VULN] Anonymous Access ENABLED - /api/dashboards/home reachable without any authentication", port=port)
        elif any(code in status_line2 for code in ("401", "403", "302")):
            anon_status = "Authentication Required"
            log_and_print("enumeration", "grafana_auth_required", f"  [+] Authentication Required (dashboards endpoint responded: {status_line2 or 'redirect/denied'})", port=port)
        else:
            log_and_print("enumeration", "grafana_anon_undetermined", f"  [-] Could not determine anonymous-access posture (response: {status_line2 or 'none'})", port=port)

        status_line3, headers3, body3 = send_http_raw_request(target, port, "/api/org", method="GET")
        if "200" in status_line3 and body3:
            try:
                org_data = json.loads(body3)
                if "name" in org_data or "id" in org_data:
                    confirmed = True
                    log_and_print("enumeration", "grafana_org", f"  [+] Organization Info Exposed -> Name: {org_data.get('name', 'Unknown')}, ID: {org_data.get('id', 'Unknown')}", port=port)
            except (json.JSONDecodeError, ValueError):
                pass
        else:
            log_and_print("enumeration", "grafana_org_protected", "  [+] Organization info endpoint (/api/org) requires authentication (expected/secure)", port=port)

        scan_results["port_scans"][str(port)]["version"] = (
            f"Grafana v{version} | DB: {db_status} | {anon_status}" if confirmed
            else "Grafana-like HTTP service (unconfirmed - API schema mismatch)"
        )
    except Exception as e:
        log_and_print("enumeration", "grafana_fault", f"  [-] Grafana Audit Exception: {e}", port=port)

# 8. Prometheus Audit Module (Port 9090)
def run_prometheus_advanced_audit(target, port=PROMETHEUS_PORT):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "prometheus_init", f"[*] Auditing Prometheus Monitoring Server on {target}:{port}", port=port)
    try:
        confirmed = False
        version, target_summary = "Unknown", "Unavailable"

        status_line, headers, body = send_http_raw_request(target, port, "/api/v1/status/buildinfo", method="GET")
        if "200" in status_line and body:
            try:
                data = json.loads(body)
                if data.get("status") == "success" and "data" in data:
                    confirmed = True
                    version = data["data"].get("version", "Unknown")
                    revision = data["data"].get("revision", "N/A")
                    log_and_print("enumeration", "prometheus_version", f"  [+] Prometheus Version: {version} (Revision: {revision})", port=port)
            except (json.JSONDecodeError, ValueError):
                pass
        if not confirmed:
            log_and_print("enumeration", "prometheus_buildinfo_fail", f"  [-] /api/v1/status/buildinfo did not match the expected Prometheus JSON schema (status: {status_line or 'no response'})", port=port)

        status_line2, headers2, body2 = send_http_raw_request(target, port, "/api/v1/targets", method="GET")
        if "200" in status_line2 and body2:
            try:
                tdata = json.loads(body2)
                if tdata.get("status") == "success":
                    confirmed = True
                    active = tdata.get("data", {}).get("activeTargets", [])
                    dropped = tdata.get("data", {}).get("droppedTargets", [])
                    target_summary = f"{len(active)} active / {len(dropped)} dropped"
                    log_and_print("enumeration", "prometheus_targets", f"  [+] Scrape Targets Exposed -> {target_summary}", port=port)
            except (json.JSONDecodeError, ValueError):
                pass

        status_line3, headers3, body3 = send_http_raw_request(target, port, "/api/v1/status/config", method="GET")
        if "200" in status_line3 and body3:
            try:
                cdata = json.loads(body3)
                if cdata.get("status") == "success":
                    confirmed = True
                    log_and_print("enumeration", "prometheus_config_exposed", "  [VULN] Full running configuration exposed via /api/v1/status/config (scrape_configs may reveal internal hosts/credentials)", port=port)
            except (json.JSONDecodeError, ValueError):
                pass
        else:
            log_and_print("enumeration", "prometheus_config_protected", "  [+] Configuration endpoint not exposed / requires authentication", port=port)

        status_line4, headers4, body4 = send_http_raw_request(target, port, "/metrics", method="GET")
        if "200" in status_line4 and "# HELP" in body4:
            confirmed = True
            metric_families = len([l for l in body4.split("\n") if l.startswith("# HELP")])
            log_and_print("enumeration", "prometheus_metrics", f"  [+] Native /metrics Endpoint Exposed -> {metric_families} distinct metric families", port=port)

        scan_results["port_scans"][str(port)]["version"] = (
            f"Prometheus v{version} | Targets: {target_summary}" if confirmed
            else "Prometheus-like HTTP service (unconfirmed - API schema mismatch)"
        )
    except Exception as e:
        log_and_print("enumeration", "prometheus_fault", f"  [-] Prometheus Audit Exception: {e}", port=port)

# 9. Kibana Audit Module (Port 5601)
def run_kibana_advanced_audit(target, port=KIBANA_PORT):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "kibana_init", f"[*] Auditing Kibana Analytics Dashboard on {target}:{port}", port=port)
    try:
        confirmed = False
        version, es_status = "Unknown", "Unknown"

        status_line, headers, body = send_http_raw_request(target, port, "/api/status", method="GET")
        if "200" in status_line and body:
            try:
                data = json.loads(body)
                if "version" in data and "status" in data:
                    confirmed = True
                    version = data.get("version", {}).get("number", "Unknown")
                    log_and_print("enumeration", "kibana_version", f"  [+] Kibana Version: {version}", port=port)
                    for svc in data.get("status", {}).get("statuses", []):
                        sid = svc.get("id", "")
                        if "elasticsearch" in sid.lower():
                            es_status = svc.get("state", svc.get("level", "unknown"))
                            log_and_print("enumeration", "kibana_es_connectivity", f"  [+] Elasticsearch Connectivity ({sid}): {es_status}", port=port)
            except (json.JSONDecodeError, ValueError):
                pass

        if not confirmed:
            status_line_root, headers_root, body_root = send_http_raw_request(target, port, "/", method="GET")
            kbn_ver_match = re.search(r'kbn-version["\']?\s*content=["\'](.*?)["\']', body_root, re.IGNORECASE)
            if kbn_ver_match or "kibana" in body_root.lower():
                confirmed = True
                version = kbn_ver_match.group(1) if kbn_ver_match else "Detected (HTML fallback, exact build unknown)"
                log_and_print("enumeration", "kibana_fallback", f"  [+] Kibana identified via HTML/meta fallback | Version hint: {version}", port=port)
            else:
                log_and_print("enumeration", "kibana_unconfirmed", f"  [-] /api/status did not match the expected Kibana JSON schema (status: {status_line or 'no response'})", port=port)

        status_line2, headers2, body2 = send_http_raw_request(target, port, "/api/saved_objects/_find?type=dashboard", method="GET")
        if "200" in status_line2:
            try:
                sdata = json.loads(body2)
                total = sdata.get("total", 0)
                log_and_print("enumeration", "kibana_dashboards_exposed", f"  [VULN] Saved dashboards accessible WITHOUT authentication -> {total} dashboard object(s) exposed", port=port)
            except (json.JSONDecodeError, ValueError):
                log_and_print("enumeration", "kibana_dashboards_exposed", "  [VULN] Saved-objects endpoint returned 200 without authentication", port=port)
        elif any(code in status_line2 for code in ("401", "403")):
            log_and_print("enumeration", "kibana_auth_required", "  [+] Authentication Required for saved objects/dashboards (expected/secure)", port=port)
        else:
            log_and_print("enumeration", "kibana_dashboards_undetermined", f"  [-] Could not determine dashboard exposure (response: {status_line2 or 'none'})", port=port)

        scan_results["port_scans"][str(port)]["version"] = (
            f"Kibana v{version} | Elasticsearch: {es_status}" if confirmed
            else "Kibana-like HTTP service (unconfirmed - API schema mismatch)"
        )
    except Exception as e:
        log_and_print("enumeration", "kibana_fault", f"  [-] Kibana Audit Exception: {e}", port=port)

# 10. Apache Kafka Audit Module (Port 9092)
KAFKA_API_KEY_NAMES = {
    0: "Produce", 1: "Fetch", 2: "ListOffsets", 3: "Metadata", 8: "OffsetCommit",
    9: "OffsetFetch", 10: "FindCoordinator", 11: "JoinGroup", 12: "Heartbeat",
    13: "LeaveGroup", 14: "SyncGroup", 17: "SaslHandshake", 18: "ApiVersions",
    19: "CreateTopics", 20: "DeleteTopics", 36: "SaslAuthenticate",
    68: "DescribeCluster", 74: "DescribeQuorum"
}

def kafka_recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf

def build_kafka_request(api_key, api_version, correlation_id, body, client_id=b"recon-audit"):
    client_id_field = struct.pack('>h', len(client_id)) + client_id
    header = struct.pack('>hh', api_key, api_version) + struct.pack('>i', correlation_id) + client_id_field
    payload = header + body
    return struct.pack('>i', len(payload)) + payload

def run_kafka_advanced_audit(target, port=KAFKA_PORT):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "kafka_init", f"[*] Auditing Apache Kafka Broker on {target}:{port} (Native Protocol Handshake)", port=port)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))

        req = build_kafka_request(18, 0, 1001, b"")
        s.sendall(req)
        size_bytes = kafka_recv_exact(s, 4)
        if len(size_bytes) < 4:
            log_and_print("enumeration", "kafka_no_response", "  [-] No valid length-prefixed Kafka frame received - port is likely not a Kafka broker", port=port)
            s.close()
            return
        msg_size = struct.unpack('>i', size_bytes)[0]
        body = kafka_recv_exact(s, msg_size)
        if len(body) < 10:
            log_and_print("enumeration", "kafka_short_frame", "  [-] Kafka response frame too short to parse as ApiVersionsResponse", port=port)
            s.close()
            return

        corr_id = struct.unpack('>i', body[0:4])[0]
        if corr_id != 1001:
            log_and_print("enumeration", "kafka_corr_mismatch", "  [-] Correlation ID mismatch on ApiVersions response - rejecting as unconfirmed (not treated as Kafka)", port=port)
            s.close()
            return

        error_code = struct.unpack('>h', body[4:6])[0]
        num_apis = struct.unpack('>i', body[6:10])[0]
        pos = 10
        api_versions = []
        for _ in range(num_apis):
            if pos + 6 > len(body):
                break
            api_key, min_v, max_v = struct.unpack('>hhh', body[pos:pos + 6])
            api_versions.append((api_key, min_v, max_v))
            pos += 6

        log_and_print("enumeration", "kafka_confirmed", f"  [+] Kafka Broker CONFIRMED (ApiVersions handshake verified, correlation ID matched) | ErrorCode: {error_code}", port=port)
        log_and_print("enumeration", "kafka_api_count", f"  [+] Supported API Keys Advertised: {len(api_versions)}", port=port)

        max_by_key = {k: mx for k, mn, mx in api_versions}
        av_max = max_by_key.get(18)
        if av_max is not None and av_max >= 3:
            version_hint = "Kafka 2.4.0+ (flexible/tagged-field schema versions supported)"
        elif av_max == 2:
            version_hint = "Kafka 1.0.0 - 2.3.x range"
        elif av_max == 1:
            version_hint = "Kafka 0.11.0 - 0.10.x range"
        elif av_max == 0:
            version_hint = "Kafka 0.10.0.x (earliest ApiVersions support)"
        else:
            version_hint = "Unknown range (ApiVersions API not advertised)"
        if 68 in max_by_key:
            version_hint += " | DescribeCluster present -> Kafka 2.8.0+"
        if 74 in max_by_key:
            version_hint += " | DescribeQuorum present -> KRaft-capable (Kafka 2.8+/3.x)"
        log_and_print("enumeration", "kafka_version_hint", f"  [+] Broker Version Range (inferred from API schema evolution): {version_hint}", port=port)

        sample = [f"{KAFKA_API_KEY_NAMES.get(k, f'API-{k}')}(v{mn}-{mx})" for k, mn, mx in sorted(api_versions, key=lambda x: x[0])[:15]]
        log_and_print("enumeration", "kafka_api_list", f"  [+] Sample Supported APIs: {', '.join(sample)}" + (" ..." if len(api_versions) > 15 else ""), port=port)

        cluster_id, controller_id, broker_list, topic_count = None, None, [], None
        try:
            meta_req = build_kafka_request(3, 2, 1002, struct.pack('>i', -1))
            s.sendall(meta_req)
            m_size_bytes = kafka_recv_exact(s, 4)
            if len(m_size_bytes) == 4:
                m_size = struct.unpack('>i', m_size_bytes)[0]
                m_body = kafka_recv_exact(s, m_size)
                mpos = 4
                brokers_len = struct.unpack('>i', m_body[mpos:mpos + 4])[0]; mpos += 4
                for _ in range(brokers_len):
                    node_id = struct.unpack('>i', m_body[mpos:mpos + 4])[0]; mpos += 4
                    host_len = struct.unpack('>h', m_body[mpos:mpos + 2])[0]; mpos += 2
                    host = m_body[mpos:mpos + host_len].decode('utf-8', errors='ignore'); mpos += host_len
                    b_port = struct.unpack('>i', m_body[mpos:mpos + 4])[0]; mpos += 4
                    rack_len = struct.unpack('>h', m_body[mpos:mpos + 2])[0]; mpos += 2
                    if rack_len >= 0:
                        mpos += rack_len
                    broker_list.append(f"{host}:{b_port} (id={node_id})")
                cid_len = struct.unpack('>h', m_body[mpos:mpos + 2])[0]; mpos += 2
                if cid_len >= 0:
                    cluster_id = m_body[mpos:mpos + cid_len].decode('utf-8', errors='ignore'); mpos += cid_len
                controller_id = struct.unpack('>i', m_body[mpos:mpos + 4])[0]; mpos += 4
                topic_count = struct.unpack('>i', m_body[mpos:mpos + 4])[0]

                log_and_print("enumeration", "kafka_cluster_id", f"  [+] Cluster ID: {cluster_id or 'N/A (older broker, field absent)'}", port=port)
                log_and_print("enumeration", "kafka_controller", f"  [+] Controller Broker ID: {controller_id}", port=port)
                log_and_print("enumeration", "kafka_brokers", f"  [+] Cluster Brokers ({len(broker_list)}): {', '.join(broker_list) if broker_list else 'N/A'}", port=port)
                log_and_print("enumeration", "kafka_topics", f"  [+] Topics Visible Without Authentication: {topic_count}", port=port)
                if topic_count and topic_count > 0:
                    log_and_print("enumeration", "kafka_topic_exposure", "  [VULN] Topic metadata enumerable without any authentication (ACL/SASL may not be enforced on the Metadata API)", port=port)
        except Exception:
            log_and_print("enumeration", "kafka_metadata_note", "  [-] Metadata request (cluster ID/topics) did not complete - broker may enforce authentication beyond the ApiVersions pre-auth stage", port=port)

        s.close()
        sec_note = "PLAINTEXT (unauthenticated wire access confirmed)" if error_code == 0 else f"Handshake returned ErrorCode {error_code}"
        scan_results["port_scans"][str(port)]["version"] = f"Apache Kafka | {version_hint} | Cluster: {cluster_id or 'N/A'} | {sec_note}"
    except Exception as e:
        log_and_print("enumeration", "kafka_fault", f"  [-] Kafka Protocol Handshake Exception: {e}", port=port)

# 11. Apache ZooKeeper Audit Module (Port 2181)
def send_zk_four_letter_command(target, port, command, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    resp = b""
    try:
        s.connect((target, port))
        s.sendall(command.encode('ascii'))
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
    except socket.timeout:
        pass
    finally:
        s.close()
    return resp.decode('utf-8', errors='ignore')

def run_zookeeper_advanced_audit(target, port=ZOOKEEPER_PORT):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "zookeeper_init", f"[*] Auditing Apache ZooKeeper Coordination Service on {target}:{port} (Four-Letter-Word Admin Commands)", port=port)
    try:
        version_str, mode_str, conn_count = "Unknown", "Unknown", "Unknown"

        ruok_resp = send_zk_four_letter_command(target, port, "ruok", timeout)
        if "imok" in ruok_resp:
            log_and_print("enumeration", "zookeeper_ruok", "  [+] 'ruok' -> imok (ZooKeeper liveness confirmed)", port=port)
        elif "not in the whitelist" in ruok_resp.lower():
            log_and_print("enumeration", "zookeeper_whitelist", "  [-] Four-letter-word commands are restricted by '4lw.commands.whitelist' (hardened configuration)", port=port)
        elif not ruok_resp:
            log_and_print("enumeration", "zookeeper_no_response", "  [-] No response to 'ruok' probe - port may not be ZooKeeper, or 4lw commands are fully disabled", port=port)

        mntr_resp = send_zk_four_letter_command(target, port, "mntr", timeout)
        if mntr_resp and "not in the whitelist" not in mntr_resp.lower() and "zk_version" in mntr_resp:
            mntr_data = {}
            for line in mntr_resp.strip().split("\n"):
                if "\t" in line:
                    k, v = line.split("\t", 1)
                    mntr_data[k.strip()] = v.strip()
            version_str = mntr_data.get("zk_version", version_str)
            mode_str = mntr_data.get("zk_server_state", mode_str)
            conn_count = mntr_data.get("zk_num_alive_connections", conn_count)
            log_and_print("enumeration", "zookeeper_mntr", f"  [+] 'mntr' -> Version: {version_str} | Server Mode: {mode_str} | Alive Connections: {conn_count}", port=port)
            if "zk_followers" in mntr_data:
                log_and_print("enumeration", "zookeeper_ensemble", f"  [+] Ensemble Info -> Followers: {mntr_data.get('zk_followers')}, Synced Followers: {mntr_data.get('zk_synced_followers', 'N/A')}", port=port)
        else:
            srvr_resp = send_zk_four_letter_command(target, port, "srvr", timeout)
            if srvr_resp and "not in the whitelist" not in srvr_resp.lower() and "Zookeeper version" in srvr_resp:
                ver_match = re.search(r'Zookeeper version:\s*(.*)', srvr_resp)
                mode_match = re.search(r'Mode:\s*(\w+)', srvr_resp)
                conn_match = re.search(r'Connections:\s*(\d+)', srvr_resp)
                version_str = ver_match.group(1).strip() if ver_match else version_str
                mode_str = mode_match.group(1).strip() if mode_match else mode_str
                conn_count = conn_match.group(1).strip() if conn_match else conn_count
                log_and_print("enumeration", "zookeeper_srvr", f"  [+] 'srvr' -> Version: {version_str} | Mode: {mode_str} | Connections: {conn_count}", port=port)
            else:
                log_and_print("enumeration", "zookeeper_admin_restricted", "  [-] Both 'mntr' and 'srvr' were restricted/unavailable - version and mode could not be confirmed", port=port)

        conf_resp = send_zk_four_letter_command(target, port, "conf", timeout)
        if conf_resp and "not in the whitelist" not in conf_resp.lower() and "=" in conf_resp:
            conf_summary = []
            for key in ["clientPort", "dataDir", "dataLogDir", "tickTime", "maxClientCnxns", "minSessionTimeout", "maxSessionTimeout", "serverId"]:
                m = re.search(rf'{key}=(.*)', conf_resp)
                if m:
                    conf_summary.append(f"{key}={m.group(1).strip()}")
            log_and_print("enumeration", "zookeeper_conf", f"  [+] 'conf' -> Configuration Exposed: {' | '.join(conf_summary) if conf_summary else conf_resp.strip()[:150]}", port=port)
        else:
            log_and_print("enumeration", "zookeeper_conf_restricted", "  [-] 'conf' command restricted or returned nothing", port=port)

        cons_resp = send_zk_four_letter_command(target, port, "cons", timeout)
        if cons_resp and "not in the whitelist" not in cons_resp.lower():
            client_lines = [l for l in cons_resp.strip().split("\n") if l.strip()]
            if client_lines:
                log_and_print("enumeration", "zookeeper_cons", f"  [+] 'cons' -> {len(client_lines)} connected client session(s) enumerated", port=port)
                log_and_print("enumeration", "zookeeper_cons_sample", f"    [+] Sample Client Entry: {client_lines[0].strip()[:150]}", port=port)
            else:
                log_and_print("enumeration", "zookeeper_cons_empty", "  [+] 'cons' -> command accepted, no active client sessions reported", port=port)
        else:
            log_and_print("enumeration", "zookeeper_cons_restricted", "  [-] 'cons' command restricted or returned nothing (connected-client enumeration unavailable)", port=port)

        scan_results["port_scans"][str(port)]["version"] = f"Apache ZooKeeper v{version_str} | Mode: {mode_str} | Alive Connections: {conn_count}"
    except Exception as e:
        log_and_print("enumeration", "zookeeper_fault", f"  [-] ZooKeeper Audit Exception: {e}", port=port)

# EXISTING MODULES:

def run_winrm_advanced_audit(target, port):
    timeout = get_dynamic_timeout()
    use_ssl = (port == WINRM_HTTPS_PORT)
    log_and_print("enumeration", "winrm_init", f"[*] Auditing WinRM Service on {target}:{port} (SSL={use_ssl})", port=port)
    
    post_payload = (
        f"POST /wsman HTTP/1.1\r\n"
        f"Host: {target}:{port}\r\n"
        f"User-Agent: WinRM-Audit-Engine\r\n"
        f"Content-Type: application/soap+xml;charset=UTF-8\r\n"
        f"Content-Length: 0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode('utf-8')
    
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(raw_sock, server_hostname=target)
        else:
            s = raw_sock
            
        s.connect((target, port))
        s.sendall(post_payload)
        resp = s.recv(2048).decode('utf-8', errors='ignore')
        s.close()

        if "401" in resp or "Server: Microsoft-HTTPAPI" in resp or "wsman" in resp.lower():
            server_header = "Microsoft WinRM (HTTPAPI/2.0)"
            for line in resp.split("\r\n"):
                if line.lower().startswith("server:"):
                    server_header = line.split(":", 1)[1].strip()
            scan_results["port_scans"][str(port)]["version"] = f"{server_header} - Auth Required (401)"
            log_and_print("enumeration", "winrm_status", f"  [+] WinRM Service Active | Server Header: {server_header}", port=port)
        else:
            scan_results["port_scans"][str(port)]["version"] = "WinRM Management Endpoint Responding"
            log_and_print("enumeration", "winrm_status", "  [+] WinRM Port open and responding to WS-Man request", port=port)
    except Exception as e:
        log_and_print("enumeration", "winrm_fault", f"  [-] WinRM Audit Error: {e}", port=port)

def run_vnc_advanced_audit(target, port):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "vnc_init", f"[*] Auditing VNC (RFB Protocol) Service on {target}:{port}", port=port)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        
        if banner.startswith("RFB"):
            scan_results["port_scans"][str(port)]["version"] = f"VNC Server ({banner})"
            log_and_print("enumeration", "vnc_banner", f"  [+] VNC Server RFB Protocol Version: {banner}", port=port)
            s.sendall(banner.encode('utf-8') + b"\n")
            time.sleep(0.2)
            auth_data = s.recv(1024)
            if auth_data:
                log_and_print("enumeration", "vnc_auth", f"  [+] VNC Security Type Negotiation Received ({len(auth_data)} bytes)", port=port)
        else:
            scan_results["port_scans"][str(port)]["version"] = "VNC / RFB Compatible Interface"
            log_and_print("enumeration", "vnc_status", f"  [+] Port {port} responded with non-standard banner", port=port)
        s.close()
    except Exception as e:
        log_and_print("enumeration", "vnc_fault", f"  [-] VNC Handshake Error: {e}", port=port)

def run_mqtt_advanced_audit(target, port):
    timeout = get_dynamic_timeout()
    use_ssl = (port == 8883)
    log_and_print("enumeration", "mqtt_init", f"[*] Auditing MQTT Messaging Broker on {target}:{port} (SSL={use_ssl})", port=port)
    
    mqtt_connect_pkt = b"\x10\x12\x00\x04MQTT\x04\x02\x00\x3c\x00\x06recon1"
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(raw_sock, server_hostname=target)
        else:
            s = raw_sock
            
        s.connect((target, port))
        s.sendall(mqtt_connect_pkt)
        resp = s.recv(1024)
        s.close()

        if resp and len(resp) >= 4 and resp[0] == 0x20:
            return_code = resp[3]
            code_msg = {
                0: "Connection Accepted (Unauthenticated Access Permitted)",
                1: "Refused - Unacceptable Protocol Version",
                2: "Refused - Identifier Rejected",
                3: "Refused - Server Unavailable",
                4: "Refused - Bad User Name or Password",
                5: "Refused - Not Authorized"
            }.get(return_code, f"Returned Code {return_code}")
            
            scan_results["port_scans"][str(port)]["version"] = f"MQTT Broker (wire protocol v3.1.1) | {code_msg} - broker software version not disclosed by protocol"
            if return_code == 0:
                log_and_print("enumeration", "mqtt_status", f"  [VULN] MQTT Broker open without credentials ({code_msg})", port=port)
            else:
                log_and_print("enumeration", "mqtt_status", f"  [+] MQTT Broker active | Status: {code_msg}", port=port)
        else:
            scan_results["port_scans"][str(port)]["version"] = "MQTT Service Active"
            log_and_print("enumeration", "mqtt_status", "  [+] MQTT Port open and responding to raw connect packet", port=port)
    except Exception as e:
        log_and_print("enumeration", "mqtt_fault", f"  [-] MQTT Handshake Error: {e}", port=port)

def run_rabbitmq_advanced_audit(target, port):
    timeout = get_dynamic_timeout()
    use_ssl = (port == 5671)
    log_and_print("enumeration", "rabbitmq_init", f"[*] Auditing RabbitMQ / AMQP Message Queue on {target}:{port} (SSL={use_ssl})", port=port)
    
    amqp_header = b"AMQP\x00\x00\x09\x01"
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(raw_sock, server_hostname=target)
        else:
            s = raw_sock

        s.connect((target, port))
        s.sendall(amqp_header)
        resp = s.recv(1024)
        s.close()

        if resp and resp.startswith(b"AMQP"):
            ver_str = f"{resp[4]}.{resp[5]}.{resp[6]}.{resp[7]}"
            scan_results["port_scans"][str(port)]["version"] = f"RabbitMQ / AMQP endpoint (wire protocol v{ver_str}) - broker software version not disclosed by protocol"
            log_and_print("enumeration", "rabbitmq_status", f"  [+] RabbitMQ Server Accepted AMQP Header: protocol v{ver_str}", port=port)
        else:
            scan_results["port_scans"][str(port)]["version"] = "RabbitMQ AMQP Interface Active"
            log_and_print("enumeration", "rabbitmq_status", "  [+] Port active, responded to AMQP probe", port=port)
    except Exception as e:
        log_and_print("enumeration", "rabbitmq_fault", f"  [-] RabbitMQ/AMQP Error: {e}", port=port)

def run_memcached_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "memcached_init", f"[*] Auditing Memcached Cache Engine on {target}:{MEMCACHED_PORT}", port=MEMCACHED_PORT)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, MEMCACHED_PORT))
        s.sendall(b"stats\r\n")
        resp = s.recv(4096).decode('utf-8', errors='ignore')
        s.close()

        if "STAT version" in resp or "STAT pid" in resp:
            ver_match = re.search(r"STAT version\s+(.*?)\r\n", resp)
            version = ver_match.group(1).strip() if ver_match else "Unknown"
            scan_results["port_scans"]["11211"]["version"] = f"Memcached v{version} (Unauthenticated Access)"
            log_and_print("enumeration", "memcached_info", f"  [VULN] Memcached Unauthenticated Access Allowed | Version: {version}", port=MEMCACHED_PORT)
        else:
            scan_results["port_scans"]["11211"]["version"] = "Memcached Cache Service Active"
            log_and_print("enumeration", "memcached_status", "  [+] Memcached Port responding", port=MEMCACHED_PORT)
    except Exception as e:
        log_and_print("enumeration", "memcached_fault", f"  [-] Memcached Error: {e}", port=MEMCACHED_PORT)

_RPC_PROGRAM_NAMES = {
    100000: "portmapper", 100003: "nfs", 100005: "mountd", 100021: "nlockmgr",
    100024: "status", 100011: "rquotad", 100002: "rusersd", 100008: "rwalld",
    100001: "rstatd", 100004: "ypserv", 100009: "yppasswdd", 100007: "ypbind",
    100227: "nfs_acl", 100029: "keyserv", 100068: "cmsd", 100083: "ttdbserverd",
}

_RPC_DUMP_CACHE = None  # One DUMP call serves both port 111 and 2049

def rpc_pmap_dump(target, timeout):
    """Real ONC RPC PMAPPROC_DUMP (program 100000, version 2, procedure 4)
    query against the portmapper - the exact call `rpcinfo -p` itself makes.
    Returns the target's actual registered-program table (program number,
    supported versions, protocol, port) instead of a guess. This is what
    nmap's own '2 (RPC #100000)' / '2-4 (RPC #100003)' notation is built
    from, and replaces the previous behavior of hardcoding the string
    'v2/v3/v4' regardless of what the target actually registered."""
    global _RPC_DUMP_CACHE
    if _RPC_DUMP_CACHE is not None:
        return _RPC_DUMP_CACHE

    xid = struct.unpack('>I', os.urandom(4))[0]
    call_header = struct.pack('>IIIIII', xid, 0, 2, 100000, 2, 4)  # xid, CALL, rpcvers, prog, vers, proc=DUMP
    cred = struct.pack('>II', 0, 0)   # AUTH_NONE, length 0
    verf = struct.pack('>II', 0, 0)
    packet = call_header + cred + verf

    programs = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(packet, (target, RPCBIND_PORT))
        data, _ = s.recvfrom(8192)
        s.close()

        if len(data) >= 24:
            resp_xid, msg_type, reply_stat = struct.unpack('>III', data[0:12])
            if resp_xid == xid and msg_type == 1 and reply_stat == 0:
                pos = 12
                verf_flavor, verf_len = struct.unpack('>II', data[pos:pos + 8])
                pos += 8 + verf_len
                if pos + 4 <= len(data):
                    accept_stat = struct.unpack('>I', data[pos:pos + 4])[0]
                    pos += 4
                    if accept_stat == 0:
                        programs = []
                        while pos + 4 <= len(data):
                            value_follows = struct.unpack('>I', data[pos:pos + 4])[0]
                            pos += 4
                            if value_follows != 1 or pos + 16 > len(data):
                                break
                            program, version, protocol, port = struct.unpack('>IIII', data[pos:pos + 16])
                            pos += 16
                            programs.append({
                                "program": program, "version": version,
                                "protocol": "tcp" if protocol == 6 else ("udp" if protocol == 17 else str(protocol)),
                                "port": port
                            })
    except Exception:
        programs = None

    _RPC_DUMP_CACHE = programs
    return programs


def _format_rpc_dump(programs):
    """Groups raw DUMP entries by program number into 'name(prog) vX,Y,Z
    [proto/port ...]' lines, and returns the grouped dict alongside for
    callers that need a specific program's data (e.g. NFS's own version set)."""
    grouped = {}
    for e in programs:
        g = grouped.setdefault(e["program"], {"versions": set(), "endpoints": set()})
        g["versions"].add(e["version"])
        g["endpoints"].add(f"{e['protocol']}/{e['port']}")
    lines = []
    for prog in sorted(grouped):
        name = _RPC_PROGRAM_NAMES.get(prog, "unknown")
        versions = ",".join(str(v) for v in sorted(grouped[prog]["versions"]))
        endpoints = " ".join(sorted(grouped[prog]["endpoints"]))
        lines.append(f"{name}({prog}) v{versions} [{endpoints}]")
    return lines, grouped


def run_nfs_rpc_advanced_audit(target, port):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "nfs_rpc_init", f"[*] Auditing RPC / NFS Storage Service on {target}:{port}", port=port)

    programs = rpc_pmap_dump(target, timeout)

    if programs:
        lines, grouped = _format_rpc_dump(programs)
        log_and_print("enumeration", "rpc_dump_table", "  [+] RPC Portmapper DUMP - registered programs:\n" + "\n".join(f"      {l}" for l in lines), port=port)

        if port == RPCBIND_PORT:
            pmap_versions = ",".join(str(v) for v in sorted(grouped.get(100000, {"versions": {2}})["versions"]))
            scan_results["port_scans"]["111"]["version"] = f"RPCBind (Portmapper) v{pmap_versions} | Registered: {'; '.join(lines)}"
        elif port == NFS_PORT:
            if 100003 in grouped:
                nfs_versions = ",".join(str(v) for v in sorted(grouped[100003]["versions"]))
                scan_results["port_scans"]["2049"]["version"] = f"NFS (Network File System) v{nfs_versions} - confirmed via RPC portmapper DUMP"
            else:
                scan_results["port_scans"]["2049"]["version"] = "NFS port active (not found in portmapper DUMP - may be statically bound)"
        return

    # DUMP failed (filtered, non-standard portmapper, or malformed reply) -
    # fall back to the old NULL-ping confirmation rather than claiming a
    # version we couldn't actually verify.
    rpc_null_ping = struct.pack("!IIIIIIII", 0x11223344, 0, 2, 100000 if port == 111 else 100003, 2, 0, 0, 0)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        
        frag_hdr = struct.pack("!I", 0x80000000 | len(rpc_null_ping))
        s.sendall(frag_hdr + rpc_null_ping)
        resp = s.recv(1024)
        s.close()

        service_label = "RPCBind (Portmap - version unconfirmed, DUMP query failed)" if port == 111 else "NFS (version unconfirmed, DUMP query failed)"
        if resp and len(resp) >= 24:
            scan_results["port_scans"][str(port)]["version"] = f"{service_label} - Responded to RPC NULL Ping"
            log_and_print("enumeration", "nfs_rpc_status", f"  [+] {service_label} active and verified via RPC ping", port=port)
        else:
            scan_results["port_scans"][str(port)]["version"] = f"{service_label} Active"
            log_and_print("enumeration", "nfs_rpc_status", f"  [+] {service_label} port active", port=port)
    except Exception as e:
        log_and_print("enumeration", "nfs_rpc_fault", f"  [-] RPC/NFS Audit Exception: {e}", port=port)

def run_pop3_advanced_audit(target, port):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "pop3_init", f"[*] Launching POP3 Verification on {target}:{port}", port=port)
    try:
        plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        plain_socket.settimeout(timeout)
        s = ssl.create_default_context().wrap_socket(plain_socket, server_hostname=target) if port == 995 else plain_socket
        s.connect((target, port))
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        scan_results["port_scans"][str(port)]["version"] = banner
        log_and_print("enumeration", "pop3_banner", f"  [+] POP3 Banner: {banner}", port=port)
        s.close()
    except Exception as e:
        log_and_print("enumeration", "pop3_fault", f"  [-] POP3 Connection error: {e}", port=port)

def run_ldap_advanced_audit(target, port):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "ldap_init", f"[*] Auditing LDAP Service on {target}:{port}", port=port)
    try:
        plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        plain_socket.settimeout(timeout)
        s = ssl.create_default_context().wrap_socket(plain_socket, server_hostname=target) if port == 636 else plain_socket
        s.connect((target, port))
        
        ldap_bind_req = b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"
        s.sendall(ldap_bind_req)
        resp = s.recv(1024)

        if resp and len(resp) > 5 and resp[0] == 0x30:
            scan_results["port_scans"][str(port)]["version"] = "Active LDAP Service (BER Response)"
            log_and_print("enumeration", "ldap_status", "  [+] LDAP Service active and responded to bind query", port=port)

            # Anonymous rootDSE search - vendorName/vendorVersion are, by LDAP
            # convention, world-readable on the root DSE even when the rest of
            # the directory requires auth. This is the standard way OpenLDAP/AD/
            # 389-ds disclose their exact build (e.g. 'OpenLDAP: slapd 2.4.57'),
            # and was previously never attempted - only bind success/failure
            # was recorded, with no exact version regardless of outcome.
            search_req = _build_ldap_rootdse_search_request()
            s.sendall(search_req)
            root_dse_resp = s.recv(4096)
            s.close()

            if root_dse_resp:
                version_str = _extract_ldap_vendor_string(root_dse_resp)
                if version_str:
                    scan_results["port_scans"][str(port)]["version"] = version_str
                    log_and_print("enumeration", "ldap_vendor_version", f"  [+] Vendor/Version (rootDSE): {version_str}", port=port)
                else:
                    log_and_print("enumeration", "ldap_rootdse_no_version", "  [-] rootDSE responded but no vendorName/vendorVersion attribute was disclosed", port=port)
        else:
            scan_results["port_scans"][str(port)]["version"] = "LDAP Service Open"
            log_and_print("enumeration", "ldap_status", "  [+] Port open (non-standard LDAP probe result)", port=port)
            s.close()
    except Exception as e:
        log_and_print("enumeration", "ldap_fault", f"  [-] LDAP Handshake Error: {e}", port=port)

def _build_ldap_rootdse_search_request():
    """Hand-rolled BER/ASN.1 LDAPv3 SearchRequest for the root DSE:
    baseObject='', scope=baseObject(0), filter=(objectClass=*),
    attributes=[vendorName, vendorVersion, namingContexts, supportedLDAPVersion].
    Kept minimal/fixed rather than a general BER encoder since this is the
    only search this tool ever issues."""
    message_id = b"\x02\x01\x02"  # INTEGER 2

    base_object = b"\x04\x00"  # OCTET STRING ""
    scope = b"\x0a\x01\x00"  # ENUMERATED baseObject
    deref = b"\x0a\x01\x00"  # ENUMERATED neverDerefAliases
    size_limit = b"\x02\x01\x00"
    time_limit = b"\x02\x01\x00"
    types_only = b"\x01\x01\x00"  # BOOLEAN FALSE
    filter_present = b"\x87\x0bobjectClass"  # [7] present "objectClass"

    attrs = [b"vendorName", b"vendorVersion", b"namingContexts", b"supportedLDAPVersion"]
    attrs_encoded = b"".join(bytes([0x04, len(a)]) + a for a in attrs)
    attributes = bytes([0x30, len(attrs_encoded)]) + attrs_encoded

    search_body = base_object + scope + deref + size_limit + time_limit + types_only + filter_present + attributes
    search_request = bytes([0x63, len(search_body)]) + search_body  # [APPLICATION 3] SearchRequest

    ldap_message_body = message_id + search_request
    return bytes([0x30, len(ldap_message_body)]) + ldap_message_body


def _extract_ldap_vendor_string(raw):
    """Pragmatic string-scan of the raw SearchResultEntry bytes rather than a
    full BER parse: vendorName/vendorVersion attribute *values* are plain
    ASCII OCTET STRINGs, so a targeted regex against the decoded bytes finds
    them reliably without implementing a general ASN.1 walker for a single
    known query shape."""
    text = raw.decode('latin-1', errors='ignore')
    vendor_name = None
    vendor_version = None
    m = re.search(r'vendorName\x00?[^\x00-\x1f]{0,3}([\x20-\x7e]{3,80})', text)
    if m:
        vendor_name = m.group(1).strip()
    m = re.search(r'vendorVersion\x00?[^\x00-\x1f]{0,3}([\x20-\x7e]{3,80})', text)
    if m:
        vendor_version = m.group(1).strip()
    if vendor_name or vendor_version:
        return " | ".join(x for x in (vendor_name, vendor_version) if x)
    # Fallback: some servers (notably Active Directory) don't expose
    # vendorVersion at all but do return a recognizable rootDSE shape -
    # look for any embedded OpenLDAP-style self-description as a last resort.
    m = re.search(r'(OpenLDAP[:\s]+slapd[^\x00-\x1f]{0,40})', text, re.IGNORECASE)
    return m.group(1).strip() if m else None

def run_dhcp_advanced_audit(target, port):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "dhcp_init", f"[*] Auditing DHCP Endpoint on {target}:{port}", port=port)

    if port == 68:
        # bootpc is the DHCP *client* port - a real client only ever acts on a
        # BOOTREPLY carrying the transaction ID from its own in-flight lease
        # request, so there is no protocol-valid active probe this tool can
        # send here (previously this reused the port-67 DHCPDISCOVER payload
        # and reported "Active DHCP Server/Relay" on a reply that could never
        # legitimately arrive - misleading given this isn't a server). State
        # for this port comes from the earlier generic UDP scan consensus;
        # this module just records that honestly instead of overwriting it
        # with a claim the protocol can't actually support.
        scan_results["port_scans"]["68"]["version"] = "DHCP Client Port (bootpc) - not actively probeable; a client only responds to an in-flight lease's own BOOTREPLY"
        log_and_print("enumeration", "dhcp_client_port_note", "  [-] Port 68 is the DHCP client endpoint - skipping server-style active probe (protocol-invalid on this port)", port=port)
        return

    try:
        dhcp_discover = (
            IP(dst=target)/UDP(sport=68, dport=port)/
            Raw(b'\x01\x01\x06\x00' + b'\x00' * 232)
        )
        resp = sr1(dhcp_discover, timeout=timeout, verbose=0)
        if resp:
            scan_results["port_scans"][str(port)]["version"] = "Active DHCP Server/Relay"
            log_and_print("enumeration", "dhcp_status", "  [+] DHCP Service replied to Discovery probe", port=port)
        else:
            scan_results["port_scans"][str(port)]["version"] = "DHCP Port Active (No reply)"
            log_and_print("enumeration", "dhcp_status", "  [+] DHCP Port active (no direct response to unicast discover)", port=port)
    except Exception as e:
        log_and_print("enumeration", "dhcp_fault", f"  [-] DHCP Probe Anomaly: {e}", port=port)

def run_ntp_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "ntp_init", f"[*] Auditing NTP Time Service on {target}:{NTP_PORT}", port=NTP_PORT)
    try:
        ntp_client_req = b'\x1b' + b'\x00' * 47
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(ntp_client_req, (target, NTP_PORT))
        data, _ = s.recvfrom(1024)
        s.close()

        if len(data) >= 48:
            li_vn_mode = data[0]
            version = (li_vn_mode >> 3) & 0x07
            mode = li_vn_mode & 0x07
            stratum = data[1]
            ref_id_raw = data[12:16]

            if stratum == 0:
                stratum_desc = "Unspecified / Kiss-o'-Death"
            elif stratum == 1:
                stratum_desc = "Primary Reference (atomic/GPS clock)"
            elif 2 <= stratum <= 15:
                stratum_desc = f"Secondary Reference (Stratum {stratum})"
            else:
                stratum_desc = f"Reserved/Unusual (Stratum {stratum})"

            if stratum <= 1:
                ref_id = ref_id_raw.decode('ascii', errors='ignore').strip('\x00') or "N/A"
            else:
                ref_id = ".".join(str(b) for b in ref_id_raw)

            scan_results["port_scans"]["123"]["version"] = f"NTPv{version} (Mode {mode}) | Stratum: {stratum_desc} | RefID: {ref_id}"
            log_and_print("enumeration", "ntp_version", f"  [+] NTP Protocol Version Detected: NTPv{version}", port=NTP_PORT)
            log_and_print("enumeration", "ntp_stratum", f"  [+] Stratum Level: {stratum_desc}", port=NTP_PORT)
            log_and_print("enumeration", "ntp_refid", f"  [+] Reference Identifier: {ref_id}", port=NTP_PORT)
        else:
            scan_results["port_scans"]["123"]["version"] = "NTP Service Active (Short/Malformed Reply)"
            log_and_print("enumeration", "ntp_short", "  [+] NTP port responded with a short/malformed packet", port=NTP_PORT)
    except socket.timeout:
        log_and_print("enumeration", "ntp_timeout", "  [-] No NTP reply received to Mode 3 client request", port=NTP_PORT)
    except Exception as e:
        log_and_print("enumeration", "ntp_fault", f"  [-] NTP Query Error: {e}", port=NTP_PORT)

def run_tftp_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "tftp_init", f"[*] Auditing TFTP Service on {target}:{TFTP_PORT}", port=TFTP_PORT)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        probe_filename = b"__recon_audit_probe__"
        rrq = b'\x00\x01' + probe_filename + b'\x00octet\x00'
        s.sendto(rrq, (target, TFTP_PORT))
        data, _ = s.recvfrom(1024)
        s.close()

        if len(data) >= 2:
            opcode = struct.unpack("!H", data[0:2])[0]
            if opcode == 5:
                err_code = struct.unpack("!H", data[2:4])[0] if len(data) >= 4 else -1
                err_msg = data[4:-1].decode('utf-8', errors='ignore') if len(data) > 4 else "Unknown"
                scan_results["port_scans"]["69"]["version"] = f"TFTP Service Active (ERROR {err_code}: {err_msg})"
                log_and_print("enumeration", "tftp_status", f"  [+] TFTP Service confirmed active | Error Code {err_code}: {err_msg}", port=TFTP_PORT)
            elif opcode == 3:
                scan_results["port_scans"]["69"]["version"] = "TFTP Service Active (Read Request Accepted)"
                log_and_print("enumeration", "tftp_status", "  [+] TFTP Service accepted the read request (DATA response)", port=TFTP_PORT)
            else:
                scan_results["port_scans"]["69"]["version"] = f"TFTP Service Active (Opcode {opcode})"
                log_and_print("enumeration", "tftp_status", f"  [+] TFTP responded with unexpected opcode {opcode}", port=TFTP_PORT)
    except socket.timeout:
        scan_results["port_scans"]["69"]["version"] = "TFTP Port Active (No Reply to Probe)"
        log_and_print("enumeration", "tftp_timeout", "  [-] No TFTP response to read-request probe", port=TFTP_PORT)
    except Exception as e:
        log_and_print("enumeration", "tftp_fault", f"  [-] TFTP Probe Anomaly: {e}", port=TFTP_PORT)

def run_sip_advanced_audit(target, port):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "sip_init", f"[*] Auditing SIP Service on {target}:{port}", port=port)

    transport = "TLS" if port == SIP_TLS_PORT else "UDP"
    options_req = (
        f"OPTIONS sip:{target} SIP/2.0\r\n"
        f"Via: SIP/2.0/{transport} 0.0.0.0:{port};branch=z9hG4bK-reconaudit\r\n"
        f"Max-Forwards: 70\r\n"
        f"To: <sip:{target}>\r\n"
        f"From: <sip:recon@0.0.0.0>;tag=reconaudit\r\n"
        f"Call-ID: reconaudit-probe@0.0.0.0\r\n"
        f"CSeq: 1 OPTIONS\r\n"
        f"Contact: <sip:recon@0.0.0.0>\r\n"
        f"Accept: application/sdp\r\n"
        f"Content-Length: 0\r\n\r\n"
    ).encode('utf-8')

    try:
        if port == SIP_TLS_PORT:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(timeout)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(raw_sock, server_hostname=target)
            s.connect((target, port))
            s.sendall(options_req)
            data = s.recv(4096)
            s.close()
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(options_req, (target, port))
            data, _ = s.recvfrom(4096)
            s.close()

        response = data.decode('utf-8', errors='ignore')
        status_line = response.split("\r\n", 1)[0].strip() if response else "No Status Line Returned"
        log_and_print("enumeration", "sip_response", f"  [+] SIP OPTIONS Response: {status_line}", port=port)

        server_hdr, allow_hdr = None, None
        for line in response.split("\r\n"):
            lk = line.lower()
            if lk.startswith("server:") or lk.startswith("user-agent:"):
                server_hdr = line.split(":", 1)[1].strip()
            elif lk.startswith("allow:"):
                allow_hdr = line.split(":", 1)[1].strip()

        version_summary = f"SIP Active ({transport}) - {status_line}"
        if server_hdr:
            version_summary += f" | Server: {server_hdr}"
            log_and_print("enumeration", "sip_server", f"    [+] SIP Server/User-Agent Header: {server_hdr}", port=port)
        if allow_hdr:
            log_and_print("enumeration", "sip_methods", f"    [+] Supported SIP Methods (Allow): {allow_hdr}", port=port)

        scan_results["port_scans"][str(port)]["version"] = version_summary
    except socket.timeout:
        log_and_print("enumeration", "sip_timeout", "  [-] No SIP response received to OPTIONS ping", port=port)
    except Exception as e:
        log_and_print("enumeration", "sip_fault", f"  [-] SIP OPTIONS Probe Anomaly: {e}", port=port)

def recv_exact_bytes(sock, n):
    """Generic helper: reads exactly n bytes from a TCP stream (loops until satisfied
    or the peer closes early)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf

def build_ssh_binary_packet(payload):
    """Wraps a payload in the SSH Binary Packet Protocol framing (RFC 4253 S6),
    used here only during the unencrypted pre-KEX phase."""
    padding_length = 8 - ((5 + len(payload)) % 8)
    if padding_length < 4:
        padding_length += 8
    packet_length = 1 + len(payload) + padding_length
    padding = os.urandom(padding_length)
    return struct.pack('>I', packet_length) + struct.pack('B', padding_length) + payload + padding

def read_ssh_binary_packet(sock, timeout):
    sock.settimeout(timeout)
    length_bytes = recv_exact_bytes(sock, 4)
    if len(length_bytes) < 4:
        return None
    packet_length = struct.unpack('>I', length_bytes)[0]
    if packet_length <= 0 or packet_length > 262144:  # sanity cap, reject garbage frames
        return None
    rest = recv_exact_bytes(sock, packet_length)
    if len(rest) < packet_length:
        return None
    padding_length = rest[0]
    payload_len = packet_length - padding_length - 1
    if payload_len < 0:
        return None
    return rest[1:1 + payload_len]

def ssh_string(data):
    return struct.pack('>I', len(data)) + data

def parse_ssh_kexinit(payload):
    """Parses SSH_MSG_KEXINIT (RFC 4253 S7.1): 1 msg-type byte + 16-byte cookie,
    followed by 10 length-prefixed name-lists."""
    pos = 1 + 16
    fields = []
    for _ in range(10):
        length = struct.unpack('>I', payload[pos:pos + 4])[0]
        pos += 4
        fields.append(payload[pos:pos + length].decode('ascii', errors='ignore'))
        pos += length
    return {
        "kex_algorithms": fields[0], "server_host_key_algorithms": fields[1],
        "encryption_c2s": fields[2], "encryption_s2c": fields[3],
        "mac_c2s": fields[4], "mac_s2c": fields[5],
        "compression_c2s": fields[6], "compression_s2c": fields[7],
    }

SSH_WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}
SSH_WEAK_CIPHERS = {"none", "arcfour", "arcfour128", "arcfour256", "des-cbc", "3des-cbc", "blowfish-cbc"}
SSH_WEAK_MACS = {"hmac-md5", "hmac-md5-96", "hmac-sha1-96", "none"}
SSH_LEGACY_HOSTKEYS = {"ssh-dss", "ssh-rsa"}  # ssh-rsa = SHA-1 signature scheme, deprecated by OpenSSH 8.8+

def run_ssh_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "ssh_init", f"[*] Auditing SSH Service on {target}:{SSH_PORT} (Algorithm Enumeration & Host Key Fingerprinting)", port=SSH_PORT)
    findings = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, SSH_PORT))

        # 1) Identification string / protocol version
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        log_and_print("enumeration", "ssh_banner", f"  [+] SSH Identification Banner: {banner}", port=SSH_PORT)
        ver_match = re.match(r'SSH-(\d+\.\d+)-(\S+)', banner)
        protocol_version = ver_match.group(1) if ver_match else "Unknown"
        software_version = ver_match.group(2) if ver_match else "Unknown"
        if protocol_version.startswith("1."):
            log_and_print("enumeration", "ssh_legacy_protocol", f"  [VULN] Legacy SSH Protocol Version {protocol_version} in use (SSHv1 is cryptographically broken/deprecated)", port=SSH_PORT)
            findings.append(f"Protocol v{protocol_version} (LEGACY/VULNERABLE)")
        else:
            log_and_print("enumeration", "ssh_protocol_version", f"  [+] SSH Protocol Version: {protocol_version} | Software: {software_version}", port=SSH_PORT)
            findings.append(f"Protocol v{protocol_version}")

        # 2) Send our own identification string to prompt the server's KEXINIT
        s.sendall(b"SSH-2.0-ReconAudit_1.0\r\n")
        server_kexinit_payload = read_ssh_binary_packet(s, timeout)

        if not server_kexinit_payload or server_kexinit_payload[0] != 20:
            log_and_print("enumeration", "ssh_kexinit_fail", "  [-] Did not receive a valid SSH_MSG_KEXINIT - algorithm enumeration unavailable", port=SSH_PORT)
            scan_results["port_scans"]["22"]["version"] = f"OpenSSH-compatible ({banner}) | " + " | ".join(findings)
            s.close()
            return

        algos = parse_ssh_kexinit(server_kexinit_payload)
        log_and_print("enumeration", "ssh_kex_algorithms", f"  [+] Key Exchange (KEX) Methods: {algos['kex_algorithms']}", port=SSH_PORT)
        log_and_print("enumeration", "ssh_hostkey_algorithms", f"  [+] Server Host Key Algorithms: {algos['server_host_key_algorithms']}", port=SSH_PORT)
        log_and_print("enumeration", "ssh_ciphers", f"  [+] Cipher List (Client->Server): {algos['encryption_c2s']}", port=SSH_PORT)
        log_and_print("enumeration", "ssh_ciphers_s2c", f"  [+] Cipher List (Server->Client): {algos['encryption_s2c']}", port=SSH_PORT)
        log_and_print("enumeration", "ssh_macs", f"  [+] MAC Algorithms (Client->Server): {algos['mac_c2s']}", port=SSH_PORT)
        log_and_print("enumeration", "ssh_compression", f"  [+] Compression: {algos['compression_c2s']}", port=SSH_PORT)

        # Weak/deprecated algorithm detection (vulnerability-detection accuracy improvement)
        kex_list = set(algos['kex_algorithms'].split(','))
        cipher_list = set(algos['encryption_c2s'].split(',')) | set(algos['encryption_s2c'].split(','))
        mac_list = set(algos['mac_c2s'].split(',')) | set(algos['mac_s2c'].split(','))
        hostkey_list = set(algos['server_host_key_algorithms'].split(','))

        weak_kex_found = kex_list & SSH_WEAK_KEX
        weak_cipher_found = cipher_list & SSH_WEAK_CIPHERS
        weak_mac_found = mac_list & SSH_WEAK_MACS
        legacy_hostkey_found = hostkey_list & SSH_LEGACY_HOSTKEYS

        if weak_kex_found:
            log_and_print("enumeration", "ssh_weak_kex", f"  [VULN] Weak/legacy Key Exchange algorithm(s) offered: {', '.join(sorted(weak_kex_found))}", port=SSH_PORT)
        if weak_cipher_found:
            log_and_print("enumeration", "ssh_weak_cipher", f"  [VULN] Weak/legacy cipher(s) offered: {', '.join(sorted(weak_cipher_found))}", port=SSH_PORT)
        if weak_mac_found:
            log_and_print("enumeration", "ssh_weak_mac", f"  [VULN] Weak/legacy MAC algorithm(s) offered: {', '.join(sorted(weak_mac_found))}", port=SSH_PORT)
        if legacy_hostkey_found:
            log_and_print("enumeration", "ssh_legacy_hostkey_algo", f"  [-] Legacy host key algorithm(s) still offered: {', '.join(sorted(legacy_hostkey_found))} (ssh-rsa uses deprecated SHA-1 signatures)", port=SSH_PORT)

        # 3) Live host key fingerprint via a real (but auth-free) curve25519-sha256 KEX
        host_key_summary = "Unavailable (server does not offer curve25519-sha256 KEX)"
        curve25519_names = {"curve25519-sha256", "curve25519-sha256@libssh.org"}
        chosen_kex = next((n for n in curve25519_names if n in kex_list), None)

        if chosen_kex:
            try:
                from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
                from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

                # Send our own KEXINIT (echo server's lists back so negotiation succeeds cleanly)
                cookie = os.urandom(16)
                client_kexinit = (
                    bytes([20]) + cookie +
                    ssh_string(chosen_kex.encode()) + ssh_string(algos['server_host_key_algorithms'].encode()) +
                    ssh_string(algos['encryption_c2s'].encode()) + ssh_string(algos['encryption_s2c'].encode()) +
                    ssh_string(algos['mac_c2s'].encode()) + ssh_string(algos['mac_s2c'].encode()) +
                    ssh_string(algos['compression_c2s'].encode()) + ssh_string(algos['compression_s2c'].encode()) +
                    ssh_string(b'') + ssh_string(b'') +
                    b'\x00' + struct.pack('>I', 0)
                )
                s.sendall(build_ssh_binary_packet(client_kexinit))

                client_priv = X25519PrivateKey.generate()
                client_pub_bytes = client_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                kex_ecdh_init = bytes([30]) + ssh_string(client_pub_bytes)
                s.sendall(build_ssh_binary_packet(kex_ecdh_init))

                reply_payload = read_ssh_binary_packet(s, timeout)
                # Some servers send their own KEXINIT again before the reply - skip past it if so
                if reply_payload and reply_payload[0] == 20:
                    reply_payload = read_ssh_binary_packet(s, timeout)

                if reply_payload and reply_payload[0] == 31:  # SSH_MSG_KEX_ECDH_REPLY
                    pos = 1
                    ks_len = struct.unpack('>I', reply_payload[pos:pos + 4])[0]; pos += 4
                    k_s = reply_payload[pos:pos + ks_len]; pos += ks_len

                    type_len = struct.unpack('>I', k_s[0:4])[0]
                    key_type = k_s[4:4 + type_len].decode('ascii', errors='ignore')
                    fingerprint = base64.b64encode(hashlib.sha256(k_s).digest()).decode().rstrip('=')
                    host_key_summary = f"{key_type} SHA256:{fingerprint}"
                    log_and_print("enumeration", "ssh_hostkey_type", f"  [+] Live Host Key Type: {key_type}", port=SSH_PORT)
                    log_and_print("enumeration", "ssh_hostkey_fingerprint", f"  [+] Live Host Key Fingerprint: SHA256:{fingerprint}", port=SSH_PORT)
                else:
                    log_and_print("enumeration", "ssh_hostkey_fail", "  [-] Did not receive SSH_MSG_KEX_ECDH_REPLY - host key fingerprint unavailable", port=SSH_PORT)
            except ImportError:
                log_and_print("enumeration", "ssh_hostkey_no_lib", "  [-] 'cryptography' library not installed - live host key fingerprinting skipped (algorithm lists above are still accurate)", port=SSH_PORT)
            except Exception as e:
                log_and_print("enumeration", "ssh_hostkey_fault", f"  [-] Host key fingerprint exchange anomaly: {e}", port=SSH_PORT)
        else:
            log_and_print("enumeration", "ssh_hostkey_skip", "  [-] Server does not offer curve25519-sha256 - live host key fingerprinting skipped (would require implementing additional KEX algorithms)", port=SSH_PORT)

        s.close()
        scan_results["port_scans"]["22"]["version"] = f"{banner} | HostKey: {host_key_summary} | " + " | ".join(findings)
    except Exception as e:
        log_and_print("enumeration", "ssh_fault", f"  [-] SSH Connection lost or timed out: {e}", port=SSH_PORT)

def ftp_banner_grab(target):
    timeout = get_dynamic_timeout()
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((target, FTP_PORT))
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        if banner:
            # Banner was being captured but never persisted into scan_results,
            # which is why FTP version reporting was previously blank even
            # though the daemon happily hands over its full identity string
            # (e.g. "220 (vsFTPd 3.0.5)", "220 ProFTPD 1.3.6 Server ready").
            log_and_print("enumeration", "ftp_banner", f"  [+] FTP Banner: {banner}", port=FTP_PORT)
            clean = re.sub(r'^220[- ]?', '', banner).strip()
            scan_results["port_scans"]["21"]["version"] = clean if clean else banner
        return banner
    except: return None

def ftp_anonymous_check(target):
    timeout = get_dynamic_timeout()
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((target, FTP_PORT))
        s.recv(1024)
        s.send(b"USER anonymous\r\n")
        s.recv(1024)
        s.send(b"PASS anonymous@target.com\r\n")
        res2 = s.recv(1024).decode('utf-8')
        s.close()
        if "230" in res2 or "successful" in res2.lower():
            log_and_print("enumeration", "ftp_anonymous", "  [VULN] FTP Anonymous access allowed with default settings", port=FTP_PORT)
            return True
    except: pass
    log_and_print("enumeration", "ftp_anonymous", "  [-] Anonymous login rejected by daemon.", port=FTP_PORT)
    return False

def ftp_bounce_check(target):
    timeout = get_dynamic_timeout()
    try:
        s = socket.socket(); s.settimeout(timeout); s.connect((target, FTP_PORT)); s.recv(1024)
        s.send(b"USER anonymous\r\n"); s.recv(1024); s.send(b"PASS anonymous@target.com\r\n"); s.recv(1024)
        s.send(b"PORT 127,0,0,1,0,80\r\n")
        res = s.recv(1024).decode('utf-8')
        s.close()
        if res.startswith("200"):
            log_and_print("enumeration", "ftp_bounce", "  [INFO] Daemon accepted PORT payload formatting syntax", port=FTP_PORT)
        else:
            log_and_print("enumeration", "ftp_bounce", f"  [-] Target daemon blocked internal tracking instruction: {res.strip()}", port=FTP_PORT)
    except: pass

def run_ftps_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "ftps_init", f"[*] Auditing FTPS / FTP Explicit TLS capabilities on {target}:{FTP_PORT}", port=FTP_PORT)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, FTP_PORT))
        s.recv(1024)
        s.sendall(b"AUTH TLS\r\n")
        resp = s.recv(1024).decode('utf-8', errors='ignore')
        if "234" in resp:
            log_and_print("enumeration", "ftps_auth_tls", "  [+] FTPS Explicit TLS supported (AUTH TLS Response 234)", port=FTP_PORT)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(s, server_hostname=target) as tls_sock:
                cipher = tls_sock.cipher()
                ver = tls_sock.version()
                log_and_print("enumeration", "ftps_tls_info", f"    [+] TLS Version: {ver} | Cipher: {cipher[0]}", port=FTP_PORT)
                scan_results["port_scans"]["21"]["version"] += f" (FTPS Enabled - {ver})"
        else:
            log_and_print("enumeration", "ftps_auth_tls", "  [-] Explicit FTPS (AUTH TLS) not supported.", port=FTP_PORT)
            s.close()
    except Exception as e:
        log_and_print("enumeration", "ftps_fault", f"  [-] FTPS Audit Exception: {e}", port=FTP_PORT)

def run_ftps_implicit_audit(target, port):
    timeout = get_dynamic_timeout()
    channel_label = "Control Channel" if port == FTPS_IMPLICIT_CTRL_PORT else "Data Channel"
    log_and_print("enumeration", "ftps_implicit_init", f"[*] Auditing Implicit FTPS {channel_label} on {target}:{port}", port=port)
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(raw_sock, server_hostname=target) as tls_sock:
            tls_sock.connect((target, port))
            ver = tls_sock.version()
            cipher = tls_sock.cipher()
            log_and_print("enumeration", "ftps_implicit_tls_info", f"  [+] Implicit TLS negotiated immediately on connect | Version: {ver} | Cipher: {cipher[0] if cipher else 'Unknown'}", port=port)
            scan_results["port_scans"][str(port)]["version"] = f"FTPS Implicit {channel_label} ({ver})"

            if port == FTPS_IMPLICIT_CTRL_PORT:
                try:
                    banner = tls_sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        log_and_print("enumeration", "ftps_implicit_banner", f"    [+] Post-TLS Control Banner: {banner}", port=port)
                except Exception:
                    pass
    except ssl.SSLError as e:
        log_and_print("enumeration", "ftps_implicit_fault", f"  [-] TLS handshake failed on implicit FTPS {channel_label}: {e}", port=port)
        scan_results["port_scans"][str(port)]["version"] = "TLS Handshake Failed (Not True Implicit FTPS)"
    except Exception as e:
        log_and_print("enumeration", "ftps_implicit_fault", f"  [-] Implicit FTPS Audit Exception ({channel_label}): {e}", port=port)

def run_telnet_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "telnet_init", f"[*] Auditing Telnet Service & IAC Option Negotiation on {target}:{TELNET_PORT}", port=TELNET_PORT)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, TELNET_PORT))
        data = s.recv(1024)

        iac_opts = []
        IAC, WILL, WONT, DO, DONT = 255, 251, 252, 253, 254
        OPTION_NAMES = {1: "ECHO", 3: "SUPPRESS-GO-AHEAD", 24: "TERMINAL-TYPE", 31: "WINDOW-SIZE", 32: "TERMINAL-SPEED", 39: "NEW-ENVIRON"}
        cmd_names = {WILL: "WILL", WONT: "WONT", DO: "DO", DONT: "DONT"}
        i = 0
        while i < len(data) - 2:
            if data[i] == IAC and data[i + 1] in cmd_names:
                opt_id = data[i + 2]
                opt_name = OPTION_NAMES.get(opt_id, f"OPT-{opt_id}")
                iac_opts.append(f"{cmd_names[data[i + 1]]} {opt_name}")
                i += 3
            else:
                i += 1

        if iac_opts:
            log_and_print("enumeration", "telnet_iac_negotiation", f"  [+] IAC Option Negotiation observed: {', '.join(iac_opts)}", port=TELNET_PORT)

        printable = re.sub(rb'\xff[\xfb-\xfe].', b'', data).decode('utf-8', errors='ignore').strip()
        banner = printable if printable else "Banner not printable / IAC-only response"
        scan_results["port_scans"]["23"]["version"] = banner
        log_and_print("enumeration", "telnet_banner", f"  [+] Telnet Login Banner/Prompt: {banner}", port=TELNET_PORT)
        log_and_print("enumeration", "telnet_cleartext_warning", "  [VULN] Telnet transmits all credentials and session data in cleartext (unencrypted)", port=TELNET_PORT)
        s.close()
    except Exception as e:
        log_and_print("enumeration", "telnet_fault", f"  [-] Telnet Connection lost or timed out: {e}", port=TELNET_PORT)

SMB2_DIALECT_NAMES = {
    0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1", 0x02FF: "SMB2 Wildcard (multi-protocol probe)"
}

def build_netbios_frame(payload):
    """Correct 4-byte NetBIOS Session Service header: 1 byte type (0x00) + 3-byte
    big-endian length. (Prior implementation used struct.pack('!xL', ...), which emits
    5 bytes and desyncs the frame - fixed here.)"""
    return struct.pack('>I', len(payload)) + payload

def build_smb2_header(command, message_id, session_id=0, credit_request=1):
    return (b'\xfeSMB' + struct.pack('<H', 64) + struct.pack('<H', 0) + struct.pack('<I', 0) +
            struct.pack('<H', command) + struct.pack('<H', credit_request) + struct.pack('<I', 0) +
            struct.pack('<I', 0) + struct.pack('<Q', message_id) + struct.pack('<I', 0) +
            struct.pack('<I', 0) + struct.pack('<Q', session_id) + b'\x00' * 16)

def build_smb2_negotiate_request(dialects, message_id=0):
    header = build_smb2_header(0, message_id)
    body = (struct.pack('<H', 36) + struct.pack('<H', len(dialects)) + struct.pack('<H', 1) +
            struct.pack('<H', 0) + struct.pack('<I', 0) + os.urandom(16) + struct.pack('<Q', 0))
    for d in dialects:
        body += struct.pack('<H', d)
    return build_netbios_frame(header + body)

def build_smb2_session_setup(security_buffer, message_id, session_id=0):
    header = build_smb2_header(1, message_id, session_id)
    sec_offset = 64 + 24
    body = (struct.pack('<H', 25) + struct.pack('B', 0) + struct.pack('B', 1) + struct.pack('<I', 0) +
            struct.pack('<I', 0) + struct.pack('<H', sec_offset) + struct.pack('<H', len(security_buffer)) +
            struct.pack('<Q', 0) + security_buffer)
    return build_netbios_frame(header + body)

def parse_smb2_negotiate_response(response):
    """response includes the 4-byte NetBIOS prefix; SMB2 header occupies [4:68], body follows."""
    if len(response) < 68 + 8:
        return None
    body = response[68:]
    security_mode = struct.unpack('<H', body[2:4])[0]
    dialect_revision = struct.unpack('<H', body[4:6])[0]
    return {
        "security_mode": security_mode,
        "signing_enabled": bool(security_mode & 0x01),
        "signing_required": bool(security_mode & 0x02),
        "dialect_revision": dialect_revision,
        "dialect_name": SMB2_DIALECT_NAMES.get(dialect_revision, f"Unknown (0x{dialect_revision:04x})"),
    }

def build_ntlm_negotiate_minimal():
    # NTLMSSP_NEGOTIATE_VERSION (0x02000000) added on top of the existing flags -
    # this asks the server to embed its OS Version block (major/minor/build) in
    # the Type-2 CHALLENGE_MESSAGE it sends back. Windows honors this by default;
    # it's the same technique nmap's smb-os-discovery script uses to report an
    # exact Windows build number instead of just a negotiated SMB dialect.
    flags = 0x00000001 | 0x00000002 | 0x00000004 | 0x00000200 | 0x00008000 | 0x00080000 | 0x20000000 | 0x02000000
    return (b'NTLMSSP\x00' + struct.pack('<I', 1) + struct.pack('<I', flags) +
            struct.pack('<HHI', 0, 0, 0) + struct.pack('<HHI', 0, 0, 0))

_NTLM_VERSION_TO_WINDOWS = {
    (5, 1): "Windows XP",
    (5, 2): "Windows Server 2003/XP x64",
    (6, 0): "Windows Vista / Server 2008",
    (6, 1): "Windows 7 / Server 2008 R2",
    (6, 2): "Windows 8 / Server 2012",
    (6, 3): "Windows 8.1 / Server 2012 R2",
}
_NTLM_BUILD_TO_WINDOWS10PLUS = {
    10240: "Windows 10 1507", 14393: "Windows 10 1607 / Server 2016",
    15063: "Windows 10 1703", 16299: "Windows 10 1709", 17134: "Windows 10 1803",
    17763: "Windows 10 1809 / Server 2019", 18362: "Windows 10 1903",
    18363: "Windows 10 1909", 19041: "Windows 10 2004", 19042: "Windows 10 20H2",
    19043: "Windows 10 21H1", 19044: "Windows 10 21H2", 19045: "Windows 10 22H2",
    20348: "Windows Server 2022", 22000: "Windows 11 21H2", 22621: "Windows 11 22H2",
    22631: "Windows 11 23H2", 26100: "Windows 11 24H2 / Server 2025",
}

def _parse_ntlm_challenge_version(raw):
    """Locates an embedded NTLM Type-2 CHALLENGE_MESSAGE anywhere in a raw
    response buffer and, if the server set NTLMSSP_NEGOTIATE_VERSION, decodes
    its 8-byte Version block per MS-NLMP 2.2.2.10 (ProductMajorVersion,
    ProductMinorVersion, ProductBuild). Uses find() for the signature rather
    than trusting fixed SMB2 header offsets, since padding/negotiate-context
    layout varies across SMB dialects."""
    idx = raw.find(b'NTLMSSP\x00')
    if idx == -1:
        return None
    msg = raw[idx:]
    if len(msg) < 24 or struct.unpack('<I', msg[8:12])[0] != 2:
        return None
    negotiate_flags = struct.unpack('<I', msg[20:24])[0]
    if not (negotiate_flags & 0x02000000):  # NTLMSSP_NEGOTIATE_VERSION
        return None
    version_offset = 48  # right after TargetInfoFields (offset 40, 8 bytes)
    if len(msg) < version_offset + 8:
        return None
    ver = msg[version_offset:version_offset + 8]
    major, minor = ver[0], ver[1]
    build = struct.unpack('<H', ver[2:4])[0]
    label = _NTLM_BUILD_TO_WINDOWS10PLUS.get(build) or _NTLM_VERSION_TO_WINDOWS.get((major, minor))
    return {
        "major": major, "minor": minor, "build": build,
        "label": label or f"Windows NT {major}.{minor} (build {build})"
    }

def build_ntlm_authenticate_null():
    """A fully empty NTLMSSP AUTHENTICATE (Type 3) message - domain/user/workstation and
    both LM/NT responses are zero-length. This is exactly the standard anonymous/null-session
    probe (equivalent to `smbclient -N` / `rpcclient -U "" -N`)."""
    flags = 0x00008201
    fixed = b'NTLMSSP\x00' + struct.pack('<I', 3)
    def field():
        return struct.pack('<HHI', 0, 0, 64)
    fixed += field() + field() + field() + field() + field() + field() + struct.pack('<I', flags)
    return fixed

def nbt_encode_name(name16):
    encoded = bytearray()
    for b in name16:
        encoded.append(0x41 + (b >> 4))
        encoded.append(0x41 + (b & 0x0F))
    return bytes(encoded)

def _skip_dns_style_name(data, offset):
    """Advances past a DNS-style encoded name (RFC 1035 S4.1.4), used as-is by
    NBT/NBSTAT messages: either a sequence of length-prefixed labels ending
    in a zero-length label, or a 2-byte 0xC0-flagged compression pointer.
    Handles whichever form the peer actually used instead of assuming one."""
    p = offset
    while p < len(data):
        length = data[p]
        if length == 0:
            return p + 1
        if (length & 0xC0) == 0xC0:
            return p + 2
        p += 1 + length
    return p

def query_netbios_name_service(target, timeout):
    """Sends an NBSTAT (RFC 1002) wildcard query to UDP/137 to recover the NetBIOS
    computer name, workgroup/domain, and (when present) the adapter MAC address."""
    result = {"computer_name": None, "workgroup": None, "mac_address": None}
    try:
        query_name = b'*' + b'\x00' * 15
        encoded_name = nbt_encode_name(query_name)
        question = bytes([32]) + encoded_name + b'\x00' + struct.pack('>HH', 0x0021, 0x0001)
        trans_id = struct.unpack('>H', os.urandom(2))[0]
        header = struct.pack('>HHHHHH', trans_id, 0x0000, 1, 0, 0, 0)
        packet = header + question

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(packet, (target, 137))
        data, _ = s.recvfrom(2048)
        s.close()

        if len(data) < 12 + len(question):
            return result
        pos = 12 + len(question)
        # The answer Resource Record's NAME field was previously assumed to
        # always be a 2-byte compression pointer - but NBSTAT responses
        # commonly echo the *literal* encoded name instead (the same 34-byte
        # length-prefixed label form as the question), not a pointer. Treating
        # that as a fixed 2 bytes desyncs every field after it by ~32 bytes,
        # which is exactly what produced garbled/rotated NetBIOS names like
        # "LOITABLE\x00\x04\x00MET" instead of "METASPLOITABLE" - the parser
        # was reading a shifted window straight into the next name entry.
        # Skipping the name per DNS label-encoding rules (pointer OR literal
        # labels) handles either form correctly.
        pos = _skip_dns_style_name(data, pos)
        pos += 2 + 2 + 4  # TYPE + CLASS + TTL
        if pos + 2 > len(data):
            return result
        rdlength = struct.unpack('>H', data[pos:pos + 2])[0]
        pos += 2
        rdata = data[pos:pos + rdlength]
        if not rdata:
            return result
        num_names = rdata[0]
        npos = 1
        for _ in range(num_names):
            if npos + 18 > len(rdata):
                break
            raw_name = rdata[npos:npos + 15].decode('ascii', errors='ignore').strip()
            name_flags = struct.unpack('>H', rdata[npos + 16:npos + 18])[0]
            is_group = bool(name_flags & 0x8000)
            if is_group and not result["workgroup"]:
                result["workgroup"] = raw_name
            elif not is_group and not result["computer_name"]:
                result["computer_name"] = raw_name
            npos += 18
        if len(rdata) >= npos + 6:
            mac = rdata[npos:npos + 6]
            if any(mac):
                result["mac_address"] = ":".join(f"{b:02x}" for b in mac)
    except Exception:
        pass
    return result

def run_smb_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "smb_init", f"[*] Auditing SMB Service on {target}:{SMB_PORT} (Dialect Negotiation, Signing, SMBv1, Guest Login, NetBIOS)", port=SMB_PORT)

    smb1_header = (
        b"\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    dialects = b"\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"
    word_count = b"\x00"
    byte_count = struct.pack("<H", len(dialects))
    payload = smb1_header + word_count + byte_count + dialects
    packet = build_netbios_frame(payload)

    dialect_name, security_mode_info = "Unknown", None
    smbv1_active = False
    smb_implementation = None

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, SMB_PORT))
        s.sendall(packet)
        response = s.recv(4096)
        s.close()

        if response and len(response) > 4:
            if response[4:8] == b"\xffSMB":
                smbv1_active = True
                log_and_print("enumeration", "smb_smbv1_detected", "  [VULN] SMBv1 Protocol Dialect Accepted (legacy, vulnerable to EternalBlue-class exploits - should be disabled)", port=SMB_PORT)
                if len(response) > 39:
                    sec_mode_byte = response[39]
                    signing_enabled = bool(sec_mode_byte & 0x02)
                    signing_required = bool(sec_mode_byte & 0x04)
                    dialect_name = "SMB 1.0 (NT LM 0.12)"
                    log_and_print("enumeration", "smb_signing_v1", f"  [+] SMBv1 Signing -> Enabled: {signing_enabled} | Required: {signing_required}", port=SMB_PORT)
                    if not signing_required:
                        log_and_print("enumeration", "smb_signing_v1_vuln", "  [VULN] SMB Signing not required (relay attacks such as NTLM relay are possible)", port=SMB_PORT)
                if len(response) >= 60:
                    # Capabilities field of the same fixed-layout NEGOTIATE
                    # response (offset derived from the same WordCount=17
                    # 'NT LM 0.12' layout the verified SecurityMode byte at
                    # [39] already comes from - see MS-CIFS 2.2.4.5.2).
                    # CAP_UNIX (0x00800000) is set by Samba's Unix Extensions
                    # and never by genuine Windows - this is the same signal
                    # nmap's own smb-os-discovery uses to print "Samba smbd"
                    # instead of a bare dialect name.
                    capabilities = struct.unpack('<I', response[56:60])[0]
                    if capabilities & 0x00800000:
                        smb_implementation = "Samba (CAP_UNIX Extensions present)"
                        log_and_print("enumeration", "smb_implementation", "  [+] Implementation: Samba - CAP_UNIX capability bit set (never present on genuine Windows)", port=SMB_PORT)
            elif response[4:8] == b"\xfeSMB":
                neg = parse_smb2_negotiate_response(response)
                if neg:
                    dialect_name = neg["dialect_name"]
                    security_mode_info = neg
                    if neg["dialect_revision"] == 0x02FF:
                        # Wildcard response - follow up with a native SMB2-only negotiate for the real dialect
                        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s2.settimeout(timeout)
                        s2.connect((target, SMB_PORT))
                        s2.sendall(build_smb2_negotiate_request([0x0202, 0x0210, 0x0300, 0x0302]))
                        response2 = s2.recv(4096)
                        s2.close()
                        neg2 = parse_smb2_negotiate_response(response2) if response2 else None
                        if neg2:
                            dialect_name = neg2["dialect_name"]
                            security_mode_info = neg2
                    log_and_print("enumeration", "smb_dialect", f"  [+] Negotiated Dialect: {dialect_name}", port=SMB_PORT)
                    log_and_print("enumeration", "smb_signing", f"  [+] SMB Signing -> Enabled: {security_mode_info['signing_enabled']} | Required: {security_mode_info['signing_required']}", port=SMB_PORT)
                    if not security_mode_info["signing_required"]:
                        log_and_print("enumeration", "smb_signing_vuln", "  [VULN] SMB Signing not required (relay attacks such as NTLM relay are possible)", port=SMB_PORT)
                else:
                    dialect_name = "SMB2/3 (unparseable negotiate response)"
                    log_and_print("enumeration", "smb_dialect", "  [+] SMB2/3 header returned but negotiate body could not be parsed", port=SMB_PORT)
    except Exception as e:
        log_and_print("enumeration", "smb_fault", f"  [-] SMB Negotiate Exception: {e}", port=SMB_PORT)

    # Guest / anonymous null-session test (SMB2 Session Setup, NTLM null credentials)
    guest_status = "Undetermined"
    ntlm_version = None
    if not smbv1_active:
        try:
            s3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s3.settimeout(timeout)
            s3.connect((target, SMB_PORT))
            s3.sendall(build_smb2_negotiate_request([0x0202, 0x0210, 0x0300, 0x0302], message_id=0))
            s3.recv(4096)

            s3.sendall(build_smb2_session_setup(build_ntlm_negotiate_minimal(), message_id=1))
            resp1 = s3.recv(4096)
            ntlm_version = _parse_ntlm_challenge_version(resp1) if resp1 else None
            if ntlm_version:
                log_and_print("enumeration", "smb_ntlm_os_version", f"  [+] OS Version (via NTLM CHALLENGE_MESSAGE): {ntlm_version['label']}", port=SMB_PORT)
            if resp1 and len(resp1) >= 48:
                status1 = struct.unpack('<I', resp1[8:12])[0]
                session_id = struct.unpack('<Q', resp1[44:52])[0] if len(resp1) >= 52 else 0
                if status1 == 0xC0000016:  # STATUS_MORE_PROCESSING_REQUIRED
                    s3.sendall(build_smb2_session_setup(build_ntlm_authenticate_null(), message_id=2, session_id=session_id))
                    resp2 = s3.recv(4096)
                    status2 = struct.unpack('<I', resp2[8:12])[0] if len(resp2) >= 12 else None
                    if status2 == 0x00000000:
                        guest_status = "ALLOWED - Anonymous/Null Session Established"
                        log_and_print("enumeration", "smb_guest_login", "  [VULN] Anonymous/Null SMB session allowed (no credentials required) - enables limited enumeration (shares, users, policy)", port=SMB_PORT)
                    elif status2 in (0xC000006D, 0xC0000022):  # LOGON_FAILURE / ACCESS_DENIED
                        guest_status = "Rejected (properly secured)"
                        log_and_print("enumeration", "smb_guest_login_secure", "  [+] Anonymous/Null session rejected (guest login disabled - secure configuration)", port=SMB_PORT)
                    else:
                        guest_status = f"Undetermined (status 0x{status2:08x})" if status2 is not None else "Undetermined"
                        log_and_print("enumeration", "smb_guest_login_undetermined", f"  [-] Guest login test returned an unexpected status: {guest_status}", port=SMB_PORT)
                else:
                    guest_status = f"NTLM negotiation not accepted (status 0x{status1:08x})"
                    log_and_print("enumeration", "smb_guest_login_no_ntlm", f"  [-] Server did not proceed with NTLM negotiation: {guest_status}", port=SMB_PORT)
            s3.close()
        except Exception as e:
            log_and_print("enumeration", "smb_guest_fault", f"  [-] Guest/Null session probe anomaly: {e}", port=SMB_PORT)
    else:
        log_and_print("enumeration", "smb_guest_skip", "  [-] Guest/Null session probe skipped (SMBv1-only host; would require a legacy Session Setup AndX implementation)", port=SMB_PORT)

    # NetBIOS name service details (UDP/137 companion query)
    nbt_info = query_netbios_name_service(target, timeout)
    if nbt_info["computer_name"] or nbt_info["workgroup"]:
        log_and_print("enumeration", "smb_netbios_name", f"  [+] NetBIOS Computer Name: {nbt_info['computer_name'] or 'N/A'}", port=SMB_PORT)
        log_and_print("enumeration", "smb_netbios_workgroup", f"  [+] NetBIOS Workgroup/Domain: {nbt_info['workgroup'] or 'N/A'}", port=SMB_PORT)
        if nbt_info["mac_address"]:
            log_and_print("enumeration", "smb_netbios_mac", f"  [+] Adapter MAC Address (via NBSTAT): {nbt_info['mac_address']}", port=SMB_PORT)
    else:
        log_and_print("enumeration", "smb_netbios_none", "  [-] No NetBIOS Name Service response on UDP/137 (host may be SMB-over-TCP only / NBT disabled)", port=SMB_PORT)

    scan_results["port_scans"]["445"]["version"] = (
        f"{'SMBv1 (Legacy)' if smbv1_active else dialect_name} | "
        f"{smb_implementation + ' | ' if smb_implementation else ''}"
        f"{'OS: ' + ntlm_version['label'] + ' | ' if ntlm_version else ''}"
        f"Signing Required: {security_mode_info['signing_required'] if security_mode_info else 'N/A'} | "
        f"Guest Login: {guest_status} | NetBIOS Name: {nbt_info['computer_name'] or 'N/A'}"
    )

def run_mysql_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "mysql_init", f"[*] Auditing MySQL Database Protocol Handshake on {target}:{MYSQL_PORT}", port=MYSQL_PORT)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, MYSQL_PORT))
        data = s.recv(1024)
        s.close()

        if len(data) >= 5:
            proto_ver = data[4]
            if proto_ver == 10:
                null_idx = data.find(b'\x00', 5)
                server_ver = data[5:null_idx].decode('utf-8', errors='ignore')
                scan_results["port_scans"]["3306"]["version"] = f"MySQL/MariaDB v{server_ver}"
                log_and_print("enumeration", "mysql_version", f"  [+] MySQL Protocol v10 Detected | Version: {server_ver}", port=MYSQL_PORT)
            else:
                log_and_print("enumeration", "mysql_proto", f"  [+] Non-standard MySQL Protocol Version: {proto_ver}", port=MYSQL_PORT)
    except Exception as e:
        log_and_print("enumeration", "mysql_fault", f"  [-] MySQL Handshake Error: {e}", port=MYSQL_PORT)

def _postgres_build_startup_packet(user, database, extra_params=None):
    """Builds a v3.0 StartupMessage. Sent with a deliberately invalid/absent
    role so the server rejects the login pre-auth - but its rejection message
    ('FATAL: password authentication failed for user "x"', 'role "x" does not
    exist', etc.) is emitted by the *actual* running backend, and on many
    default installs the very first ErrorResponse also lets slip build/version
    detail lines depending on log_error_verbosity. Even when it doesn't, the
    structured error still confirms live PostgreSQL wire-protocol behavior
    rather than just a raw SSL byte."""
    params = {"user": user, "database": database, "application_name": "recon_agent"}
    if extra_params:
        params.update(extra_params)
    body = b""
    for k, v in params.items():
        body += k.encode() + b"\x00" + str(v).encode() + b"\x00"
    body += b"\x00"
    length = 4 + 4 + len(body)
    return struct.pack("!II", length, 196608) + body  # 196608 = protocol 3.0


def _pg_read_message(sock, timeout):
    """Reads one PostgreSQL wire-protocol backend message: 1-byte type code,
    4-byte big-endian length (includes itself, excludes the type byte), then
    that many bytes of payload."""
    sock.settimeout(timeout)
    msg_type = recv_exact_bytes(sock, 1)
    if not msg_type:
        return None, b""
    length_bytes = recv_exact_bytes(sock, 4)
    if len(length_bytes) < 4:
        return msg_type, b""
    length = struct.unpack("!I", length_bytes)[0]
    payload = recv_exact_bytes(sock, length - 4) if length > 4 else b""
    return msg_type, payload


_PG_AUTH_LABELS = {3: "cleartext password", 5: "MD5 password", 7: "GSSAPI", 9: "SSPI", 10: "SASL/SCRAM"}

def _postgres_attempt_trust_query(target, timeout, user, database):
    """Attempts a real (credential-free) login using a common default
    role/database name - not a password guess, just observing whether the
    server's pg_hba.conf grants 'trust'/no-password access for this
    role+host, which is a real and fairly common misconfiguration on lab and
    default-install targets. If it's permitted, runs the harmless read-only
    'SELECT version()' to get the exact, authoritative version string
    straight from the backend instead of guessing from banners. If the
    server properly demands a password, this backs off immediately without
    attempting any credential."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, POSTGRES_PORT))
        s.sendall(_postgres_build_startup_packet(user, database))

        msg_type, payload = _pg_read_message(s, timeout)
        if msg_type != b'R' or len(payload) < 4:
            s.close()
            return None, "No AuthenticationRequest received"
        auth_code = struct.unpack("!I", payload[:4])[0]
        if auth_code != 0:
            s.close()
            return None, f"Authentication required ({_PG_AUTH_LABELS.get(auth_code, f'type {auth_code}')}) - no credentials attempted"

        # AuthenticationOk - drain ParameterStatus/BackendKeyData until ReadyForQuery
        for _ in range(25):
            msg_type, payload = _pg_read_message(s, timeout)
            if msg_type in (b'Z', b'', None):
                break

        query = b"SELECT version();\x00"
        s.sendall(b'Q' + struct.pack("!I", 4 + len(query)) + query)

        version_text = None
        for _ in range(25):
            msg_type, payload = _pg_read_message(s, timeout)
            if msg_type in (b'', None):
                break
            if msg_type == b'D' and len(payload) >= 6:  # DataRow
                field_count = struct.unpack("!H", payload[0:2])[0]
                if field_count >= 1:
                    flen = struct.unpack("!i", payload[2:6])[0]
                    if flen > 0:
                        version_text = payload[6:6 + flen].decode('utf-8', errors='ignore')
            if msg_type == b'Z':
                break
        s.close()
        return (version_text, None) if version_text else (None, "Query executed but returned no data")
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def run_postgres_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "postgres_init", f"[*] Auditing PostgreSQL Service SSL/Handshake on {target}:{POSTGRES_PORT}", port=POSTGRES_PORT)
    ssl_state = "Unknown"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, POSTGRES_PORT))

        ssl_request = struct.pack("!II", 8, 80877103)
        s.sendall(ssl_request)
        response = s.recv(1)

        if response == b'S':
            log_and_print("enumeration", "postgres_ssl", "  [+] PostgreSQL SSL Encryption Supported", port=POSTGRES_PORT)
            ssl_state = "SSL Enabled"
        elif response == b'N':
            log_and_print("enumeration", "postgres_ssl", "  [-] PostgreSQL SSL Encryption Disabled", port=POSTGRES_PORT)
            ssl_state = "SSL Disabled"
        s.close()
    except Exception as e:
        log_and_print("enumeration", "postgres_fault", f"  [-] PostgreSQL SSL Probe Error: {e}", port=POSTGRES_PORT)

    version_str = None
    trust_auth_hit = None

    # Phase 1: real credential-free login attempt with common default
    # role/database combinations - this is the same category of check this
    # tool already runs for FTP anonymous access and unauthenticated Redis.
    for probe_user, probe_db in (("postgres", "postgres"), ("postgres", "template1")):
        raw_version, note = _postgres_attempt_trust_query(target, timeout, probe_user, probe_db)
        if raw_version:
            version_str = raw_version.strip()
            trust_auth_hit = f"user='{probe_user}' db='{probe_db}'"
            log_and_print("enumeration", "postgres_trust_auth",
                           f"  [VULN] Passwordless/trust authentication accepted for {trust_auth_hit} - exact version confirmed via live query: {version_str}",
                           port=POSTGRES_PORT)
            break
        else:
            log_and_print("enumeration", f"postgres_trust_probe_{probe_user}_{probe_db}", f"  [-] {probe_user}/{probe_db}: {note}", port=POSTGRES_PORT)

    # Phase 2 (fallback only): best-effort version leak from an ErrorResponse
    # to a deliberately-invalid role, for servers that properly require auth.
    if not version_str:
        try:
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.settimeout(timeout)
            s2.connect((target, POSTGRES_PORT))
            s2.sendall(_postgres_build_startup_packet("recon_probe_nonexistent", "postgres"))
            raw = s2.recv(4096)
            s2.close()

            if raw:
                text = raw.decode('utf-8', errors='ignore')
                log_and_print("enumeration", "postgres_error_response", f"  [+] Backend responded to StartupMessage ({len(raw)} bytes)", port=POSTGRES_PORT)
                ver_match = re.search(r'PostgreSQL\s+(\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)', text)
                if ver_match:
                    version_str = f"PostgreSQL {ver_match.group(1)}"
                    log_and_print("enumeration", "postgres_version", f"  [+] Version leaked in error detail: {version_str}", port=POSTGRES_PORT)
                elif "does not exist" in text.lower() or "password authentication failed" in text.lower():
                    log_and_print("enumeration", "postgres_auth_behavior", "  [+] Confirmed live PostgreSQL backend via authentication ErrorResponse (properly requires credentials, no version disclosed)", port=POSTGRES_PORT)
        except Exception as e:
            log_and_print("enumeration", "postgres_fault", f"  [-] PostgreSQL StartupMessage Probe Error: {e}", port=POSTGRES_PORT)

    if version_str:
        suffix = f" [VULN: passwordless access via {trust_auth_hit}]" if trust_auth_hit else ""
        scan_results["port_scans"]["5432"]["version"] = f"{version_str} ({ssl_state}){suffix}"
    else:
        scan_results["port_scans"]["5432"]["version"] = f"PostgreSQL Server Active ({ssl_state}) - exact version requires authentication (server properly enforces auth)"

def run_redis_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "redis_init", f"[*] Auditing Redis Key-Value Store on {target}:{REDIS_PORT}", port=REDIS_PORT)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, REDIS_PORT))
        s.sendall(b"INFO\r\n")
        data = s.recv(4096).decode('utf-8', errors='ignore')
        s.close()

        if "redis_version" in data:
            ver_match = re.search(r"redis_version:(.*?\r\n)", data)
            version = ver_match.group(1).strip() if ver_match else "Unknown"
            scan_results["port_scans"]["6379"]["version"] = f"Redis Server v{version} (Unauthenticated)"
            log_and_print("enumeration", "redis_info", f"  [VULN] Redis Server Responded without Authentication | Version: {version}", port=REDIS_PORT)
        elif "NOAUTH" in data or "WRONGPASS" in data:
            scan_results["port_scans"]["6379"]["version"] = "Redis Server (Auth Required)"
            log_and_print("enumeration", "redis_auth", "  [+] Redis Server Active (Password Protected)", port=REDIS_PORT)
        else:
            scan_results["port_scans"]["6379"]["version"] = "Redis Server Active"
            log_and_print("enumeration", "redis_status", "  [+] Redis Service Responding", port=REDIS_PORT)
    except Exception as e:
        log_and_print("enumeration", "redis_fault", f"  [-] Redis Handshake Error: {e}", port=REDIS_PORT)

# ==============================================================================
# HTTP/HTTPS AUDIT MODULE: Server Header, X-Powered-By, TLS Cert CN, Framework Fingerprints
# ==============================================================================
_HTTP_TLS_PORTS = {HTTPS_PORT, *HTTPS_ALT_PORTS}

def send_https_raw_request(target, port, path="/", method="GET"):
    """TLS-wrapped counterpart to send_http_raw_request. Needed because the
    generic helper only speaks plaintext HTTP - every TLS-listening port
    (443, 8443, 9443, ...) was previously getting zero application-layer
    probing at all, which is the root cause of HTTP version reporting being
    stuck at 'port/service correct, version missing'."""
    timeout = get_dynamic_timeout()
    try:
        req = f"{method} {path} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: ReconScanner/2.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=target)
        tls_sock.connect((target, port))
        cert_bin = tls_sock.getpeercert(binary_form=False)
        tls_sock.sendall(req.encode('utf-8'))
        resp = b""
        while True:
            chunk = tls_sock.recv(4096)
            if not chunk: break
            resp += chunk
        tls_sock.close()

        resp_str = resp.decode('utf-8', errors='ignore')
        parts = resp_str.split("\r\n\r\n", 1)
        headers_raw = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""
        status_line = headers_raw.split("\r\n")[0] if headers_raw else ""
        headers = {}
        for line in headers_raw.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return status_line, headers, body, cert_bin
    except Exception:
        return "", {}, "", None


def _extract_http_server_identity(headers, body):
    """Pulls the most specific version string available across the common
    HTTP fingerprint surfaces, in priority order: Server header (most
    authoritative), X-Powered-By (framework/runtime), then well-known
    generator meta tags in the body (e.g. WordPress) as a last resort."""
    server_hdr = headers.get("server", "").strip()
    powered_by = headers.get("x-powered-by", "").strip()

    parts = []
    if server_hdr:
        parts.append(server_hdr)
    if powered_by:
        parts.append(powered_by)

    if not parts and body:
        gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.IGNORECASE)
        if gen_match:
            parts.append(gen_match.group(1).strip())

    return " | ".join(parts) if parts else None


def run_http_advanced_audit(target, port):
    """Covers plain HTTP (80) and every TLS-listening HTTP port (443, 8443,
    9443) - previously none of these had a dedicated module, so the only
    thing recorded was 'open' from the raw port scan and version stayed
    'Not Evaluated'."""
    timeout = get_dynamic_timeout()
    is_tls = port in _HTTP_TLS_PORTS
    log_and_print("enumeration", "http_init", f"[*] Auditing {'HTTPS' if is_tls else 'HTTP'} Service on {target}:{port}", port=port)

    cert_info = None
    if is_tls:
        status_line, headers, body, cert_bin = send_https_raw_request(target, port, "/", "GET")
        if cert_bin:
            cn = cert_bin.get("subject", ())
            cert_cn = next((v for tup in cn for (k, v) in tup if k == "commonName"), None)
            if cert_cn:
                cert_info = cert_cn
                log_and_print("enumeration", "http_tls_cert", f"  [+] TLS Certificate CN: {cert_cn}", port=port)
    else:
        status_line, headers, body = send_http_raw_request(target, port, "/", "GET")

    if not status_line and not headers:
        log_and_print("enumeration", "http_fault", f"  [-] No HTTP response received on port {port}", port=port)
        return

    if status_line:
        log_and_print("enumeration", "http_status", f"  [+] {status_line}", port=port)

    identity = _extract_http_server_identity(headers, body)
    if identity:
        log_and_print("enumeration", "http_server_header", f"  [+] Server Identity: {identity}", port=port)
        scan_results["port_scans"][str(port)]["version"] = identity
    else:
        # Server deliberately suppressed identifying headers - common hardening
        # practice, not a scan failure. Report the confirmed-active state
        # honestly rather than fabricating a version.
        fallback = "HTTP Server Active (headers suppressed - no version disclosed)"
        scan_results["port_scans"][str(port)]["version"] = fallback
        log_and_print("enumeration", "http_no_banner", "  [-] Server/X-Powered-By headers not present", port=port)

    for hdr_key in ("x-aspnet-version", "x-aspnetmvc-version"):
        if hdr_key in headers:
            log_and_print("enumeration", "http_framework_header", f"  [+] {hdr_key}: {headers[hdr_key]}", port=port)


# ==============================================================================
# SMTP AUDIT MODULE: Banner Grab, EHLO Capability Set, MTA Version
# ==============================================================================
def _smtp_read_multiline(sock, timeout):
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            # SMTP multiline replies use "code-text" for continuation lines and
            # "code text" (space) on the final line - stop once we see that.
            lines = data.split(b"\r\n")
            last = next((l for l in reversed(lines) if l), b"")
            if len(last) >= 4 and last[3:4] == b" ":
                break
    except Exception:
        pass
    return data.decode('utf-8', errors='ignore')


def run_smtp_advanced_audit(target, port):
    """Grabs the SMTP greeting banner and EHLO capability response - the two
    places an MTA identifies itself (Postfix, Exim, Sendmail, Microsoft
    Exchange/ESMTP all announce name+version in the 220 greeting). Previously
    there was no SMTP module at all, so ports 25/465/587 only ever got
    'service correct, version missing' from the generic port scan."""
    timeout = get_dynamic_timeout()
    is_implicit_tls = (port == 465)
    log_and_print("enumeration", "smtp_init", f"[*] Auditing SMTP Service on {target}:{port}", port=port)

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((target, port))

        if is_implicit_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=target)
        else:
            sock = raw_sock

        greeting = _smtp_read_multiline(sock, timeout)
        if greeting:
            log_and_print("enumeration", "smtp_banner", f"  [+] Greeting: {greeting.strip()}", port=port)

        sock.sendall(b"EHLO recon-agent.local\r\n")
        ehlo_resp = _smtp_read_multiline(sock, timeout)
        if ehlo_resp:
            log_and_print("enumeration", "smtp_ehlo", f"  [+] EHLO Capabilities:\n" + "\n".join(f"      {l}" for l in ehlo_resp.strip().splitlines()), port=port)
        sock.close()

        combined = f"{greeting} {ehlo_resp}"
        # Known MTA identity patterns, most specific first.
        mta_patterns = [
            r'(Microsoft ESMTP MAIL Service[^\r\n]*)',
            r'(Postfix[^\r\n]*)',
            r'(Exim\s[\d.]+[^\r\n]*)',
            r'(Sendmail[^\r\n]*)',
            r'(Exchange Server[^\r\n]*)',
        ]
        identity = None
        for pat in mta_patterns:
            m = re.search(pat, combined, re.IGNORECASE)
            if m:
                identity = m.group(1).strip()
                break

        if identity:
            scan_results["port_scans"][str(port)]["version"] = identity
            log_and_print("enumeration", "smtp_version", f"  [+] MTA Identity: {identity}", port=port)
        elif greeting.strip():
            # Fall back to the raw 220 line itself - still far more useful
            # than "Not Evaluated" and often contains a hostname/product hint.
            clean = re.sub(r'^\d{3}[- ]?', '', greeting.strip().splitlines()[0]).strip()
            scan_results["port_scans"][str(port)]["version"] = clean if clean else "SMTP Server Active"
        else:
            scan_results["port_scans"][str(port)]["version"] = "SMTP Server Active"
    except Exception as e:
        log_and_print("enumeration", "smtp_fault", f"  [-] SMTP Audit Exception: {e}", port=port)


# ==============================================================================
# RDP AUDIT MODULE: NLA Detection, Protocol Version, Encryption Level
# ==============================================================================
RDP_NEG_REQ, RDP_NEG_RSP, RDP_NEG_FAILURE = 0x01, 0x02, 0x03
PROTOCOL_RDP, PROTOCOL_SSL, PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX = 0x00000000, 0x00000001, 0x00000002, 0x00000008
RDP_FAILURE_CODES = {
    1: "SSL_REQUIRED_BY_SERVER", 2: "SSL_NOT_ALLOWED_BY_SERVER", 3: "SSL_CERT_NOT_ON_SERVER",
    4: "INCONSISTENT_FLAGS", 5: "HYBRID_REQUIRED_BY_SERVER", 6: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"
}
RDP_ENCRYPTION_METHODS = {0: "None", 1: "40-bit RC4", 2: "128-bit RC4", 8: "56-bit RC4", 0x10: "FIPS 140-1"}
RDP_ENCRYPTION_LEVELS = {0: "None", 1: "Low", 2: "Client Compatible", 3: "High", 4: "FIPS Compliant"}

def build_x224_negotiation_request(requested_protocols):
    neg_req = struct.pack('<BBHI', RDP_NEG_REQ, 0x00, 0x0008, requested_protocols)
    x224_body = b'\xe0\x00\x00\x00\x00\x00' + neg_req
    x224 = struct.pack('B', len(x224_body)) + x224_body
    return struct.pack('>BBH', 3, 0, 4 + len(x224)) + x224

def parse_x224_negotiation_response(data):
    result = {"selected_protocol": None, "failure_code": None, "negotiation_present": False}
    if not data or len(data) < 6:
        return result
    if data[4] <= 6:
        return result
    nego_offset = 11
    if len(data) < nego_offset + 8:
        return result
    nego_type = data[nego_offset]
    value = struct.unpack('<I', data[nego_offset + 4:nego_offset + 8])[0]
    result["negotiation_present"] = True
    if nego_type == RDP_NEG_RSP:
        result["selected_protocol"] = value
    elif nego_type == RDP_NEG_FAILURE:
        result["failure_code"] = value
    return result

def run_rdp_advanced_audit(target, port=RDP_PORT):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "rdp_init", f"[*] Auditing RDP Service on {target}:{port} (NLA Detection, Protocol Version, Encryption Level)", port=port)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        requested = PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX
        sock.send(build_x224_negotiation_request(requested))
        log_and_print("enumeration", "rdp_neg_req", f"  [+] X.224 Connection Request + RDP Negotiation Request sent (requestedProtocols=SSL|HYBRID|HYBRID_EX)", port=port)

        resp = sock.recv(4096)
        if not resp:
            log_and_print("enumeration", "rdp_no_response", "  [-] No response to X.224/RDP Negotiation Request - target may not speak RDP", port=port)
            return
        parsed = parse_x224_negotiation_response(resp)

        if parsed["failure_code"] is not None:
            fcode = parsed["failure_code"]
            log_and_print("enumeration", "rdp_neg_failure", f"  [+] Negotiation Response: FAILURE ({RDP_FAILURE_CODES.get(fcode, f'code {fcode}')})", port=port)
            if fcode == 5:
                log_and_print("enumeration", "rdp_nla_forced", "  [+] Server mandates Hybrid/CredSSP -> Network Level Authentication (NLA) is ENFORCED", port=port)
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            sock.send(build_x224_negotiation_request(PROTOCOL_RDP))
            resp = sock.recv(4096)
            parsed = parse_x224_negotiation_response(resp)

        selected = parsed["selected_protocol"]
        proto_names = {0: "Standard RDP Security", 1: "TLS/SSL", 2: "CredSSP (Hybrid/NLA)", 8: "CredSSP + Early User Auth"}
        if selected is None and not parsed["negotiation_present"]:
            selected = PROTOCOL_RDP
            log_and_print("enumeration", "rdp_legacy", "  [+] No negotiation block returned (legacy server) -> Standard RDP Security assumed", port=port)
        elif selected is not None:
            log_and_print("enumeration", "rdp_neg_success", f"  [+] Negotiation Response: SUCCESS -> selectedProtocol={selected} ({proto_names.get(selected, 'Unknown')})", port=port)

        if selected == PROTOCOL_RDP:
            sec_layer, nla, tls_support = "RDP Security (Standard/Native Encryption)", False, False
        elif selected == PROTOCOL_SSL:
            sec_layer, nla, tls_support = "SSL/TLS", False, True
        elif selected in (PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX):
            sec_layer, nla, tls_support = "CredSSP (Hybrid/NLA)", True, True
        else:
            sec_layer, nla, tls_support = "Undetermined", False, False

        log_and_print("enumeration", "rdp_security_layer", f"  [+] Security Layer: {sec_layer}", port=port)
        log_and_print("enumeration", "rdp_nla_status", f"  [+] Network Level Authentication (NLA): {'Enabled' if nla else 'Disabled'}", port=port)
        if not nla and selected in (PROTOCOL_RDP, PROTOCOL_SSL):
            log_and_print("enumeration", "rdp_nla_vuln", "  [VULN] NLA disabled - server permits establishing a session before authentication, larger pre-auth attack surface (e.g. BlueKeep-class exploitation)", port=port)

        tls_version_str = "N/A"
        if tls_support:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
                except ssl.SSLError:
                    pass
                tls_sock = ctx.wrap_socket(sock, server_hostname=target)
                cipher_info = tls_sock.cipher()
                if cipher_info:
                    tls_version_str = cipher_info[1]
                    log_and_print("enumeration", "rdp_tls_version", f"  [+] TLS Protocol Version: {cipher_info[1]} | Cipher: {cipher_info[0]} ({cipher_info[2]}-bit)", port=port)
                sock = tls_sock
            except Exception as e:
                log_and_print("enumeration", "rdp_tls_fault", f"  [-] TLS handshake anomaly: {e}", port=port)

        # Encryption Method/Level - only meaningful outside a CredSSP tunnel (legacy GCC field)
        if selected in (PROTOCOL_RDP, PROTOCOL_SSL):
            enc_method, enc_level = probe_rdp_encryption_level(sock, timeout)
            if enc_method is not None:
                log_and_print("enumeration", "rdp_encryption_method", f"  [+] Encryption Method: {RDP_ENCRYPTION_METHODS.get(enc_method, f'Unknown ({enc_method})')}", port=port)
                log_and_print("enumeration", "rdp_encryption_level", f"  [+] Encryption Level: {RDP_ENCRYPTION_LEVELS.get(enc_level, f'Unknown ({enc_level})')}", port=port)
                if enc_level in (0, 1):
                    log_and_print("enumeration", "rdp_encryption_vuln", f"  [VULN] Weak legacy RDP encryption level ({RDP_ENCRYPTION_LEVELS.get(enc_level)}) - traffic may be susceptible to interception/tampering", port=port)
                scan_results["port_scans"][str(port)]["version"] = f"RDP | Security: {sec_layer} | NLA: {nla} | Encryption: {RDP_ENCRYPTION_LEVELS.get(enc_level, 'Unknown')} | TLS: {tls_version_str}"
            else:
                log_and_print("enumeration", "rdp_encryption_undetermined", "  [-] Encryption Level: Undetermined (server returned no parseable legacy Security Data)", port=port)
                scan_results["port_scans"][str(port)]["version"] = f"RDP | Security: {sec_layer} | NLA: {nla} | TLS: {tls_version_str}"
        else:
            log_and_print("enumeration", "rdp_encryption_na", "  [+] Encryption Level: N/A (transport secured end-to-end via CredSSP/TLS; legacy field not applicable)", port=port)
            scan_results["port_scans"][str(port)]["version"] = f"RDP | Security: {sec_layer} | NLA: {nla} | TLS: {tls_version_str}"

        sock.close()
    except Exception as e:
        log_and_print("enumeration", "rdp_fault", f"  [-] RDP Audit Exception: {e}", port=port)
        try:
            sock.close()
        except Exception:
            pass

def build_client_mcs_connect_initial(encryption_methods=0x1F):
    """EXPERIMENTAL / BEST-EFFORT: simplified Client MCS Connect Initial PDU, sent only to
    coax a Standard-RDP or TLS-only server into echoing its legacy Server Security Data
    block (encryptionMethod/encryptionLevel). A parse failure is reported as Undetermined,
    never as a negative/negative-confidence result."""
    core_body = struct.pack('<I', 0x00080004)
    core_body += struct.pack('<HH', 1024, 768)
    core_body += struct.pack('<HH', 0xCA01, 1)
    core_body += struct.pack('<I', 0x00000409)
    core_body += struct.pack('<I', 2600)
    core_body += "reconcli".encode('utf-16-le').ljust(32, b'\x00')[:32]
    core_body += struct.pack('<I', 4) + struct.pack('<I', 0) + struct.pack('<I', 12) + b'\x00' * 64
    client_core = struct.pack('<HH', 0xC001, 4 + len(core_body)) + core_body

    client_security = struct.pack('<HH', 0xC002, 12) + struct.pack('<II', encryption_methods, 0)
    client_network = struct.pack('<HH', 0xC003, 8) + struct.pack('<HH', 0, 0)
    user_data = client_core + client_security + client_network

    gcc_header = b'\x00\x05\x00\x14\x7c\x00\x01\x2a\x14\x76\x0a\x01\x01\x00\x01\xc0'
    gcc_pdu = gcc_header + struct.pack('>H', 0x8000 | len(user_data)) + user_data

    def der_len(n):
        return struct.pack('B', n) if n < 0x80 else struct.pack('B', 0x80 | ((n.bit_length() + 7) // 8)) + n.to_bytes((n.bit_length() + 7) // 8, 'big')
    def der_tlv(tag, value):
        return struct.pack('B', tag) + der_len(len(value)) + value

    domain_selector = der_tlv(0x04, b'\x01')
    upward_flag = der_tlv(0x01, b'\xff')
    domain_params = der_tlv(0x30,
        b'\x02\x01\x22\x02\x01\x02\x02\x01\x00\x02\x01\x01'
        b'\x02\x01\x00\x02\x01\x01\x02\x03\x00\xff\xff\x02\x01\x02')
    mcs_body = (domain_selector + domain_selector + upward_flag +
                domain_params + domain_params + domain_params + der_tlv(0x04, gcc_pdu))
    mcs_ci = b'\x7f\x65' + der_len(len(mcs_body)) + mcs_body
    x224_data = b'\x02\xf0\x80' + mcs_ci
    return struct.pack('>BBH', 3, 0, 4 + len(x224_data)) + x224_data

def probe_rdp_encryption_level(sock, timeout):
    try:
        sock.settimeout(timeout)
        sock.send(build_client_mcs_connect_initial())
        data = sock.recv(8192)
    except Exception:
        return None, None
    idx = data.find(b'\x02\x0c')  # little-endian 0x0C02 == SC_SECURITY block header
    if idx == -1 or len(data) < idx + 12:
        return None, None
    try:
        return struct.unpack('<II', data[idx + 4:idx + 12])
    except Exception:
        return None, None

def run_kerberos_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "kerberos_init", f"[*] Auditing Kerberos Key Distribution Center (KDC) on {target}:{KERBEROS_PORT}", port=KERBEROS_PORT)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, KERBEROS_PORT))
        dummy_req = b"\x00\x00\x00\x04\x6e\x81\x00\x00"
        s.sendall(dummy_req)
        resp = s.recv(1024)
        s.close()

        if resp:
            scan_results["port_scans"]["88"]["version"] = "Kerberos KDC (v5)"
            log_and_print("enumeration", "kerberos_status", "  [+] Kerberos v5 KDC Active and responding to probes", port=KERBEROS_PORT)
        else:
            scan_results["port_scans"]["88"]["version"] = "Kerberos Service Active"
    except Exception as e:
        log_and_print("enumeration", "kerberos_fault", f"  [-] Kerberos Connection Anomaly: {e}", port=KERBEROS_PORT)

def run_oracle_advanced_audit(target):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "oracle_init", f"[*] Auditing Oracle TNS Listener on {target}:{ORACLE_PORT}", port=ORACLE_PORT)
    
    tns_connect = (
        b"\x00\x3a\x00\x00\x01\x00\x00\x00\x01\x36\x01\x2c\x00\x00\x08\x00"
        b"\x7f\xff\x01\x00\x00\x00\x00\x20\x00\x3a\x00\x01\x20\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"(CONNECT_DATA=(COMMAND=version))"
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, ORACLE_PORT))
        s.sendall(tns_connect)
        data = s.recv(2048).decode('utf-8', errors='ignore')
        s.close()

        if "VSNNUM" in data or "TNSLSNR" in data:
            scan_results["port_scans"]["1521"]["version"] = "Oracle TNS Listener Active"
            log_and_print("enumeration", "oracle_tns", "  [+] Oracle TNS Listener Active (Version Data Extracted)", port=ORACLE_PORT)
        else:
            scan_results["port_scans"]["1521"]["version"] = "Oracle Database Service"
            log_and_print("enumeration", "oracle_status", "  [+] Oracle Service Port responding", port=ORACLE_PORT)
    except Exception as e:
        log_and_print("enumeration", "oracle_fault", f"  [-] Oracle TNS Probe Error: {e}", port=ORACLE_PORT)

# ==============================================================================
# DNS AUDIT MODULE: AXFR, Recursion, DNSSEC, CHAOS version.bind, Zone Enumeration
# ==============================================================================
def dns_recv_tcp_message(sock, timeout):
    """DNS-over-TCP framing: 2-byte big-endian length prefix + message."""
    sock.settimeout(timeout)
    length_bytes = recv_exact_bytes(sock, 2)
    if len(length_bytes) < 2:
        return None
    msg_len = struct.unpack('>H', length_bytes)[0]
    msg = recv_exact_bytes(sock, msg_len)
    return msg if len(msg) == msg_len else None

def guess_zone_from_ptr(target, timeout):
    """Heuristic: reverse-resolve the target's own IP against itself and take the last
    two labels of the PTR result as a naive apex-zone guess (does not handle multi-part
    TLDs like co.uk correctly - best-effort only, used purely to give AXFR/zone-walk
    something to test against when no zone name was supplied)."""
    try:
        octets = target.split('.')
        if len(octets) != 4:
            return None
        ptr_name = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"
        pkt = IP(dst=target) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=ptr_name, qtype="PTR"))
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp and resp.haslayer(DNS) and resp[DNS].ancount > 0:
            hostname = resp[DNS].an.rdata
            if isinstance(hostname, bytes):
                hostname = hostname.decode('utf-8', errors='ignore')
            hostname = hostname.rstrip('.')
            labels = hostname.split('.')
            if len(labels) >= 2:
                return ".".join(labels[-2:]), hostname
    except Exception:
        pass
    return None, None

def run_dns_advanced_audit(target, port=DNS_PORT):
    timeout = get_dynamic_timeout()
    log_and_print("enumeration", "dns_init", f"[*] Auditing DNS Service on {target}:{port} (AXFR, Recursion, DNSSEC, CHAOS version.bind, Zone Enumeration)", port=port)
    findings = []

    # 1) CHAOS class version.bind query - classic server-software fingerprint
    try:
        pkt = IP(dst=target) / UDP(dport=port) / DNS(rd=0, qd=DNSQR(qname="version.bind", qtype="TXT", qclass=3))
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp and resp.haslayer(DNS) and resp[DNS].ancount > 0:
            rdata = resp[DNS].an.rdata
            version_str = rdata.decode('utf-8', errors='ignore') if isinstance(rdata, bytes) else str(rdata)
            log_and_print("enumeration", "dns_version_bind", f"  [+] CHAOS version.bind -> {version_str}", port=port)
            findings.append(f"Software: {version_str}")
        else:
            log_and_print("enumeration", "dns_version_bind_blocked", "  [-] CHAOS version.bind query not answered (version disclosure disabled/blocked - good practice)", port=port)
    except Exception as e:
        log_and_print("enumeration", "dns_version_bind_fault", f"  [-] CHAOS version.bind probe anomaly: {e}", port=port)

    # 2) Recursion / open-resolver test
    try:
        pkt = IP(dst=target) / UDP(dport=port) / DNS(rd=1, qd=DNSQR(qname="www.google.com", qtype="A"))
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp and resp.haslayer(DNS):
            recursion_available = bool(resp[DNS].ra)
            answered = resp[DNS].ancount > 0
            if recursion_available and answered:
                log_and_print("enumeration", "dns_open_resolver", "  [VULN] Open Resolver - recursion enabled for arbitrary external queries (abusable for DNS amplification attacks)", port=port)
                findings.append("Recursion: ENABLED (open resolver)")
            elif recursion_available:
                log_and_print("enumeration", "dns_recursion_flag", "  [+] Server sets Recursion Available (RA) but did not return an answer for the test query", port=port)
                findings.append("Recursion: RA flag set, no answer")
            else:
                log_and_print("enumeration", "dns_recursion_disabled", "  [+] Recursion disabled / authoritative-only response (secure default for an internet-facing name server)", port=port)
                findings.append("Recursion: Disabled")
        else:
            log_and_print("enumeration", "dns_recursion_no_response", "  [-] No response to recursion test query", port=port)
    except Exception as e:
        log_and_print("enumeration", "dns_recursion_fault", f"  [-] Recursion test anomaly: {e}", port=port)

    # 3) DNSSEC validation test (dnssec-failed.org is intentionally broken, purpose-built for this test)
    try:
        pkt = IP(dst=target) / UDP(dport=port) / DNS(rd=1, qd=DNSQR(qname="dnssec-failed.org", qtype="A"))
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp and resp.haslayer(DNS):
            rcode = resp[DNS].rcode
            if rcode == 2:  # SERVFAIL
                log_and_print("enumeration", "dns_dnssec_validating", "  [+] DNSSEC Validation CONFIRMED - resolver returns SERVFAIL for the intentionally-broken dnssec-failed.org test domain", port=port)
                findings.append("DNSSEC: Validating")
            else:
                log_and_print("enumeration", "dns_dnssec_not_validating", f"  [-] DNSSEC Validation NOT detected (dnssec-failed.org returned rcode={rcode} instead of SERVFAIL)", port=port)
                findings.append("DNSSEC: Not validating")
        # Complementary EDNS0/DO-bit support check against a normal signed domain
        pkt2 = IP(dst=target) / UDP(dport=port) / DNS(rd=1, qd=DNSQR(qname="cloudflare.com", qtype="A"), ar=DNSRROPT(z=0x8000))
        resp2 = sr1(pkt2, timeout=timeout, verbose=0)
        if resp2 and resp2.haslayer(DNS):
            has_opt = resp2.haslayer(DNSRROPT)
            ad_flag = bool(getattr(resp2[DNS], 'ad', 0))
            log_and_print("enumeration", "dns_edns_support", f"  [+] EDNS0 Support: {'Yes' if has_opt else 'No'} | Authenticated Data (AD) flag on signed-domain query: {ad_flag}", port=port)
    except Exception as e:
        log_and_print("enumeration", "dns_dnssec_fault", f"  [-] DNSSEC test anomaly: {e}", port=port)

    # 4) Reverse-DNS based zone guess (feeds AXFR + zone enumeration below)
    zone_guess, ptr_hostname = guess_zone_from_ptr(target, timeout)
    if zone_guess:
        log_and_print("enumeration", "dns_zone_guess", f"  [+] Candidate zone guessed from reverse DNS ({ptr_hostname}) -> '{zone_guess}' (heuristic - naive apex guess, verify manually)", port=port)
    else:
        log_and_print("enumeration", "dns_zone_guess_fail", "  [-] Could not derive a candidate zone via reverse DNS - AXFR/zone-enumeration tests skipped (no target zone name available)", port=port)

    # 5) AXFR (full zone transfer) check - the single most decisive zone-enumeration test
    axfr_result = "Not tested (no candidate zone)"
    if zone_guess:
        try:
            query = DNS(rd=0, qd=DNSQR(qname=zone_guess, qtype="AXFR"))
            raw = bytes(query)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            s.sendall(struct.pack('>H', len(raw)) + raw)
            msg = dns_recv_tcp_message(s, timeout)
            s.close()
            if msg:
                axfr_resp = DNS(msg)
                if axfr_resp.ancount > 0 and axfr_resp.rcode == 0:
                    axfr_result = f"ALLOWED - {axfr_resp.ancount}+ record(s) returned"
                    log_and_print("enumeration", "dns_axfr_vuln", f"  [VULN] Zone Transfer (AXFR) ALLOWED for '{zone_guess}' - full zone contents disclosed to any client (CRITICAL misconfiguration)", port=port)
                    sample_names = []
                    rr = axfr_resp.an
                    for _ in range(min(5, axfr_resp.ancount)):
                        if rr is None:
                            break
                        sample_names.append(f"{rr.rrname.decode(errors='ignore') if isinstance(rr.rrname, bytes) else rr.rrname} ({rr.type})")
                        rr = rr.payload.getlayer(rr.__class__) if hasattr(rr, 'payload') else None
                    if sample_names:
                        log_and_print("enumeration", "dns_axfr_sample", f"    [+] Sample records disclosed: {', '.join(sample_names)}", port=port)
                elif axfr_resp.rcode == 5:
                    axfr_result = "Refused (secure)"
                    log_and_print("enumeration", "dns_axfr_refused", f"  [+] Zone Transfer (AXFR) REFUSED for '{zone_guess}' (properly restricted)", port=port)
                else:
                    axfr_result = f"No transfer (rcode={axfr_resp.rcode})"
                    log_and_print("enumeration", "dns_axfr_no_transfer", f"  [+] AXFR did not yield a zone transfer for '{zone_guess}' (rcode={axfr_resp.rcode})", port=port)
            else:
                axfr_result = "No response on TCP/53"
                log_and_print("enumeration", "dns_axfr_no_response", "  [-] No response to AXFR request over TCP/53", port=port)
        except Exception as e:
            axfr_result = f"Error: {e}"
            log_and_print("enumeration", "dns_axfr_fault", f"  [-] AXFR probe anomaly: {e}", port=port)

    # 6) Zone enumeration note (kept intentionally conservative - authorized environments only)
    if zone_guess and "ALLOWED" not in axfr_result:
        log_and_print("enumeration", "dns_zone_enum_note",
                       "  [*] Zone Transfer blocked - further zone enumeration (NSEC walking, subdomain brute-forcing) "
                       "was NOT attempted here to avoid generating heavy/ambiguous query volume against a target whose "
                       "authorization scope is unknown to this script. Run a dedicated tool (e.g. dnsrecon, ldns-walk) "
                       "against the confirmed zone name in an authorized engagement.", port=port)

    findings.append(f"AXFR: {axfr_result}")
    scan_results["port_scans"][str(port)]["version"] = "DNS Server | " + " | ".join(findings)

# ==============================================================================
# 4. CVE & CVSS SCORE API INTEGRATION ENGINE
# ==============================================================================

_CVE_LOOKUP_CACHE = {}

_VERSION_PLACEHOLDER_TOKENS = (
    "not evaluated", "unconfirmed", "undetermined", "unknown", "n/a", "-", ""
)

# Ordered most-specific-first: pulls the actual product name a version string
# belongs to, instead of the generic service label ("SSH", "HTTP", "SMTP")
# that was previously used both as the NVD query term and as the relevance
# check. A generic label like "ssh" matches an enormous number of unrelated
# CVE descriptions that merely mention SSH in passing, which was the main
# source of false-positive high/critical matches in the risk report.
_PRODUCT_NAME_PATTERNS = [
    r'\b(OpenSSH)[_/]', r'\b(Apache)[/ ]', r'\b(nginx)[/ ]', r'\b(Microsoft-IIS)[/ ]',
    r'\b(Microsoft ESMTP)', r'\b(Postfix)\b', r'\b(Exim)\b', r'\b(Sendmail)\b',
    r'\b(vsFTPd)\b', r'\b(ProFTPD)\b', r'\b(Pure-FTPd)\b', r'\b(FileZilla)\b',
    r'\b(MySQL|MariaDB)\b', r'\b(PostgreSQL)\b', r'\b(Redis)\b', r'\b(MongoDB)\b',
    r'\b(Samba)\b', r'\b(BIND|ISC BIND)\b', r'\b(dnsmasq)\b', r'\b(OpenSSL)\b',
    r'\b(WordPress)\b', r'\b(Jenkins)\b', r'\b(Grafana)\b', r'\b(Prometheus)\b',
    r'\b(Kibana)\b', r'\b(Elasticsearch)\b', r'\b(RabbitMQ)\b', r'\b(Memcached)\b',
    r'\b(OpenLDAP)\b', r'\b(RPCBind)\b', r'\b(NFS)\b',
]

def _extract_product_name(service_name, version_text):
    """Best-effort real product name for CVE relevance checks. Falls back to
    the generic service label only when no specific product token is found
    in the banner - e.g. 'SMTP' stays 'SMTP' if the banner never identified
    itself, but 'SMTP' becomes 'Postfix' the moment a Postfix banner was
    actually captured."""
    text = version_text or ""
    for pattern in _PRODUCT_NAME_PATTERNS:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            return m.group(1)
    return service_name.strip()

# Maps the specific product names above to their NVD CPE 2.3 vendor:product
# pair. This is the actual fix for weak CVE correlation: NVD's free-text
# keywordSearch only matches CVEs whose *description* happens to restate the
# version in the exact format we searched for, so it systematically misses
# range-style advisories ("OpenSSH before 6.7", "affects 4.x through 6.6")
# even when the scanned version is squarely inside that range. virtualMatchString
# instead compares against NVD's structured CPE Match Criteria, which already
# encodes those version ranges (versionStartIncluding/versionEndExcluding) -
# so a vulnerable-but-not-literally-quoted version is still found correctly.
# CPE identifiers verified against the NVD product dictionary (nvd.nist.gov/products/cpe).
_CPE_VENDOR_PRODUCT_MAP = {
    "OpenSSH": "openbsd:openssh",
    "Apache": "apache:http_server",
    "nginx": "nginx:nginx",
    "Microsoft-IIS": "microsoft:internet_information_services",
    "Postfix": "postfix:postfix",
    "Exim": "exim:exim",
    "Sendmail": "sendmail:sendmail",
    "vsFTPd": "vsftpd_project:vsftpd",
    "ProFTPD": "proftpd:proftpd",
    "Pure-FTPd": "pureftpd:pure-ftpd",
    "MySQL": "oracle:mysql",
    "MariaDB": "mariadb:mariadb",
    "PostgreSQL": "postgresql:postgresql",
    "Redis": "redis:redis",
    "MongoDB": "mongodb:mongodb",
    "Samba": "samba:samba",
    "BIND": "isc:bind",
    "ISC BIND": "isc:bind",
    "OpenSSL": "openssl:openssl",
    "WordPress": "wordpress:wordpress",
    "Jenkins": "jenkins:jenkins",
    "Grafana": "grafana:grafana",
    "Prometheus": "prometheus:prometheus",
    "Kibana": "elastic:kibana",
    "Elasticsearch": "elastic:elasticsearch",
    "Memcached": "memcached:memcached",
    "OpenLDAP": "openldap:openldap",
}

# Services whose wire protocol only ever discloses a PROTOCOL version (NFSv3,
# NFSv4, RPC version 2...) rather than a software package version - there is
# no clean "X.Y" release number to build a CPE virtualMatchString from, ever,
# for these, regardless of how good the banner-grabbing is. Rather than
# skipping CVE correlation entirely for them (which was the actual complaint:
# a bare "SKIPPED-NO-VERSION" with nothing else to go on), they get a
# product-only NVD search - explicitly labeled lower-confidence since it
# can't be scoped to a specific version, but still surfaces real, relevant
# CVEs instead of nothing.
_PRODUCT_ONLY_SEARCHABLE = {
    "RPCBind": "rpcbind",
    "NFS": "nfs-utils",
}

def _numeric_version_prefix(raw_version):
    """'4.7p1' -> '4.7', '8.9p1' -> '8.9', '5.0.51a' -> '5.0.51', '2.4.41' ->
    unchanged. NVD's CPE version field is sometimes the bare numeric version
    with the vendor's patch letter in a separate 'update' field (4.7 / p1)
    rather than concatenated (4.7p1) - querying the numeric prefix with a
    wildcard update field matches both representations; querying the
    concatenated form only matches the (less common) literal-concatenation
    records."""
    m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){0,2})', raw_version)
    return m.group(1) if m else raw_version


def _nvd_api_get(api_url):
    """Shared request/retry/error-handling for both the CPE-based and
    keyword-based NVD lookups so the two query strategies don't duplicate
    the 429-backoff and exception handling."""
    attempts = 0
    while attempts < 2:
        attempts += 1
        try:
            req = urllib.request.Request(api_url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            with urllib.request.urlopen(req, timeout=8) as response:
                if response.status == 200:
                    return json.loads(response.read().decode()), None
                elif response.status == 429 and attempts < 2:
                    time.sleep(6)
                    continue
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempts < 2:
                time.sleep(6)
                continue
            return None, f"NVD API returned HTTP {e.code}"
        except Exception as e:
            return None, f"{type(e).__name__}: {e}"
    return None, "NVD API rate-limited after retry"


def _cvss_from_metrics(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            cvss_info = metrics[key][0].get("cvssData", {})
            score = cvss_info.get("baseScore", 0.0)
            severity = cvss_info.get("baseSeverity") or metrics[key][0].get("baseSeverity", "UNKNOWN")
            return score, severity
    return 0.0, "UNKNOWN"


_PROTOCOL_VERSION_CONTEXT_RE = re.compile(r'(protocol|wire)\s*v?\s*$', re.IGNORECASE)

def _is_protocol_version_context(text, match_start, window=30):
    """True when the number just matched is actually a wire/spec protocol
    version (e.g. 'wire protocol v3.1.1' for MQTT, 'AMQP protocol v0.9.1')
    rather than the product's own software version - those numbers are
    shared by every implementation of the protocol and correlating CVEs
    against them produces meaningless matches (there's no CVE for 'protocol
    3.1.1' as a product)."""
    context = text[max(0, match_start - window):match_start]
    return bool(_PROTOCOL_VERSION_CONTEXT_RE.search(context))


def _first_non_protocol_match(pattern, text, flags=0):
    for m in re.finditer(pattern, text, flags):
        if not _is_protocol_version_context(text, m.start(1)):
            return m
    return None


def extract_clean_version(service_name, version_text):
    """Strict version extraction: refuses to guess a product version out of
    unrelated numbers (IDs, ports, counts) that show up in free-text summary
    strings. Returns None when no trustworthy version-like token is found, so
    the caller can skip CVE lookup instead of querying on noise."""
    if not version_text or version_text.strip().lower() in _VERSION_PLACEHOLDER_TOKENS:
        return None
    # Priority 1: version immediately after a name separator, e.g. OpenSSH_8.9p1,
    # nginx/1.18.0, Apache/2.4.41 - this is the actual product version, and avoids
    # accidentally grabbing a leading protocol-version number (e.g. the "2.0" in
    # "SSH-2.0-OpenSSH_8.9p1" is the SSH protocol version, not the software version).
    cue_match = _first_non_protocol_match(r'[_/](\d{1,3}\.\d{1,3}(?:\.\d{1,4})?(?:[a-zA-Z]?\d*)?)', version_text)
    if not cue_match:
        # Priority 2: an explicit "version"/"v"/"build"/"release" cue anywhere in the text
        cue_match = _first_non_protocol_match(r'(?:version|ver|build|release)[\s:]*v?(\d{1,3}\.\d{1,3}(?:\.\d{1,4})?)', version_text, re.IGNORECASE)
    if not cue_match:
        # Priority 3 (fallback): the first bare dotted-number pattern in the text
        # that isn't itself flagged as a protocol/wire-spec version.
        cue_match = _first_non_protocol_match(r'\bv?(\d{1,3}\.\d{1,3}(?:\.\d{1,4})?)\b', version_text)
    if not cue_match:
        return None
    candidate = cue_match.group(1)
    # Reject obvious non-version noise: bare small numbers like "0.0"
    if candidate in ("0.0", "0.0.0"):
        return None
    return candidate

def _fetch_cve_product_only(product_name, version_text):
    """Product-name-only NVD keywordSearch for services that structurally
    never expose a software version (RPCBind, NFS - see
    _PRODUCT_ONLY_SEARCHABLE). Every result is explicitly capped at 'low'
    confidence since it isn't scoped to any version at all, but that's still
    strictly more useful than a bare skip - the person can see what CVEs
    exist for the product family and cross-check against their actual
    OS package version manually."""
    cache_key = (product_name.strip().lower(), "__product_only__")
    if cache_key in _CVE_LOOKUP_CACHE:
        return _CVE_LOOKUP_CACHE[cache_key]

    query = _PRODUCT_ONLY_SEARCHABLE[product_name]
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(query)}&resultsPerPage=10"
    data, err = _nvd_api_get(api_url)

    cve_list = []
    if err:
        cve_list = [{
            "cve_id": "LOOKUP-UNAVAILABLE",
            "cvss_score": None,
            "severity": "INFO",
            "summary": f"NVD lookup for '{query}' failed ({err}). Not counted toward risk score - verify manually.",
            "confidence": "n/a"
        }]
    elif data is not None:
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "N/A")
            score, severity = _cvss_from_metrics(cve_data.get("metrics", {}))
            descriptions = cve_data.get("descriptions", [{}])
            desc = descriptions[0].get("value", "No description available.") if descriptions else "No description available."
            cve_list.append({
                "cve_id": cve_id,
                "cvss_score": score,
                "severity": severity,
                "summary": desc[:150] + ("..." if len(desc) > 150 else ""),
                "confidence": f"low (product-only match on '{query}' - {product_name} discloses no software version over the wire, only protocol version(s) [{version_text}]; verify installed package version manually before treating as confirmed)"
            })
        time.sleep(1.5)
        if not cve_list:
            cve_list = [{
                "cve_id": "NONE-FOUND",
                "cvss_score": None,
                "severity": "INFO",
                "summary": f"No CVEs returned by NVD for '{query}'. This does not guarantee the installed version is unaffected.",
                "confidence": "n/a"
            }]

    _CVE_LOOKUP_CACHE[cache_key] = cve_list
    return cve_list


def fetch_cve_details(service_name, version_text):
    """Fetches real-time CVEs and CVSS scores via the NVD API.

    Strategy (in order):
    1. CPE-based lookup (virtualMatchString) when we have a known vendor:product
       mapping for the identified software. This is matched against NVD's
       structured CPE applicability ranges, so it correctly finds CVEs like
       "affects versions before 6.7" even though '4.7p1' never appears
       verbatim in the CVE description - keywordSearch would miss these
       entirely, which was the main reason vulnerability-detection recall
       stayed low across repeated review passes.
    2. keywordSearch fallback when there's no CPE mapping for this product,
       or the CPE query genuinely returns zero results - preserves the
       previous behavior as a safety net rather than silently going quiet.

    Accuracy safeguards carried over/extended:
    - Skips the query entirely when no trustworthy version could be extracted.
    - Caches results per (product, version) to avoid duplicate calls.
    - On network/API failure, returns a clearly-labeled "lookup unavailable"
      marker EXCLUDED from severity scoring - never fabricates a fake
      CVE/CVSS score.
    - CPE-matched results are authoritative (NVD already confirmed version
      applicability) so they're tagged 'high' confidence directly. Keyword
      fallback results still get the product/version relevance re-check.
    - Results are capped and sorted by severity so a wide vulnerable range
      doesn't dump dozens of low-value entries into the report.
    """
    clean_version = extract_clean_version(service_name, version_text)
    product_name = _extract_product_name(service_name, version_text)

    if not clean_version:
        if product_name in _PRODUCT_ONLY_SEARCHABLE:
            # RPCBind/NFS never expose a software package version over the
            # wire - only protocol versions (NFSv2/3/4, RPC version 2) - so
            # there will never be a clean_version to extract, ever, no
            # matter how good the banner grab is. A blanket skip here just
            # hides real, relevant CVEs from the report. Search by product
            # name alone instead, clearly labeled as version-unscoped.
            return _fetch_cve_product_only(product_name, version_text)
        return [{
            "cve_id": "SKIPPED-NO-VERSION",
            "cvss_score": None,
            "severity": "INFO",
            "summary": f"No reliable version string could be extracted from '{version_text}' - CVE correlation skipped to avoid false-positive matches. Confirm the version manually.",
            "confidence": "n/a"
        }]

    cache_key = (product_name.strip().lower(), clean_version)
    if cache_key in _CVE_LOOKUP_CACHE:
        return _CVE_LOOKUP_CACHE[cache_key]

    cve_list = []
    lookup_note = None
    vendor_product = _CPE_VENDOR_PRODUCT_MAP.get(product_name)

    if vendor_product:
        numeric_version = _numeric_version_prefix(clean_version)
        cpe_string = f"cpe:2.3:a:{vendor_product}:{numeric_version}:*:*:*:*:*:*:*"
        api_url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                   f"?virtualMatchString={urllib.parse.quote(cpe_string, safe=':*')}&resultsPerPage=50")
        data, err = _nvd_api_get(api_url)
        if data is not None:
            for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "N/A")
                score, severity = _cvss_from_metrics(cve_data.get("metrics", {}))
                descriptions = cve_data.get("descriptions", [{}])
                desc = descriptions[0].get("value", "No description available.") if descriptions else "No description available."
                cve_list.append({
                    "cve_id": cve_id,
                    "cvss_score": score,
                    "severity": severity,
                    "summary": desc[:150] + ("..." if len(desc) > 150 else ""),
                    "confidence": "high (CPE version-range match confirmed by NVD)"
                })
            time.sleep(1.5)
        elif err:
            lookup_note = err

    if not cve_list and not lookup_note:
        # No CPE mapping for this product, or the CPE query came back empty -
        # fall back to the original free-text search so coverage never drops
        # below what the tool already did for unmapped products.
        query = f"{product_name} {clean_version}"
        api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(query)}&resultsPerPage=10"
        data, err = _nvd_api_get(api_url)
        if err:
            lookup_note = err
        elif data is not None:
            product_token = product_name.strip().lower().split()[0] if product_name.strip() else ""
            for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "N/A")
                score, severity = _cvss_from_metrics(cve_data.get("metrics", {}))
                descriptions = cve_data.get("descriptions", [{}])
                desc = descriptions[0].get("value", "No description available.") if descriptions else "No description available."

                # Relevance re-check: word-boundary version match instead of a bare
                # substring check (a substring match on "2.4" wrongly hits "2.41",
                # "12.4", dates, etc. and was a direct source of false positives).
                desc_lower = desc.lower()
                version_referenced = bool(re.search(rf'(?<!\d){re.escape(clean_version)}(?!\d)', desc))
                product_referenced = product_token in desc_lower if product_token else False
                if product_referenced and version_referenced:
                    confidence = "high (product + version referenced in CVE description)"
                elif product_referenced:
                    confidence = "medium (product referenced, version not explicitly confirmed)"
                else:
                    confidence = "low (keyword match only - verify manually)"

                cve_list.append({
                    "cve_id": cve_id,
                    "cvss_score": score,
                    "severity": severity,
                    "summary": desc[:150] + ("..." if len(desc) > 150 else ""),
                    "confidence": confidence
                })
            time.sleep(1.5)

    if lookup_note:
        cve_list = [{
            "cve_id": "LOOKUP-UNAVAILABLE",
            "cvss_score": None,
            "severity": "INFO",
            "summary": f"NVD lookup for '{product_name} {clean_version}' failed ({lookup_note}). Not counted toward risk score - verify manually.",
            "confidence": "n/a"
        }]
    elif not cve_list:
        cve_list = [{
            "cve_id": "NONE-FOUND",
            "cvss_score": None,
            "severity": "INFO",
            "summary": f"No CVEs returned by NVD for '{product_name} {clean_version}'. This does not guarantee the version is unaffected - only that no matching record was found.",
            "confidence": "n/a"
        }]
    else:
        # Cap to the most severity-relevant findings - a broad version-range
        # CPE match can legitimately return dozens of CVEs, and dumping all
        # of them makes the report harder to act on, not more accurate.
        cve_list.sort(key=lambda c: (c.get("cvss_score") or 0), reverse=True)
        if len(cve_list) > 15:
            omitted = len(cve_list) - 15
            cve_list = cve_list[:15]
            cve_list.append({
                "cve_id": "ADDITIONAL-RESULTS-OMITTED",
                "cvss_score": None,
                "severity": "INFO",
                "summary": f"{omitted} additional lower-severity CVE(s) matched but were omitted for brevity - see the NVD CPE page for the full list.",
                "confidence": "n/a"
            })

    _CVE_LOOKUP_CACHE[cache_key] = cve_list
    return cve_list

# ==============================================================================
# 5. AUTOMATED RISK ASSESSMENT GENERATOR MODULE
# ==============================================================================

def generate_risk_assessment():
    """Evaluates all open ports, correlates findings with CVEs, and creates a comprehensive Risk Assessment report."""
    print("\n" + "="*80)
    print(" [*] INITIATING AUTOMATED CVE & CVSS RISK ASSESSMENT")
    print("="*80)
    
    total_cves = 0
    max_cvss = 0.0
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    unverified_count = 0

    service_risks = {}
    
    for port_str, data in scan_results["port_scans"].items():
        state = port_authoritative_states.get(int(port_str), "FILTERED")
        if state == "OPEN":
            service = data.get("service", "Unknown")
            version = data.get("version", "Not Evaluated")
            
            print(f"[*] Querying API for Open Port {port_str} [{service}] -> Version: {version}")
            cves = fetch_cve_details(service, version)
            
            port_max_cvss = 0.0
            for cve in cves:
                score = cve.get("cvss_score")
                if score is None:  # INFO markers (skipped/failed/none-found) never count toward risk
                    continue

                # A "low (keyword match only)" hit means NVD's keywordSearch surfaced
                # a description that doesn't actually reference this product - counting
                # it toward the risk score was the direct cause of false-positive
                # CRITICAL/HIGH findings. Still returned in cve_findings for manual
                # review, just excluded from the aggregate score/counts/CVSS ceiling.
                confidence = cve.get("confidence", "")
                if confidence.startswith("low"):
                    unverified_count += 1
                    continue

                total_cves += 1
                if score > max_cvss: max_cvss = score
                if score > port_max_cvss: port_max_cvss = score
                
                sev = cve["severity"].upper()
                if sev == "CRITICAL" or score >= 9.0: critical_count += 1
                elif sev == "HIGH" or score >= 7.0: high_count += 1
                elif sev == "MEDIUM" or score >= 4.0: medium_count += 1
                else: low_count += 1
                
            service_risks[port_str] = {
                "service": service,
                "version": version,
                "highest_cvss": port_max_cvss,
                "cve_findings": cves
            }

    # Overall System Severity Scoring Logic
    if max_cvss >= 9.0 or critical_count > 0:
        overall_risk = "CRITICAL"
    elif max_cvss >= 7.0 or high_count > 0:
        overall_risk = "HIGH"
    elif max_cvss >= 4.0 or medium_count > 0:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    assessment_report = {
        "overall_system_risk": overall_risk,
        "max_cvss_score": max_cvss,
        "metrics": {
            "total_cves_identified": total_cves,
            "critical_severity": critical_count,
            "high_severity": high_count,
            "medium_severity": medium_count,
            "low_severity": low_count,
            "excluded_low_confidence_matches": unverified_count
        },
        "detailed_service_risk": service_risks
    }
    
    scan_results["risk_assessment"] = assessment_report
    
    print("\n" + "="*80)
    print("                    AUTOMATED RISK ASSESSMENT REPORT")
    print("="*80)
    print(f" OVERALL SYSTEM RISK LEVEL : {overall_risk}")
    print(f" HIGHEST CVSS SCORE        : {max_cvss} / 10.0")
    print(f" TOTAL CVE VULNERABILITIES : {total_cves}")
    print(f" SEVERITY BREAKDOWN        : Critical: {critical_count} | High: {high_count} | Medium: {medium_count} | Low: {low_count}")
    print("-" * 80)
    for port, rdata in service_risks.items():
        print(f" Port {port} [{rdata['service']}] -> Peak CVSS: {rdata['highest_cvss']}")
        for cve in rdata['cve_findings']:
            score_display = cve['cvss_score'] if cve['cvss_score'] is not None else "N/A"
            print(f"   - {cve['cve_id']} | CVSS: {score_display} | Severity: {cve['severity']}")
            print(f"     Summary: {cve['summary']}")
    print("="*80 + "\n")


# ==============================================================================
# 6. SCAN EXECUTION CONTROLLER
# ==============================================================================

def execute_scan(target, zombie_ip=None):
    global _TCP_IP_OS_EVIDENCE, _RPC_DUMP_CACHE
    _TCP_IP_OS_EVIDENCE = None  # Reset cache in case execute_scan runs more than once in-process
    _RPC_DUMP_CACHE = None
    scan_results["target_ip"] = target
    scan_results["zombie_ip"] = zombie_ip or "Skipped"
    
    print(f"\n[*] Starting Dynamic Reconnaissance Pipeline against target: {target}")
    ping_scan(target)
    
    all_ports = [int(p) for p in scan_results["port_scans"].keys()]
    
    print("\n[*] Running Primary Multi-Protocol Port Discovery Engine...")
    for port in all_ports:
        basic_port_scan(target, port)
        syn_scan(target, port)
        tcp_scan(target, port)
        udp_scan(target, port)
        fin_scan(target, port)
        null_scan(target, port)
        xmas_scan(target, port)
        ack_scan(target, port)
        window_scan(target, port)
        maimon_scan(target, port)
        if zombie_ip:
            zombie_scan(target, zombie_ip, port)

    print("\n[*] Evaluating Port Priority Consensus Decision Engine...")
    for port in all_ports:
        state = final_consensus_decision(port)
        port_authoritative_states[port] = state
        if state == "OPEN":
            print(f"  [+] PORT {port}: OPEN (Confirmed by Multi-Vector Decision Engine)")
        else:
            # Default display version reflects the actual multi-vector verdict
            # for this port (CLOSED / FILTERED / OPEN|FILTERED) rather than a
            # blanket "Port Closed" stamped mid-scan off a single TCP-connect
            # probe - that previously mislabeled every UDP-only port (which
            # has no TCP listener by definition) as flatly "closed" even when
            # its real UDP state was open|filtered. "OPEN" ports keep their
            # placeholder here; the application-layer modules fill those in.
            scan_results["port_scans"][str(port)]["version"] = f"Port {state.replace('_', ' ').title()}"

    print("\n[*] Executing Target Operating System Fingerprinting...")
    service_and_os_detection(target)

    print("\n[*] Launching Targeted Application-Layer Auditing Modules...")
    for port, state in port_authoritative_states.items():
        if state == "OPEN":
            if port == 21:
                ftp_banner_grab(target)
                ftp_anonymous_check(target)
                ftp_bounce_check(target)
                run_ftps_advanced_audit(target)
            elif port == 22:
                run_ssh_advanced_audit(target)
            elif port == 23:
                run_telnet_advanced_audit(target)
            elif port == 53:
                run_dns_advanced_audit(target, port)
            elif port == 88:
                run_kerberos_advanced_audit(target)
            elif port == 111 or port == 2049:
                run_nfs_rpc_advanced_audit(target, port)
            elif port == 123:
                run_ntp_advanced_audit(target)
            elif port == 69:
                run_tftp_advanced_audit(target)
            elif port in [67, 68]:
                run_dhcp_advanced_audit(target, port)
            elif port in [389, 636]:
                run_ldap_advanced_audit(target, port)
            elif port in [110, 995]:
                run_pop3_advanced_audit(target, port)
            elif port == HTTP_PORT or port == HTTPS_PORT or port in HTTPS_ALT_PORTS:
                run_http_advanced_audit(target, port)
            elif port in SMTP_PORTS:
                run_smtp_advanced_audit(target, port)
            elif port == 445:
                run_smb_advanced_audit(target)
            elif port == 3389:
                run_rdp_advanced_audit(target, port)
            elif port == 1521:
                run_oracle_advanced_audit(target)
            elif port == 3306:
                run_mysql_advanced_audit(target)
            elif port == 5432:
                run_postgres_advanced_audit(target)
            elif port == 6379:
                run_redis_advanced_audit(target)
            elif port == 9042:
                run_cassandra_advanced_audit(target)
            elif port == 5984:
                run_couchdb_advanced_audit(target)
            elif port in [7474, 7687]:
                run_neo4j_advanced_audit(target, port)
            elif port in [8080, 50000]:
                run_jenkins_advanced_audit(target, port)
            elif port == 9418:
                run_git_advanced_audit(target)
            elif port == 631:
                run_ipp_cups_advanced_audit(target)
            elif port == 3000:
                run_grafana_advanced_audit(target, port)
            elif port == 9090:
                run_prometheus_advanced_audit(target, port)
            elif port == 5601:
                run_kibana_advanced_audit(target, port)
            elif port == 9092:
                run_kafka_advanced_audit(target, port)
            elif port == 2181:
                run_zookeeper_advanced_audit(target, port)
            elif port in [5985, 5986]:
                run_winrm_advanced_audit(target, port)
            elif port in VNC_PORTS:
                run_vnc_advanced_audit(target, port)
            elif port in MQTT_PORTS:
                run_mqtt_advanced_audit(target, port)
            elif port in RABBITMQ_PORTS:
                run_rabbitmq_advanced_audit(target, port)
            elif port == 11211:
                run_memcached_advanced_audit(target)
            elif port in SIP_PORTS:
                run_sip_advanced_audit(target, port)
            elif port in [989, 990]:
                run_ftps_implicit_audit(target, port)

    print("\n[*] Refining OS Fingerprint with Application-Layer Banner Evidence...")
    # Every version-bearing banner (Apache/Ubuntu, Microsoft ESMTP, OpenSSH,
    # vsFTPd, etc.) is now populated - re-run the merge step so those banners
    # actually count. Re-uses the cached TCP/IP probe from the first pass
    # instead of sending another round of SYN packets.
    service_and_os_detection(target, refine_with_banners=True)

    # Trigger Automated Vulnerability API & Risk Assessment Generator
    generate_risk_assessment()

    print("\n[*] Scan Execution Completed Successfully.")
    return scan_results

# Replace the existing main block at the bottom of file.py with this:

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        target_host = sys.argv[1]
        zombie_host = sys.argv[2] if len(sys.argv) > 2 else None
    else:
        target_host = input("[?] Enter Target IP Address to scan: ").strip()
        zombie_prompt = input("[?] Enter Zombie Host IP for Idle Scan (Press Enter to Skip): ").strip()
        zombie_host = zombie_prompt if zombie_prompt else None

    if not target_host:
        print("[!] Target IP is required. Exiting.")
        sys.exit(1)

    results = execute_scan(target_host, zombie_host)

    # Output file generation
    output_filename = f"scan_results_{target_host}.json"
    with open(output_filename, "w") as f:
        json.dump(results, f, indent=4)
           
    # Save output to JSON file

# ==============================================================================
# REPORT GENERATION ENGINES (JSON, TXT, XML)
# ==============================================================================

def generate_txt_report(results):
    """Generates a structured plain text report including enumeration and CVE findings."""
    lines = []
    lines.append("=" * 80)
    lines.append("                    SECURITY ASSESSMENT SCAN REPORT")
    lines.append("=" * 80)
    lines.append(f"Target IP: {results.get('target_ip', 'N/A')}")
    lines.append(f"Zombie IP: {results.get('zombie_ip', 'Skipped')}")
    
    net_disc = results.get("network_discovery", {})
    if net_disc:
        lines.append("\n[+] NETWORK DISCOVERY")
        for k, v in net_disc.items():
            lines.append(f"  - {k}: {v}")
            
    os_info = results.get("os_fingerprint", {})
    lines.append("\n[+] OS FINGERPRINTING")
    if isinstance(os_info, dict):
        lines.append(f"  - Detected OS: {os_info.get('detected_os', 'Unknown')}")
        lines.append(f"  - Confidence: {os_info.get('confidence_percentage', '0%')}")
        evidence = os_info.get("evidence", [])
        if evidence:
            lines.append("  - Evidence:")
            for item in evidence:
                lines.append(f"      * {item}")
    else:
        lines.append(f"  - OS Details: {os_info}")

    lines.append("\n" + "=" * 80)
    lines.append("                            PORT SCANS")
    lines.append("=" * 80)
    
    port_scans = results.get("port_scans", {})
    for port, data in port_scans.items():
        lines.append(f"\nPort: {port} | Service: {data.get('service', 'N/A')} | Version: {data.get('version', 'N/A')}")
        
        scans = data.get("scans", {})
        if scans:
            lines.append("  Scans:")
            for scan_type, status in scans.items():
                lines.append(f"    - {scan_type}: {status}")
                
        enum_data = data.get("enumeration", {})
        if enum_data:
            lines.append("  Enumeration:")
            for enum_key, enum_val in enum_data.items():
                lines.append(f"    - {enum_key}: {enum_val}")

    risk = results.get("risk_assessment", {})
    if risk:
        lines.append("\n" + "=" * 80)
        lines.append("                         RISK ASSESSMENT")
        lines.append("=" * 80)
        lines.append(f"Overall System Risk: {risk.get('overall_system_risk', 'UNKNOWN')}")
        lines.append(f"Max CVSS Score: {risk.get('max_cvss_score', 0.0)}")
        
        metrics = risk.get("metrics", {})
        if metrics:
            lines.append("\nVulnerability Metrics:")
            for m_key, m_val in metrics.items():
                lines.append(f"  - {m_key}: {m_val}")
                
        detailed_risk = risk.get("detailed_service_risk", {})
        if detailed_risk:
            lines.append("\nDetailed Service Vulnerabilities:")
            for port, s_risk in detailed_risk.items():
                lines.append(f"\n  [Port {port}] Service: {s_risk.get('service', 'N/A')} | Highest CVSS: {s_risk.get('highest_cvss', 0.0)}")
                cve_findings = s_risk.get("cve_findings", [])
                if cve_findings:
                    lines.append("  CVE Findings:")
                    for cve in cve_findings:
                        lines.append(f"    * cve_id: {cve.get('cve_id', 'N/A')}")
                        lines.append(f"      cvss_score: {cve.get('cvss_score', 0.0)}")
                        lines.append(f"      severity: {cve.get('severity', 'N/A')}")
                        lines.append(f"      summary: {cve.get('summary', 'N/A')}")
                        
    lines.append("\n" + "=" * 80)
    lines.append("                          END OF REPORT")
    lines.append("=" * 80)
    return "\n".join(lines)


def build_xml_element(parent, data):
    """Recursively converts Python dictionary structure into well-formed XML elements."""
    if isinstance(data, dict):
        for key, value in data.items():
            # Clean XML tag names
            clean_tag = str(key).replace(" ", "_").replace("/", "_").replace("|", "_")
            if clean_tag[0].isdigit():
                clean_tag = f"port_{clean_tag}"
                
            sub_elem = ET.SubElement(parent, clean_tag)
            build_xml_element(sub_elem, value)
    elif isinstance(data, list):
        for item in data:
            item_elem = ET.SubElement(parent, "item")
            build_xml_element(item_elem, item)
    else:
        parent.text = str(data)


def generate_xml_report(results):
    """Generates an XML report with formatted structure."""
    root = ET.Element("scan_report")
    build_xml_element(root, results)
    
    # Pretty print XML string
    raw_string = ET.tostring(root, encoding="unicode")

    raw_string = re.sub(
        r'[\x00-\x08\x0B\x0C\x0E-\x1F]',
        '',
        raw_string
    )

    parsed = minidom.parseString(raw_string)
    return parsed.toprettyxml(indent="    ")


def save_reports(target_ip, scan_data):
    """Saves scan data into JSON, TXT, and XML format."""
    
    json_filename = "scan_report_with_risk_assessment.json"
    txt_filename = "scan_report_with_risk_assessment.txt"
    xml_filename = "scan_report_with_risk_assessment.xml"
    ip_json_filename = f"scan_results_{target_ip}.json"

    # Save JSON
    json_output = json.dumps(scan_data, indent=4)
    with open(json_filename, "w", encoding="utf-8") as f:
        f.write(json_output)
    with open(ip_json_filename, "w", encoding="utf-8") as f:
        f.write(json_output)

    # Save TXT
    txt_output = generate_txt_report(scan_data)
    with open(txt_filename, "w", encoding="utf-8") as f:
        f.write(txt_output)

    # Save XML
    xml_output = generate_xml_report(scan_data)
    with open(xml_filename, "w", encoding="utf-8") as f:
        f.write(xml_output)

    # Terminal Status Confirmation Output
    print(f"[+] JSON report saved to '{json_filename}'")
    print(f"[+] TXT report saved to '{txt_filename}'")
    print(f"[+] XML report saved to '{xml_filename}'")


# ==============================================================================
# MAIN EXECUTION ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    # Ensure target_ip is configured
    target_host = scan_results.get("target_ip", "192.168.56.105")
    if not target_host:
        target_host = "192.168.56.105"
        scan_results["target_ip"] = target_host
        
    # Execution completed, trigger report generation pipeline
    save_reports(target_host, scan_results)

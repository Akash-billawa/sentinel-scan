"""Likely Reason / Explanation Engine.

Maps a detected scan to one of 100 plausible reasons, ranked by
weighted evidence.  Each reason belongs to a classification bucket:
BENIGN SECURITY ACTIVITY, DEVICE NORMAL ACTIVITY, ISP/ROUTER NORMAL,
CLOUD SERVICE, DEVELOPER TOOL, SUSPICIOUS ACTIVITY, ATTACK,
FALSE POSITIVE, or UNKNOWN.

The engine collects `[+]` supporting and `[-]` contradicting evidence
and returns the highest-scoring reason plus the full ranked list for
debugging and dashboard display.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# Known ASNs and IP ranges for benign/security entities.
# Keys are entity ids; values are (ASN strings, IP CIDRs).
_KNOWN_ENTITIES: Dict[str, Dict] = {
    "cloudflare": {"asns": ["AS13335", "AS46562"], "cidrs": ["103.21.244.0/22", "104.16.0.0/12", "173.245.48.0/20"]},
    "google": {"asns": ["AS15169"], "cidrs": ["8.8.8.0/24", "8.8.4.0/24"]},
    "amazon_aws": {"asns": ["AS16509", "AS14618"], "cidrs": ["13.0.0.0/8"]},
    "akamai": {"asns": ["AS20940", "AS21342", "AS21399", "AS16625"], "cidrs": ["23.0.0.0/12"]},
    "fastly": {"asns": ["AS54113"], "cidrs": ["151.101.0.0/16"]},
    "kaspersky": {"asns": ["AS204428"], "cidrs": ["93.159.228.0/22"]},
    "microsoft": {"asns": ["AS8075"], "cidrs": ["13.107.0.0/16"]},
}


@dataclass
class Reason:
    id: str
    name: str
    category: str
    score: float = 0.0
    positive: List[str] = field(default_factory=list)
    negative: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Reason catalog (100 entries, grouped by category)
# ---------------------------------------------------------------------------

_CATALOG: List[Dict] = [
    # --- BENIGN SECURITY ACTIVITY (1-20) ---
    {"id": "cloudflare_health", "name": "Cloudflare security health check",
     "category": "BENIGN SECURITY ACTIVITY", "match": ["cloudflare"], "rate_max": 50},
    {"id": "cloudflare_zt_tunnel", "name": "Cloudflare Zero Trust tunnel connectivity check",
     "category": "BENIGN SECURITY ACTIVITY", "match": ["cloudflare"], "rate_max": 20},
    {"id": "cloudflare_warp", "name": "Cloudflare WARP network probing",
     "category": "BENIGN SECURITY ACTIVITY", "match": ["cloudflare"], "rate_max": 100},
    {"id": "cloudflare_cdn_edge", "name": "Cloudflare CDN edge verification",
     "category": "BENIGN SECURITY ACTIVITY", "match": ["cloudflare"]},
    {"id": "cloudflare_dns", "name": "Cloudflare DNS resolver activity",
     "category": "BENIGN SECURITY ACTIVITY", "match": ["cloudflare"], "port": 53},
    {"id": "kaspersky_av", "name": "Kaspersky antivirus network inspection",
     "category": "BENIGN SECURITY ACTIVITY", "match": ["kaspersky"]},
    {"id": "kaspersky_fw", "name": "Kaspersky firewall scanning local connections",
     "category": "BENIGN SECURITY ACTIVITY", "match": ["kaspersky"], "private": True},
    {"id": "windows_defender", "name": "Windows Defender network protection check",
     "category": "BENIGN SECURITY ACTIVITY", "match": ["microsoft"], "private": True},
    {"id": "windows_smart", "name": "Windows Security SmartScreen lookup",
     "category": "BENIGN SECURITY ACTIVITY", "match": ["microsoft"], "port": 443},
    {"id": "antivirus_vuln", "name": "Antivirus vulnerability assessment scan",
     "category": "BENIGN SECURITY ACTIVITY", "rate_min": 1, "rate_max": 50},
    {"id": "edr_monitoring", "name": "Endpoint Detection Response (EDR) monitoring",
     "category": "BENIGN SECURITY ACTIVITY", "private": True, "rate_max": 50},
    {"id": "sec_agent_status", "name": "Company security agent checking device status",
     "category": "BENIGN SECURITY ACTIVITY", "private": True},
    {"id": "nac_verify", "name": "Network Access Control (NAC) verification",
     "category": "BENIGN SECURITY ACTIVITY", "private": True},
    {"id": "vpn_connectivity", "name": "VPN client checking connectivity",
     "category": "BENIGN SECURITY ACTIVITY", "rate_max": 30},
    {"id": "safe_browsing", "name": "Browser safe browsing URL reputation check",
     "category": "BENIGN SECURITY ACTIVITY", "port": 443},
    {"id": "pw_breach_monitor", "name": "Password manager breach monitoring service",
     "category": "BENIGN SECURITY ACTIVITY", "port": 443},
    {"id": "device_posture", "name": "Device security posture assessment",
     "category": "BENIGN SECURITY ACTIVITY", "private": True},
    {"id": "malware_scan", "name": "Malware scanner checking suspicious connections",
     "category": "BENIGN SECURITY ACTIVITY", "private": True},
    {"id": "fw_validation", "name": "Firewall rule validation test",
     "category": "BENIGN SECURITY ACTIVITY", "rate_max": 100},
    {"id": "sec_software_port", "name": "Security software port inspection",
     "category": "BENIGN SECURITY ACTIVITY", "private": True, "rate_max": 100},

    # --- DEVICE / OS NORMAL ACTIVITY (21-40) ---
    {"id": "win_discovery", "name": "Windows network discovery scan",
     "category": "DEVICE NORMAL ACTIVITY", "private": True},
    {"id": "win_smb", "name": "Windows file sharing discovery (SMB)",
     "category": "DEVICE NORMAL ACTIVITY", "private": True, "port": 445},
    {"id": "printer_discovery", "name": "Printer discovery request",
     "category": "DEVICE NORMAL ACTIVITY", "private": True, "port": 9100},
    {"id": "bluetooth_discovery", "name": "Bluetooth device discovery",
     "category": "DEVICE NORMAL ACTIVITY", "private": True},
    {"id": "nearby_share", "name": "Nearby sharing detection",
     "category": "DEVICE NORMAL ACTIVITY", "private": True},
    {"id": "chromecast", "name": "Chromecast / casting device search",
     "category": "DEVICE NORMAL ACTIVITY", "private": True, "port": 8008},
    {"id": "smart_tv", "name": "Smart TV discovery",
     "category": "DEVICE NORMAL ACTIVITY", "private": True},
    {"id": "mobile_hotspot", "name": "Mobile hotspot device detection",
     "category": "DEVICE NORMAL ACTIVITY", "private": True},
    {"id": "router_discovery", "name": "Router device discovery",
     "category": "DEVICE NORMAL ACTIVITY", "private": True},
    {"id": "iot_discovery", "name": "IoT device discovery",
     "category": "DEVICE NORMAL ACTIVITY", "private": True},
    {"id": "home_assistant", "name": "Home assistant device scan",
     "category": "DEVICE NORMAL ACTIVITY", "private": True},
    {"id": "console_discovery", "name": "Gaming console network discovery",
     "category": "DEVICE NORMAL ACTIVITY", "private": True},
    {"id": "media_server", "name": "Media server discovery",
     "category": "DEVICE NORMAL ACTIVITY", "private": True},
    {"id": "backup_software", "name": "Backup software searching devices",
     "category": "DEVICE NORMAL ACTIVITY", "private": True},
    {"id": "rdp_check", "name": "Remote desktop availability check",
     "category": "DEVICE NORMAL ACTIVITY", "port": 3389},
    {"id": "vm_adapter", "name": "Virtual machine adapter scanning",
     "category": "DEVICE NORMAL ACTIVITY", "private": True},
    {"id": "docker_probe", "name": "Docker container network probing",
     "category": "DEVICE NORMAL ACTIVITY", "private": True},
    {"id": "wsl_activity", "name": "WSL virtual network activity",
     "category": "DEVICE NORMAL ACTIVITY", "private": True},
    {"id": "emulator", "name": "Emulator network communication",
     "category": "DEVICE NORMAL ACTIVITY", "private": True},
    {"id": "software_update", "name": "Software update connectivity test",
     "category": "DEVICE NORMAL ACTIVITY", "port": 443},

    # --- ISP / ROUTER NORMAL (41-55) ---
    {"id": "isp_health", "name": "ISP router health monitoring",
     "category": "ISP/ROUTER NORMAL", "private": True},
    {"id": "isp_diag", "name": "ISP diagnostic test",
     "category": "ISP/ROUTER NORMAL", "private": True},
    {"id": "isp_firmware", "name": "ISP firmware update check",
     "category": "ISP/ROUTER NORMAL", "private": True},
    {"id": "isp_speedtest", "name": "ISP speed test measurement",
     "category": "ISP/ROUTER NORMAL", "port": 8080},
    {"id": "router_devices", "name": "Router checking connected devices",
     "category": "ISP/ROUTER NORMAL", "private": True},
    {"id": "router_arp", "name": "Router ARP scanning LAN",
     "category": "ISP/ROUTER NORMAL", "private": True},
    {"id": "dhcp_lease", "name": "DHCP lease verification",
     "category": "ISP/ROUTER NORMAL", "private": True},
    {"id": "dns_resolver_test", "name": "DNS resolver testing",
     "category": "ISP/ROUTER NORMAL", "port": 53},
    {"id": "nat_tracking", "name": "NAT connection tracking",
     "category": "ISP/ROUTER NORMAL", "private": True},
    {"id": "gateway_check", "name": "Gateway availability check",
     "category": "ISP/ROUTER NORMAL", "private": True},
    {"id": "mesh_wifi", "name": "Mesh WiFi node discovery",
     "category": "ISP/ROUTER NORMAL", "private": True},
    {"id": "wifi_opt", "name": "WiFi optimization scan",
     "category": "ISP/ROUTER NORMAL", "private": True},
    {"id": "router_sec_scan", "name": "Router security feature scan",
     "category": "ISP/ROUTER NORMAL", "private": True},
    {"id": "isp_troubleshoot", "name": "ISP troubleshooting activity",
     "category": "ISP/ROUTER NORMAL", "private": True},
    {"id": "cgnat_check", "name": "Carrier-grade NAT behavior check",
     "category": "ISP/ROUTER NORMAL", "private": True},

    # --- CLOUD / ONLINE SERVICES (56-65) ---
    {"id": "cloud_health", "name": "Cloud server health check",
     "category": "CLOUD SERVICE", "port": 443},
    {"id": "api_avail", "name": "API availability monitoring",
     "category": "CLOUD SERVICE", "port": 443},
    {"id": "uptime_monitor", "name": "Website uptime monitoring",
     "category": "CLOUD SERVICE", "port": 443, "rate_max": 10},
    {"id": "lb_health", "name": "Load balancer health probe",
     "category": "CLOUD SERVICE", "rate_max": 20},
    {"id": "cloud_fw_inspect", "name": "Cloud firewall inspection",
     "category": "CLOUD SERVICE"},
    {"id": "cdn_perf", "name": "CDN performance testing",
     "category": "CLOUD SERVICE"},
    {"id": "bot_protect", "name": "Bot protection analysis",
     "category": "CLOUD SERVICE"},
    {"id": "ddos_protect", "name": "DDoS protection traffic analysis",
     "category": "CLOUD SERVICE"},
    {"id": "cert_validate", "name": "Certificate validation check",
     "category": "CLOUD SERVICE", "port": 443},
    {"id": "tls_testing", "name": "TLS/HTTPS security testing",
     "category": "CLOUD SERVICE", "port": 443},

    # --- DEVELOPER / TECHNICAL TOOLS (66-80) ---
    {"id": "nmap_scan", "name": "Nmap network scan",
     "category": "DEVELOPER TOOL", "tool": "Nmap"},
    {"id": "angry_ip_scan", "name": "Angry IP Scanner discovery",
     "category": "DEVELOPER TOOL", "tool": "Angry IP Scanner"},
    {"id": "masscan_scan", "name": "Masscan high-speed scan",
     "category": "DEVELOPER TOOL", "tool": "Masscan"},
    {"id": "rustscan_scan", "name": "RustScan port discovery",
     "category": "DEVELOPER TOOL", "tool": "RustScan"},
    {"id": "wireshark_test", "name": "Wireshark packet capture testing",
     "category": "DEVELOPER TOOL", "private": True},
    {"id": "metasploit_recon", "name": "Metasploit reconnaissance",
     "category": "DEVELOPER TOOL", "rate_min": 10},
    {"id": "vuln_scan", "name": "Vulnerability scanner activity",
     "category": "DEVELOPER TOOL", "rate_min": 10, "unique_ports_min": 50},
    {"id": "openvas_nessus", "name": "OpenVAS/Nessus scan",
     "category": "DEVELOPER TOOL", "rate_max": 200, "unique_ports_min": 20},
    {"id": "burp_test", "name": "Burp Suite network testing",
     "category": "DEVELOPER TOOL", "port": 8080},
    {"id": "api_sec_scan", "name": "API security scanner",
     "category": "DEVELOPER TOOL", "port": 443},
    {"id": "web_crawler", "name": "Web crawler activity",
     "category": "DEVELOPER TOOL", "port": 80},
    {"id": "dev_server", "name": "Local development server detection",
     "category": "DEVELOPER TOOL", "private": True},
    {"id": "db_discovery", "name": "Database discovery scan",
     "category": "DEVELOPER TOOL"},
    {"id": "ssh_check", "name": "SSH availability checking",
     "category": "DEVELOPER TOOL", "port": 22},
    {"id": "devops_probe", "name": "DevOps monitoring tool probing",
     "category": "DEVELOPER TOOL"},

    # --- SUSPICIOUS / ATTACK POSSIBILITIES (81-95) ---
    {"id": "attacker_recon", "name": "Attacker performing reconnaissance",
     "category": "ATTACK", "rate_min": 50, "unique_ports_min": 20},
    {"id": "port_scan_pre", "name": "Port scanning before exploitation",
     "category": "ATTACK", "unique_ports_min": 100},
    {"id": "botnet_search", "name": "Botnet searching vulnerable devices",
     "category": "ATTACK", "unique_targets_min": 20},
    {"id": "malware_lan", "name": "Malware looking for LAN targets",
     "category": "ATTACK", "private": True, "unique_targets_min": 5},
    {"id": "worm_prop", "name": "Worm propagation attempt",
     "category": "ATTACK", "unique_targets_min": 50},
    {"id": "unauth_vuln", "name": "Unauthorized vulnerability scan",
     "category": "ATTACK", "unique_ports_min": 100, "rate_min": 100},
    {"id": "cred_attack_prep", "name": "Credential attack preparation",
     "category": "ATTACK", "port": 22},
    {"id": "exposed_svc", "name": "Exposed service discovery",
     "category": "ATTACK", "unique_ports_min": 50},
    {"id": "net_mapping", "name": "Network mapping attempt",
     "category": "ATTACK", "unique_targets_min": 10},
    {"id": "fw_bypass", "name": "Firewall bypass testing",
     "category": "ATTACK", "ecn": True},
    {"id": "stealth_ack", "name": "Stealth ACK scan attempt",
     "category": "ATTACK", "scan_type": "ACK Scan"},
    {"id": "os_fingerprint", "name": "OS fingerprinting attempt",
     "category": "ATTACK", "unique_targets_min": 5, "rate_min": 10},
    {"id": "svc_version", "name": "Service version detection",
     "category": "ATTACK", "tcp_completion_min": 0.3},
    {"id": "iot_compromise", "name": "IoT compromise attempt",
     "category": "ATTACK", "private": True, "unique_targets_min": 10},
    {"id": "router_attack", "name": "Router attack attempt",
     "category": "ATTACK", "private": True, "port": 80},

    # --- FALSE POSITIVE / HARMLESS REASONS (96-100) ---
    {"id": "browser_bg", "name": "Browser background connections",
     "category": "FALSE POSITIVE", "rate_max": 5},
    {"id": "mobile_apps", "name": "Mobile apps checking services",
     "category": "FALSE POSITIVE", "rate_max": 20},
    {"id": "telemetry", "name": "Automatic software telemetry",
     "category": "FALSE POSITIVE", "rate_max": 10},
    {"id": "ntp_sync", "name": "Network time synchronization",
     "category": "FALSE POSITIVE", "port": 123},
    {"id": "normal_high_vol", "name": "Normal high-volume network activity",
     "category": "FALSE POSITIVE", "rate_min": 100},
]


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except (ValueError, TypeError):
        return False


def _entity_for_asn(asn: Optional[str]) -> Optional[str]:
    if not asn:
        return None
    for entity_id, info in _KNOWN_ENTITIES.items():
        if asn in info.get("asns", []):
            return entity_id
    return None


def _entity_for_ip(ip: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return None
    for entity_id, info in _KNOWN_ENTITIES.items():
        for cidr in info.get("cidrs", []):
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return entity_id
            except ValueError:
                continue
    return None


def _scan_type_matches(scan_type: str, target: str) -> bool:
    """Match scan_type loosely: 'ACK Scan' should match 'TCP ACK Recon Scan'."""
    if not scan_type or not target:
        return False
    return target.lower() in scan_type.lower()


def _has_destination_port(signals: Dict, port: int) -> bool:
    ports = signals.get("destination_ports") or signals.get("unique_port_list") or []
    try:
        return int(port) in [int(p) for p in ports]
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Reason scoring
# ---------------------------------------------------------------------------

@dataclass
class Explanation:
    name: str
    category: str
    confidence: float
    positive: List[str] = field(default_factory=list)
    negative: List[str] = field(default_factory=list)
    all_reasons: List[Dict] = field(default_factory=list)


def _score_reason(rule: Dict, signals: Dict) -> Reason:
    """Score a single reason rule against the signals."""
    r = Reason(id=rule["id"], name=rule["name"], category=rule["category"])

    matched = 0
    required = 0

    # ASN / entity match
    if "match" in rule:
        required += 1
        asn_entity = _entity_for_asn(signals.get("source_asn"))
        ip_entity = _entity_for_ip(signals.get("source_ip", ""))
        for ent in rule["match"]:
            if asn_entity == ent or ip_entity == ent:
                matched += 1
                r.positive.append(f"Source belongs to {ent} ASN/CIDR")
                break

    # Tool match
    if "tool" in rule:
        required += 1
        if signals.get("source_tool_guess") == rule["tool"]:
            matched += 1
            r.positive.append(f"Tool fingerprint matches {rule['tool']}")

    # Port match
    if "port" in rule:
        required += 1
        if _has_destination_port(signals, rule["port"]):
            matched += 1
            r.positive.append(f"Destination port {rule['port']} present")

    # Rate range
    if "rate_max" in rule:
        required += 1
        rate = signals.get("rate", 0)
        if 0 < rate <= rule["rate_max"]:
            matched += 1
            r.positive.append(f"Rate {rate:.0f} pkt/sec (within benign range)")
    if "rate_min" in rule:
        required += 1
        rate = signals.get("rate", 0)
        if rate >= rule["rate_min"]:
            matched += 1
            r.positive.append(f"Rate {rate:.0f} pkt/sec (meets threshold)")

    # Private IP
    if "private" in rule:
        required += 1
        if _is_private(signals.get("source_ip", "")):
            matched += 1
            r.positive.append("Source is a private/LAN IP")

    # Scan type
    if "scan_type" in rule:
        required += 1
        if _scan_type_matches(signals.get("scan_type", ""), rule["scan_type"]):
            matched += 1
            r.positive.append(f"Scan type matches: {rule['scan_type']}")

    # ECN flag
    if "ecn" in rule:
        required += 1
        if signals.get("uses_ecn"):
            matched += 1
            r.positive.append("ECN/CWR flags present")

    # Unique ports/targets thresholds
    if "unique_ports_min" in rule:
        required += 1
        if signals.get("unique_ports", 0) >= rule["unique_ports_min"]:
            matched += 1
            r.positive.append(f"Unique ports {signals.get('unique_ports', 0)} >= {rule['unique_ports_min']}")
    if "unique_targets_min" in rule:
        required += 1
        if signals.get("unique_targets", 0) >= rule["unique_targets_min"]:
            matched += 1
            r.positive.append(f"Unique targets {signals.get('unique_targets', 0)} >= {rule['unique_targets_min']}")

    # TCP completion ratio
    if "tcp_completion_min" in rule:
        required += 1
        if signals.get("tcp_completion_ratio", 0) >= rule["tcp_completion_min"]:
            matched += 1
            r.positive.append(f"TCP completion ratio {signals.get('tcp_completion_ratio', 0):.0%}")

    # Compute final score: fraction of rules matched, clamped, with a small
    # bonus for many positives.  No rules -> neutral 0.3 baseline so a
    # default reason can still surface.
    if required == 0:
        r.score = 0.3
    else:
        r.score = min(1.0, (matched / required) * 0.7 + 0.2 * min(matched, 3) / 3)

    # Entity/ASN/CIDR match specificity bonus
    if "match" in rule:
        asn_entity = _entity_for_asn(signals.get("source_asn"))
        ip_entity = _entity_for_ip(signals.get("source_ip", ""))
        for ent in rule["match"]:
            if asn_entity == ent or ip_entity == ent:
                r.score = min(1.0, r.score + 0.20)
                break

    # Tool match specificity bonus (if the fingerprinted tool matches exactly)
    if "tool" in rule and signals.get("source_tool_guess") == rule["tool"]:
        r.score = min(1.0, r.score + 0.15)

    # Port match specificity bonus (if a specific port matches)
    if "port" in rule and _has_destination_port(signals, rule["port"]):
        r.score = min(1.0, r.score + 0.10)

    # Threshold specificity bonus (prefer more restrictive/specific rules)
    if "unique_ports_min" in rule and signals.get("unique_ports", 0) >= rule["unique_ports_min"]:
        r.score = min(1.0, r.score + rule["unique_ports_min"] * 0.0001)
    if "rate_min" in rule and signals.get("rate", 0) >= rule["rate_min"]:
        r.score = min(1.0, r.score + rule["rate_min"] * 0.0001)

    return r


def explain_attack(signals: Dict) -> Explanation:
    """Score every reason against the signals; return the best explanation."""
    scored = [_score_reason(rule, signals) for rule in _CATALOG]
    scored.sort(key=lambda r: r.score, reverse=True)

    top = scored[0] if scored else Reason(id="unknown", name="Unknown activity", category="UNKNOWN", score=0.0)

    # Confidence is the top score scaled to 0-100, with a floor so we don't
    # report 0% for every Unknown.
    confidence = round(top.score * 100, 1)
    if top.category in ("ATTACK", "SUSPICIOUS ACTIVITY"):
        confidence = max(confidence, 50.0)

    all_reasons = [
        {
            "id": r.id,
            "name": r.name,
            "category": r.category,
            "score": round(r.score, 3),
        }
        for r in scored[:10]
    ]

    return Explanation(
        name=top.name,
        category=top.category,
        confidence=confidence,
        positive=top.positive,
        negative=top.negative,
        all_reasons=all_reasons,
    )

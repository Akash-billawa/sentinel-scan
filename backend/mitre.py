"""MITRE ATT&CK technique mapping for SentinelScan alerts.

Maps each scan classification to a canonical (tactic, technique_id,
technique_name) triple.  The table is intentionally small and static:
it covers the scan types the engine emits and falls back to a safe
default for anything unexpected.
"""

from __future__ import annotations

from typing import Tuple


# (tactic, technique_id, technique_name)
_MITRE_MAP: dict[str, Tuple[str, str, str]] = {
    "SYN Scan (Stealth)": ("Discovery", "T1046", "Network Service Discovery"),
    "TCP Connect Scan": ("Discovery", "T1046", "Network Service Discovery"),
    "ACK Scan": ("Discovery", "T1046", "Network Service Discovery"),
    "Xmas Scan": ("Discovery", "T1046", "Network Service Discovery"),
    "NULL Scan": ("Discovery", "T1046", "Network Service Discovery"),
    "FIN Scan": ("Discovery", "T1046", "Network Service Discovery"),
    "UDP Scan": ("Discovery", "T1046", "Network Service Discovery"),
    "Ping Sweep": ("Discovery", "T1018", "Remote System Discovery"),
    "ICMP Flood": ("Impact", "T1498", "Network Denial of Service"),
    "Fragmented Scan": ("Discovery", "T1046", "Network Service Discovery"),
    "Mass Scan": ("Discovery", "T1046", "Network Service Discovery"),
    "Service Enumeration": ("Discovery", "T1046", "Network Service Discovery"),
    "Horizontal Scan": ("Discovery", "T1018", "Remote System Discovery"),
    "Vertical Scan": ("Discovery", "T1046", "Network Service Discovery"),
    "Tunnel/Proxy Activity": ("Command and Control", "T1572", "Protocol Tunneling"),
    "Persistent Connection": ("Persistence", "T1505", "Server Software Component"),
    "Generic TCP Probe": ("Discovery", "T1046", "Network Service Discovery"),
    "Generic UDP Probe": ("Discovery", "T1046", "Network Service Discovery"),
    "Generic ICMP Probe": ("Discovery", "T1018", "Remote System Discovery"),
}


def lookup(scan_type: str) -> Tuple[str, str, str]:
    """Return (tactic, technique_id, technique_name) for a scan type.

    Falls back to Network Service Discovery for unknown inputs.
    """
    return _MITRE_MAP.get(scan_type, ("Discovery", "T1046", "Network Service Discovery"))


def format_line(scan_type: str) -> str:
    """Return the display string: 'Tactic — T#### Technique Name'."""
    tactic, tid, name = lookup(scan_type)
    return f"{tactic} — {tid} {name}"

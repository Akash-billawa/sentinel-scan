import json
from datetime import datetime
from unittest.mock import patch

import pytest

from backend.alerts import (
    _rate_line,
    _raw_evidence,
    _reason_lines,
    _recommendations,
    _scan_speed,
    _target_list,
    _timeline,
    format_alert,
)
from backend.database import Attack, PacketEvent


def _make_attack(**overrides):
    defaults = {
        "id": 1,
        "source_ip": "198.51.100.42",
        "source_mac": "A4:83:E7:11:22:33",
        "source_vendor": "Apple, Inc.",
        "source_hostname": "demo.local",
        "source_country": "DemoLand",
        "source_isp": "Demo ISP",
        "source_asn": "AS65536",
        "source_os_guess": "Linux",
        "source_os_confidence": 60,
        "source_tool_guess": "Nmap",
        "source_tool_confidence": 75,
        "scan_type": "SYN Scan (Stealth)",
        "scan_confidence": 80,
        "packet_count": 200,
        "duration_seconds": 12.0,
        "unique_ports": 32,
        "unique_targets": 5,
        "target_ports_json": json.dumps([22, 80, 443, 8080]),
        "target_hosts_json": json.dumps(["10.0.0.1", "10.0.0.2", "10.0.0.3"]),
        "risk_score": 5.2,
        "risk_level": "medium",
        "started_at": datetime(2025, 1, 1, 12, 0, 0),
        "ended_at": datetime(2025, 1, 1, 12, 0, 12),
        "technique_signals_json": json.dumps(
            ["signal: multi-host probing", "signal: SYN sweep"]
        ),
        "source_tool_reasons_json": json.dumps(["SYN ratio 80%, 32 ports"]),
        "source_tool_negative_reasons_json": json.dumps(
            ["rate too high for default Nmap timing"]
        ),
        "explanation_name": "Cloudflare WARP connectivity verification",
        "explanation_category": "BENIGN SECURITY ACTIVITY",
        "explanation_confidence": 87.0,
        "explanation_evidence_json": json.dumps(
            [
                "[+] Source belongs to Cloudflare ASN/CIDR",
                "[+] Rate 30 pkt/sec (within benign range)",
                "[+] Destination port 443 present",
            ]
        ),
        "explanation_all_reasons_json": json.dumps(
            [
                {"id": "cloudflare_warp", "name": "Cloudflare WARP network probing",
                 "category": "BENIGN SECURITY ACTIVITY", "score": 0.87},
            ]
        ),
    }
    defaults.update(overrides)
    return Attack(**defaults)


def test_scan_speed_buckets():
    assert _scan_speed(5) == "Low"
    assert _scan_speed(50) == "Moderate"
    assert _scan_speed(500) == "High"
    assert _scan_speed(2000) == "Very High"


def test_rate_line():
    attack = _make_attack(packet_count=100, duration_seconds=10.0)
    assert _rate_line(attack) == "10.0 packets/sec"


def test_target_list_truncation():
    attack = _make_attack(
        target_hosts_json=json.dumps([f"10.0.0.{i}" for i in range(15)])
    )
    out = _target_list(attack)
    assert "10.0.0.0" in out
    assert "and 5 more" in out


def test_reason_lines_from_signals():
    attack = _make_attack()
    out = _reason_lines(attack)
    assert "multi-host probing" in out
    assert "SYN sweep" in out


def test_recommendations_scale_with_risk():
    assert "Consider blocking" in _recommendations("critical")
    assert "Block IP if activity continues" in _recommendations("low")


def test_raw_evidence_empty():
    assert _raw_evidence([]) == "  No raw packet data captured"


def test_raw_evidence_with_packet():
    pkt = PacketEvent(
        timestamp=datetime(2025, 1, 1, 12, 0, 1),
        source_ip="198.51.100.42",
        destination_ip="10.0.0.1",
        source_port=12345,
        destination_port=80,
        protocol="TCP",
        flags="SYN",
        length=64,
        summary="TCP 198.51.100.42:12345 -> 10.0.0.1:80",
    )
    out = _raw_evidence([pkt])
    assert "Protocol : TCP" in out
    assert "TCP Flags: SYN" in out


def test_timeline():
    attack = _make_attack()
    pkt = PacketEvent(
        timestamp=datetime(2025, 1, 1, 12, 0, 6),
        source_ip="198.51.100.42",
        destination_ip="10.0.0.1",
        source_port=12345,
        destination_port=80,
        protocol="TCP",
        flags="SYN",
        length=64,
        summary="TCP 198.51.100.42:12345 -> 10.0.0.1:80",
    )
    out = _timeline(attack, [pkt])
    assert "12:00:00  First packet detected" in out
    assert "12:00:06  Active scanning observed" in out
    assert "12:00:12  Alert generated" in out


def test_tool_evidence_renders_positive_and_negative():
    attack = _make_attack()
    from backend.alerts import _tool_evidence

    out = _tool_evidence(attack)
    assert "[+] SYN ratio 80%, 32 ports" in out
    assert "[-] rate too high for default Nmap timing" in out


def test_format_alert_contains_all_sections():
    attack = _make_attack()
    with patch("backend.alerts.db.list_packets_for_attack", return_value=[]):
        result = format_alert(attack)
    assert "🚨" in result["body"]
    assert "Reconnaissance Activity Detected" in result["body"]
    assert "Rate     : 16.7 packets/sec" in result["body"]
    assert "Speed    : Moderate" in result["body"]
    assert "10.0.0.1" in result["body"]
    assert "Reason:" in result["body"]
    assert "Timeline:" in result["body"]
    assert "Raw Evidence:" in result["body"]
    assert "Action:" in result["body"]
    assert "MITRE    : Discovery — T1046 Network Service Discovery" in result["body"]
    assert "Tool Evidence:" in result["body"]
    assert "[+]" in result["body"]
    assert "[-]" in result["body"]
    assert "Likely Reason / Explanation:" in result["body"]
    assert "Cloudflare WARP connectivity verification" in result["body"]
    assert "BENIGN SECURITY ACTIVITY" in result["body"]
    assert "87%" in result["body"]
    assert "MAC      : A4:83:E7:11:22:33" in result["body"]
    assert "Vendor   : Apple, Inc." in result["body"]

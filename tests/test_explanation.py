"""Tests for the Explanation Engine."""

from backend.explanation import explain_attack


def test_cloudflare_asn_maps_to_benign():
    sig = {
        "source_ip": "104.16.0.1",
        "source_asn": "AS13335",
        "rate": 30,
        "scan_type": "TCP Connect Scan",
        "unique_ports": 5,
        "unique_targets": 1,
    }
    e = explain_attack(sig)
    assert "Cloudflare" in e.name
    assert e.category == "BENIGN SECURITY ACTIVITY"


def test_nmap_tool_attribution():
    sig = {
        "source_ip": "198.51.100.42",
        "source_tool_guess": "Nmap",
        "scan_type": "SYN Scan (Stealth)",
        "rate": 200,
        "unique_ports": 200,
        "unique_targets": 10,
    }
    e = explain_attack(sig)
    assert e.category == "DEVELOPER TOOL"
    assert "Nmap" in e.name


def test_high_rate_wide_port_scan_is_attack():
    sig = {
        "source_ip": "203.0.113.5",
        "rate": 5000,
        "unique_ports": 2000,
        "unique_targets": 100,
        "scan_type": "Mass Scan",
    }
    e = explain_attack(sig)
    assert e.category in ("ATTACK", "SUSPICIOUS ACTIVITY")
    assert e.confidence >= 50


def test_all_reasons_populated():
    sig = {"source_ip": "10.0.0.5", "rate": 10, "unique_ports": 1}
    e = explain_attack(sig)
    assert len(e.all_reasons) > 0
    assert len(e.all_reasons) <= 10


def test_private_ip_local_activity():
    sig = {
        "source_ip": "192.168.1.50",
        "rate": 5,
        "unique_ports": 1,
        "unique_targets": 1,
    }
    e = explain_attack(sig)
    # Private IP activity should map to a benign/device-normal reason.
    assert e.category in (
        "DEVICE NORMAL ACTIVITY",
        "ISP/ROUTER NORMAL",
        "FALSE POSITIVE",
        "BENIGN SECURITY ACTIVITY",
    )


def test_ssh_port_suggests_developer_tool():
    sig = {
        "source_ip": "198.51.100.99",
        "unique_port_list": [22],
        "rate": 10,
        "unique_ports": 1,
    }
    e = explain_attack(sig)
    assert "SSH" in e.name or e.category == "DEVELOPER TOOL"


def test_empty_signals_returns_explanation():
    e = explain_attack({})
    assert e.name
    assert e.category
    assert e.confidence >= 0
